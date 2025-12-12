# Assuming you are in the project environment for alx_travel_app_0x02
pip install requests python-dotenv djangorestframework

# Django
DJANGO_SECRET_KEY=replace_me
DEBUG=True

# Database (example)
DATABASE_URL=postgres://user:pass@localhost:5432/alx_travel_db

# Chapa (sandbox)
CHAPA_SECRET_KEY=sk_test_xxx
CHAPA_BASE_URL=https://api.chapa.co/v1
CHAPA_INITIATE_ENDPOINT=/transaction/initialize
CHAPA_VERIFY_ENDPOINT=/transaction/verify/   # note: may be appended with reference
CHAPA_RETURN_URL=http://localhost:8000/api/payments/verify/  # chapa redirect

# settings.py

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ... other settings ...

# CHAPA CONFIGURATION
CHAPA_SECRET_KEY = os.getenv('CHAPA_SECRET_KEY')
CHAPA_BASE_URL = os.getenv('CHAPA_BASE_URL')

# Add rest_framework to INSTALLED_APPS if not already there
INSTALLED_APPS = [
    # ...
    'rest_framework',
    # ...
]


# listings/models.py

from django.db import models
import uuid

# Define the status choices (following the suggested workflow)
class Payment(models.Model):
    STATUS_CHOICES = (
        ('PENDING', 'Pending'), # Initial status after initiation
        ('COMPLETED', 'Completed'), # Confirmed successful by verification
        ('FAILED', 'Failed'),
        ('CANCELLED', 'Cancelled'),
        ('UNVERIFIED', 'Unverified - Status Unknown'),
    )

    # 1. Booking Information
    # In a real app, this would be a ForeignKey to a Booking model
    booking_reference = models.CharField(max_length=100, unique=True) 

    # 2. Chapa Transaction Reference (Our unique identifier)
    # This is required for Chapa API calls
    tx_ref = models.CharField(
        max_length=200, 
        unique=True, 
        default=uuid.uuid4
    ) 
    
    # 3. Financial Details
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=5, default='ETB')
    
    # 4. Status Tracking
    status = models.CharField(
        max_length=20, 
        choices=STATUS_CHOICES, 
        default='PENDING'
    )
    
    # 5. API Data
    checkout_url = models.URLField(max_length=500, null=True, blank=True)
    chapa_response_data = models.JSONField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Payment {self.tx_ref} - {self.status}"

# Don't forget to run migrations after saving this file:
# python manage.py makemigrations listings
# python manage.py migrate


# listings/views.py
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from django.db import transaction
from .serializers import InitiatePaymentSerializer
from .models import Payment
from .chapa_client import initiate_payment, verify_payment, ChapaError

from bookings.models import Booking   # adjust path

class InitiatePaymentAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = InitiatePaymentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        booking_id = serializer.validated_data['booking_id']

        booking = get_object_or_404(Booking, id=booking_id, user=request.user)

        # Use server-side amount to avoid tampering
        amount = booking.total_amount

        with transaction.atomic():
            payment = Payment.objects.create(
                booking=booking,
                amount=amount,
                currency='ETB',
                status=Payment.STATUS_PENDING
            )

            try:
                chapa_resp = initiate_payment(booking_id=booking.id, amount=amount, currency='ETB', customer_email=booking.user.email)
            except ChapaError as e:
                payment.status = Payment.STATUS_FAILED
                payment.chapa_response = {"error": str(e)}
                payment.save(update_fields=['status','chapa_response','updated_at'])
                return Response({"detail": "Failed to contact payment gateway"}, status=status.HTTP_502_BAD_GATEWAY)

            # Save response and transaction id
            payment.status = Payment.STATUS_INITIATED
            payment.chapa_response = chapa_resp
            # extract transaction id/reference based on Chapa response structure
            tx = chapa_resp.get('data', {}).get('reference') or chapa_resp.get('data', {}).get('id') or chapa_resp.get('reference')
            payment.transaction_id = tx
            payment.save(update_fields=['status','chapa_response','transaction_id','updated_at'])

            # Extract checkout URL (depends on Chapa's 'checkout_url' or 'hosted_url' key)
            checkout_url = (chapa_resp.get('data') or {}).get('checkout_url') or (chapa_resp.get('data') or {}).get('hosted_url')
            return Response({"checkout_url": checkout_url, "payment_id": payment.id})

class VerifyPaymentAPIView(APIView):
    permission_classes = [AllowAny]  # return URL will hit this

    def get(self, request):
        # Chapa may pass reference or tx_ref in query params
        ref = request.query_params.get('reference') or request.query_params.get('tx_ref')
        if not ref:
            return Response({"detail": "Missing reference"}, status=status.HTTP_400_BAD_REQUEST)

        payment = get_object_or_404(Payment, transaction_id=ref)

        try:
            verify_resp = verify_payment(ref)
        except ChapaError:
            return Response({"detail": "Verification failed"}, status=status.HTTP_502_BAD_GATEWAY)

        # parse response to determine success
        status_str = (verify_resp.get('data') or {}).get('status') or verify_resp.get('status')
        if status_str and status_str.lower() in ('success','paid','completed'):
            with transaction.atomic():
                payment.status = Payment.STATUS_COMPLETED
                payment.chapa_response = verify_resp
                payment.save()
                # update booking status
                booking = payment.booking
                booking.status = 'CONFIRMED'
                booking.save()
                # enqueue confirmation email
                from .tasks import send_payment_confirmation_email
                send_payment_confirmation_email.delay(booking.id, payment.id)
            return Response({"detail":"Payment confirmed"}, status=status.HTTP_200_OK)
        else:
            payment.status = Payment.STATUS_FAILED
            payment.chapa_response = verify_resp
            payment.save()
            return Response({"detail":"Payment not successful"}, status=status.HTTP_200_OK)


# Basic webhook example (POST)
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json

@csrf_exempt
def chapa_webhook(request):
    """
    Example: validate signature if chapa provides one (check Chapa docs),
    parse payload, update Payment idempotently.
    """
    try:
        payload = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error":"invalid json"}, status=400)

    data = payload.get('data') or payload
    ref = (data or {}).get('reference') or (data or {}).get('tx_ref')
    status_str = (data or {}).get('status')

    if not ref:
        return JsonResponse({"error":"no reference"}, status=400)

    try:
        payment = Payment.objects.get(transaction_id=ref)
    except Payment.DoesNotExist:
        return JsonResponse({"error":"unknown reference"}, status=404)

    if payment.status == Payment.STATUS_COMPLETED:
        return JsonResponse({"status":"already processed"}, status=200)

    if status_str and status_str.lower() in ('success','paid','completed'):
        payment.status = Payment.STATUS_COMPLETED
        payment.chapa_response = payload
        payment.save()
        booking = payment.booking
        booking.status = 'CONFIRMED'
        booking.save()
        from .tasks import send_payment_confirmation_email
        send_payment_confirmation_email.delay(booking.id, payment.id)
    else:
        payment.status = Payment.STATUS_FAILED
        payment.chapa_response = payload
        payment.save()

    return JsonResponse({"status":"ok"})

# listings/urls.py

from django.urls import path
from .views import InitializePaymentAPIView

urlpatterns = [
    # ... other paths
    path('payments/initiate/', InitializePaymentAPIView.as_view(), name='initiate-payment'),
    # Note: We will add the 'verify' path in the next step
]



