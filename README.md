# alx_travel_app_0x02
## Environment (.env) & settings
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

### settings.py (add near top)
import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / '.env')

CHAPA_SECRET_KEY = os.getenv('CHAPA_SECRET_KEY')
CHAPA_BASE_URL = os.getenv('CHAPA_BASE_URL', 'https://api.chapa.co/v1')
CHAPA_INITIATE_ENDPOINT = os.getenv('CHAPA_INITIATE_ENDPOINT', '/transaction/initialize')
CHAPA_VERIFY_ENDPOINT = os.getenv('CHAPA_VERIFY_ENDPOINT', '/transaction/verify/')
CHAPA_RETURN_URL = os.getenv('CHAPA_RETURN_URL')

Install dependencies if not present:
pip install python-dotenv requests djangorestframework celery redis

#### Payment model
from django.db import models
from django.conf import settings

# import Booking model - adjust path if needed
try:
    from bookings.models import Booking
except Exception:
    # fallback: if Booking in listings.models replace with from .models import Booking
    Booking = None

class Payment(models.Model):
    STATUS_PENDING = 'PENDING'
    STATUS_INITIATED = 'INITIATED'
    STATUS_COMPLETED = 'COMPLETED'
    STATUS_FAILED = 'FAILED'
    STATUS_CANCELLED = 'CANCELLED'

    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_INITIATED, 'Initiated'),
        (STATUS_COMPLETED, 'Completed'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_CANCELLED, 'Cancelled'),
    ]

    booking = models.ForeignKey('bookings.Booking', on_delete=models.CASCADE, related_name='payments')
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=10, default='ETB')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    transaction_id = models.CharField(max_length=255, blank=True, null=True)  # chapa reference/id
    chapa_response = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['transaction_id']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return f"Payment({self.pk}) booking={self.booking_id} status={self.status}"

Run migrations:
python manage.py makemigrations listings
python manage.py migrate

##### Chapa client (single file for HTTP calls)
import requests
from django.conf import settings
from requests.exceptions import RequestException

BASE = settings.CHAPA_BASE_URL.rstrip('/')

class ChapaError(Exception):
    pass

def initiate_payment(booking_id: int, amount: float, currency: str, customer_email: str = None):
    """
    Calls Chapa initialize endpoint. Returns parsed JSON response.
    """
    url = f"{BASE}{settings.CHAPA_INITIATE_ENDPOINT}"
    payload = {
        "amount": float(amount),
        "currency": currency,
        "tx_ref": f"booking_{booking_id}",
        "return_url": settings.CHAPA_RETURN_URL,
    }
    if customer_email:
        payload["customer"] = {"email": customer_email}

    headers = {
        "Authorization": f"Bearer {settings.CHAPA_SECRET_KEY}",
        "Content-Type": "application/json"
    }

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except RequestException as e:
        raise ChapaError(str(e))

def verify_payment(reference: str):
    """
    Calls Chapa verify endpoint. Some providers require GET /verify/<ref>.
    Adjust URL depending on Chapa docs.
    """
    # If CHAPA_VERIFY_ENDPOINT ends with '/', append reference
    base_ep = settings.CHAPA_VERIFY_ENDPOINT
    if base_ep.endswith('/'):
        url = f"{BASE}{base_ep}{reference}"
    else:
        url = f"{BASE}{base_ep}/{reference}"

    headers = {"Authorization": f"Bearer {settings.CHAPA_SECRET_KEY}"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except RequestException as e:
        raise ChapaError(str(e))

##### Serializers
from rest_framework import serializers
from .models import Payment

class InitiatePaymentSerializer(serializers.Serializer):
    booking_id = serializers.IntegerField()

class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = '__all__'

##### Views — initiate, verify (and webhook example)
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

##### Celery task (background email)
from celery import shared_task
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from bookings.models import Booking
from .models import Payment

@shared_task
def send_payment_confirmation_email(booking_id, payment_id):
    try:
        booking = Booking.objects.get(id=booking_id)
        payment = Payment.objects.get(id=payment_id)
    except Exception:
        return

    subject = f"Booking confirmed #{booking.id}"
    html_message = render_to_string("emails/payment_confirmation.html", {"booking": booking, "payment": payment})
    plain_message = f"Your booking {booking.id} is confirmed. Payment ID: {payment.transaction_id}"
    send_mail(subject, plain_message, settings.DEFAULT_FROM_EMAIL, [booking.user.email], html_message=html_message)

##### URLs
from django.urls import path
from .views import InitiatePaymentAPIView, VerifyPaymentAPIView, chapa_webhook

urlpatterns = [
    path('payments/initiate/', InitiatePaymentAPIView.as_view(), name='payments-initiate'),
    path('payments/verify/', VerifyPaymentAPIView.as_view(), name='payments-verify'),
    path('payments/webhook/', chapa_webhook, name='payments-webhook'),
]

Include in project urls.py:
path('api/', include('listings.urls')),

##### Admin (optional)
from django.contrib import admin
from .models import Payment

@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ('id','booking','amount','currency','status','transaction_id','created_at')
    search_fields = ('transaction_id','booking__id')
    list_filter = ('status','currency')

##### Tests (unit tests with mocking)
from django.test import TestCase
from django.urls import reverse
from unittest.mock import patch
from bookings.models import Booking
from django.contrib.auth import get_user_model
from listings.models import Payment

User = get_user_model()

class PaymentFlowTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='test', password='pass', email='a@b.com')
        # create a booking; adjust fields to your Booking model
        self.booking = Booking.objects.create(user=self.user, total_amount=100.00, status='PENDING')

    @patch('listings.chapa_client.initiate_payment')
    def test_initiate_payment_creates_payment_and_returns_checkout(self, mock_initiate):
        mock_initiate.return_value = {
            "data": {
                "reference": "ref_123",
                "checkout_url": "https://checkout.example"
            }
        }
        self.client.login(username='test', password='pass')
        resp = self.client.post(reverse('payments-initiate'), data={'booking_id': self.booking.id})
        self.assertEqual(resp.status_code, 200)
        self.assertIn('checkout_url', resp.json())
        payment = Payment.objects.get(booking=self.booking)
        self.assertEqual(payment.transaction_id, 'ref_123')
        self.assertEqual(payment.status, Payment.STATUS_INITIATED)

    @patch('listings.chapa_client.verify_payment')
    def test_verify_payment_marks_completed(self, mock_verify):
        payment = Payment.objects.create(booking=self.booking, amount=100.0, status=Payment.STATUS_INITIATED, transaction_id='ref_123')
        mock_verify.return_value = {"data": {"status": "success"}}
        resp = self.client.get(reverse('payments-verify') + '?reference=ref_123')
        self.assertEqual(resp.status_code, 200)
        payment.refresh_from_db()
        self.assertEqual(payment.status, Payment.STATUS_COMPLETED)

Run tests:
python manage.py test listings

##### Sandbox testing / sample curl calls
curl -X POST http://localhost:8000/api/payments/initiate/ \
  -H "Authorization: Token <user_token>" \
  -H "Content-Type: application/json" \
  -d '{"booking_id": 123}'

http://localhost:8000/api/payments/verify/?reference=ref_123

curl -X POST http://localhost:8000/api/payments/webhook/ \
  -H "Content-Type: application/json" \
  -d '{"data":{"reference":"ref_123","status":"success"}}'

##### What to capture for submission (screenshots/logs)

Screenshot of .env.example (with CHAPA_SECRET_KEY redacted) and settings.py showing CHAPA vars loaded.

Terminal output showing makemigrations and migrate completed.

Screenshot of initiating payment response (checkout_url) in Postman or terminal.

Screenshot of Chapa sandbox checkout page showing a successful sandbox payment (or the redirect to return URL).

Screenshot of Payment row in Django admin (status = COMPLETED) or a manage.py shell query showing the updated status.

Celery worker log showing email task enqueued/executed (optional).

Sample test run output python manage.py test listings showing tests passed.

##### Important notes & best practices

Server-side truth: always trust booking.amount from server DB — never trust client-provided amount.

Webhook security: check Chapa docs for webhook signature and validate headers (HMAC). If available, validate to prevent spoofing.

Idempotency: webhook/verify should be idempotent (check if payment already COMPLETED).

Retries and timeouts: use sensible timeouts and retry policies when calling external API.

Logging: keep chapa_response JSON for auditing.

Don't store card data (Chapa handles payment input).

##### Next steps I can do right now (pick any and I’ll produce code)

Paste a ready-to-drop proj/celery.py + settings.py Celery settings.

Paste full-file copies (so you can create them directly).

Add detailed test cases for webhook signature validation (if you want).

Generate a short README section for how to run sandbox tests and what screenshots to produce.
