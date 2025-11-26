from django.shortcuts import render, redirect
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
from firebase_admin import auth
from .models import LoginAttempt, Profile
import json
import logging
import random

logger = logging.getLogger(__name__)
import os
import firebase_admin
from firebase_admin import credentials, firestore

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVICE_KEY = os.path.join(BASE_DIR, "firebase/serviceAccountKey.json")

if not firebase_admin._apps:
    cred = credentials.Certificate(SERVICE_KEY)
    firebase_admin.initialize_app(cred)

db = firestore.client()

# --- PAGES ---
def login_page(request):
    if request.user.is_authenticated:
        return redirect('home')
    context = {'firebase_config': settings.FIREBASE_CLIENT_CONFIG}
    return render(request, 'login.html', context)

def home(request):
    if not request.user.is_authenticated:
        return redirect('login')
    return render(request, 'home.html')

def logout_view(request):
    logout(request)
    return redirect('login')

from django.core.mail import send_mail 


@csrf_exempt
def send_email_otp(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        
        if User.objects.filter(email=email).exists():
            return JsonResponse({'status': 'error', 'message': 'Email already registered.'}, status=400)

        # Generate OTP
        otp = str(random.randint(100000, 999999))
        
        # Save to Session
        request.session['registration_otp'] = otp
        request.session['registration_email'] = email
        request.session.set_expiry(300) 

        try:
            send_mail(
                subject='Verify your Account',
                message=f'Your verification code is: {otp}',
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[email],
                fail_silently=False,
            )
            print(f"Email sent to {email}") 
            return JsonResponse({'status': 'success', 'message': 'OTP sent to email.'})
            
        except Exception as e:
            print(f"Email Error: {e}")
            return JsonResponse({'status': 'error', 'message': 'Failed to send email. Check server logs.'}, status=500)

    return JsonResponse({'status': 'error'}, status=400)

@csrf_exempt
def verify_email_otp(request):
    """
    Verifies the code entered by the user before allowing Password creation.
    """
    if request.method == 'POST':
        data = json.loads(request.body)
        user_otp = data.get('otp')
        
        saved_otp = request.session.get('registration_otp')
        
        if saved_otp and user_otp == saved_otp:
            return JsonResponse({'status': 'success'})
        else:
            return JsonResponse({'status': 'error', 'message': 'Invalid OTP.'}, status=400)
    return JsonResponse({'status': 'error'}, status=400)
@csrf_exempt
def report_failure(request):
    """
    Security Monitor: Tracks failed logins (Email Only).
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            identifier = data.get('identifier') 
            ip = request.META.get('REMOTE_ADDR')

            # 1. Log the failure
            LoginAttempt.objects.create(identifier=identifier, ip_address=ip)

            # 2. Count recent failures (last 10 minutes)
            time_threshold = timezone.now() - timedelta(minutes=10)
            recent_failures = LoginAttempt.objects.filter(
                identifier=identifier, 
                timestamp__gte=time_threshold
            ).count()

            response = {'status': 'ok', 'count': recent_failures}

            # --- TRIGGER 1: 3rd Failed Attempt (Alert User) ---
            if recent_failures == 3:
                try:
                    if '@' in identifier:
                        user = User.objects.get(email=identifier)
                        
                        subject = "Security Alert: Suspicious Login Activity"
                        message = (
                            f"Hello,\n\n"
                            f"We noticed 3 failed login attempts on your account.\n"
                            f"IP Address: {ip}\n"
                            f"Time: {timezone.now()}\n\n"
                            f"If this wasn't you, please reset your password immediately."
                        )
                        
                        send_mail(
                            subject,
                            message,
                            settings.EMAIL_HOST_USER,
                            [user.email],
                            fail_silently=True,
                        )
                        print(f"Alert sent to {user.email}")
                        response['alert'] = "Email alert sent."
                        
                except User.DoesNotExist:
                    pass 

            # --- TRIGGER 2: 5th Failed Attempt (Block) ---
            if recent_failures >= 5:
                response['status'] = 'blocked'
                response['message'] = 'Security Lockdown: Too many attempts. Please wait 10 minutes.'

            return JsonResponse(response)

        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

    return JsonResponse({'status': 'error'}, status=405)

@csrf_exempt
def firebase_login(request):
    """
    Final Login/Registration Handshake (Email Only)
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            token = data.get('token')
            
            # Verify with Firebase
            decoded_token = auth.verify_id_token(token)
            uid = decoded_token['uid']
            email = decoded_token.get('email')

            # Identify User (or create if new)
            user, created = User.objects.get_or_create(username=uid)
            
            # Security Check: Is this email currently blocked?
            if email:
                time_threshold = timezone.now() - timedelta(minutes=10)
                fail_count = LoginAttempt.objects.filter(identifier=email, timestamp__gte=time_threshold).count()
                
                if fail_count >= 5:
                    return JsonResponse({
                        'status': 'error', 
                        'message': 'Account is temporarily locked due to suspicious activity.'
                    }, status=403)

            # If new user, save email
            if created:
                user.email = email if email else ""
                user.save()
                # Clear session otp
                if 'registration_otp' in request.session:
                    del request.session['registration_otp']

            # Success! Clear failures
            if email:
                LoginAttempt.objects.filter(identifier=email).delete()
            
            login(request, user)
            return JsonResponse({'status': 'success'})

        except Exception as e:
            print("Login Error:", e)
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

    return JsonResponse({'status': 'error'}, status=405)