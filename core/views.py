from django.shortcuts import render, redirect
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from firebase_admin import auth
import json

# 1. Login Page (Injects keys securely)
def login_page(request):
    if request.user.is_authenticated:
        return redirect('home')
    
    context = {
        'firebase_config': settings.FIREBASE_CLIENT_CONFIG
    }
    return render(request, 'login.html', context)

# 2. Home Page (Protected)
def home(request):
    if not request.user.is_authenticated:
        return redirect('login')
    return render(request, 'home.html')

# 3. Logout
def logout_view(request):
    logout(request)
    return redirect('login')

# 4. API Bridge (Validates Token)
@csrf_exempt
def firebase_login(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            token = data.get('token')

            # Verify with Firebase Server
            decoded_token = auth.verify_id_token(token)
            uid = decoded_token['uid']
            email = decoded_token.get('email', f"{uid}@noreply.com")

            # Get or Create Django User
            user, created = User.objects.get_or_create(username=uid)
            if created:
                user.email = email
                user.save()
            
            # Create Session
            login(request, user)
            return JsonResponse({'status': 'success'})

        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

    return JsonResponse({'status': 'error'}, status=405)