from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login_page, name='login'),
    path('logout/', views.logout_view, name='logout'),

    path('api/login/', views.firebase_login, name='api_login'),
    path('api/report_failure/', views.report_failure, name='report_failure'),
    
    path('api/send_email_otp/', views.send_email_otp, name='send_email_otp'),
    path('api/verify_email_otp/', views.verify_email_otp, name='verify_email_otp'),
]