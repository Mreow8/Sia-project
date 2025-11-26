from django.urls import path
from . import views  # <--- This works here because views.py is in the same folder

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login_page, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('api/login/', views.firebase_login, name='firebase_login'),
]