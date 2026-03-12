from django.contrib import admin
from django.urls import path
from detector import views

urlpatterns = [
    path('admin/', admin.site.urls),

    path('', views.home, name='home'),
    path('history/', views.history, name='history'),
    path('detect_attack/', views.detect_attack, name='detect_attack'),
]