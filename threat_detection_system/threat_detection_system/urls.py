from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),

    # login/logout routes
    path('', include('accounts.urls')),

    # dashboard and attack detection
    path('', include('detector.urls')),
]