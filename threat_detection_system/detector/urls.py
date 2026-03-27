from django.urls import path
from . import views

urlpatterns = [

    path("", views.home, name="home"),

    path("history/", views.history, name="history"),

    path("detect_attack/", views.detect_attack, name="detect_attack"),

    path("dashboard_stats/", views.dashboard_stats, name="dashboard_stats"),

]