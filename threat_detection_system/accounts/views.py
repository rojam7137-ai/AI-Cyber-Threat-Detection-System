from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from detector.models import TrafficLog   # ✅ Added import


def login_view(request):

    if request.method == "POST":

        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user is not None:

            # 🔥 Clear previous logs (fresh dashboard for every login)
            TrafficLog.objects.all().delete()

            login(request, user)
            return redirect("home")

        else:
            return render(request, "login.html", {
                "error": "Invalid username or password"
            })

    return render(request, "login.html")


def logout_view(request):

    logout(request)

    return redirect("login")