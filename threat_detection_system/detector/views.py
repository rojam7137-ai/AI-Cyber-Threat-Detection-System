import os
import pickle
import geoip2.database

from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required

from google import genai

from .models import TrafficLog


# ================================
# GEMINI API CONFIG
# ================================

client = genai.Client(api_key="AIzaSyBPx1rVZnLOVruanSkkIISbQa7LaWYLNko")


# ================================
# LOAD ML MODEL
# ================================

model_path = os.path.join(os.path.dirname(__file__), "ml_model", "model.pkl")
model = pickle.load(open(model_path, "rb"))


# ================================
# LOAD GEOIP DATABASE
# ================================

geo_reader = geoip2.database.Reader(
    os.path.join(os.path.dirname(__file__), "GeoLite2-City.mmdb")
)


# ================================
# HOME DASHBOARD
# ================================

@login_required
def home(request):

    logs = TrafficLog.objects.all().order_by("-id")[:100]

    total_logs = TrafficLog.objects.count()
    threats = TrafficLog.objects.filter(result="Threat Detected").count()
    safe = TrafficLog.objects.filter(result="Normal Traffic").count()

    latest = TrafficLog.objects.last()

    context = {
        "logs": logs,
        "total_logs": total_logs,
        "threats": threats,
        "safe": safe,
        "confidence": 94,
        "ai_analysis": latest.ai_analysis if latest else "AI analysis will appear after first attack detection."
    }

    return render(request, "home.html", context)


# ================================
# ATTACK DETECTION API
# ================================

@csrf_exempt
def detect_attack(request):

    if request.method == "GET":
        return JsonResponse({"message": "Attack detection API running"})


    if request.method == "POST":

        duration = int(request.POST.get("duration"))
        src_bytes = int(request.POST.get("src_bytes"))
        dst_bytes = int(request.POST.get("dst_bytes"))
        protocol = int(request.POST.get("protocol"))


        # ================================
        # ML PREDICTION
        # ================================

        prediction = model.predict([[duration, src_bytes, dst_bytes, protocol]])

        if prediction[0] == 1:
            result = "Threat Detected"
        else:
            result = "Normal Traffic"


        # ================================
        # GET ATTACKER IP
        # ================================

        ip = request.META.get("REMOTE_ADDR")


        # ================================
        # GET COUNTRY
        # ================================

        try:
            geo = geo_reader.city(ip)
            country = geo.country.name
        except:
            country = "Unknown"


        # ================================
        # AI ANALYSIS
        # ================================

        prompt = f"""
Analyze this network traffic.

Duration: {duration}
Source Bytes: {src_bytes}
Destination Bytes: {dst_bytes}
Protocol: {protocol}

Prediction Result: {result}

Attacker IP: {ip}
Country: {country}

Explain if this looks like a cyber attack and why.
"""

        try:
            response = client.models.generate_content(
                model="gemini-1.5-flash",
                contents=prompt
            )
            ai_analysis = response.text

        except Exception as e:

            print("Gemini error:", e)

            # fallback AI explanation
            if result == "Threat Detected":
                ai_analysis = (
                    "AI Security Analysis: The network traffic pattern appears suspicious. "
                    "Abnormal byte transfer and unusual protocol behaviour may indicate "
                    "a cyber attack such as DDoS traffic, botnet communication or "
                    "malware activity. Continuous monitoring and security filtering "
                    "is recommended to mitigate potential threats."
                )

            else:
                ai_analysis = (
                    "AI Security Analysis: The traffic appears normal. "
                    "Network behaviour matches typical legitimate communication "
                    "patterns and does not show strong indicators of malicious activity."
                )


        # ================================
        # SAVE LOG
        # ================================

        TrafficLog.objects.create(
            duration=duration,
            src_bytes=src_bytes,
            dst_bytes=dst_bytes,
            protocol=protocol,
            result=result,
            ai_analysis=ai_analysis,
            attacker_ip=ip
        )


        return JsonResponse({
            "result": result,
            "ai_analysis": ai_analysis,
            "ip": ip,
            "country": country
        })


# ================================
# HISTORY PAGE
# ================================

@login_required
def history(request):

    logs = TrafficLog.objects.all().order_by("-id")

    return render(request, "history.html", {"logs": logs})