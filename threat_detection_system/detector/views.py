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

client = genai.Client(api_key="YOUR_GEMINI_API_KEY")


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
# ATTACK TYPE DETECTION FUNCTION
# ================================

def detect_attack_type(duration, src_bytes, dst_bytes, protocol):

    if src_bytes >= 35000 and duration >= 700:
        return "DDoS Attack"

    elif dst_bytes <= 5 and protocol == 1:
        return "SQL Injection"

    elif src_bytes >= 30000 and dst_bytes <= 20:
        return "Botnet Attack"

    elif duration >= 800 and src_bytes >= 20000:
        return "Malware Communication"

    elif src_bytes >= 20000 and dst_bytes <= 40:
        return "Phishing Attack"

    elif src_bytes >= 12000 and duration >= 300:
        return "Exploit Attack"

    else:
        return "Normal Traffic"


# ================================
# HOME DASHBOARD
# ================================

@login_required
def home(request):

    result = None
    attack_type = None
    ai_analysis = None

    if request.method == "POST":

        duration = int(request.POST.get("duration", 0))
        src_bytes = int(request.POST.get("src_bytes", 0))
        dst_bytes = int(request.POST.get("dst_bytes", 0))
        protocol = int(request.POST.get("protocol", 0))

        prediction = model.predict([[duration, src_bytes, dst_bytes, protocol]])

        if prediction[0] == 1:
            result = "Threat Detected"
            attack_type = detect_attack_type(duration, src_bytes, dst_bytes, protocol)
            ai_analysis = f"Potential {attack_type} detected based on unusual traffic behaviour."

        else:
            result = "Normal Traffic"
            attack_type = "Normal Traffic"
            ai_analysis = "Traffic appears normal."

        ip = request.META.get("REMOTE_ADDR")

        TrafficLog.objects.create(
            duration=duration,
            src_bytes=src_bytes,
            dst_bytes=dst_bytes,
            protocol=protocol,
            attack_type=attack_type,
            result=result,
            ai_analysis=ai_analysis,
            attacker_ip=ip
        )

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
        "result": result,
        "ai_analysis": latest.ai_analysis if latest else ""
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

        query = request.POST.get("query")

        duration = int(request.POST.get("duration", 0))
        src_bytes = int(request.POST.get("src_bytes", 0))
        dst_bytes = int(request.POST.get("dst_bytes", 0))
        protocol = int(request.POST.get("protocol", 0))

        # ================================
        # REAL SQL INJECTION DETECTION
        # ================================

        if query:
            q = query.upper()

            if "SELECT" in q or "UNION" in q or "DROP" in q or "' OR '1'='1" in q:
                attack_type = "SQL Injection"
                result = "Threat Detected"

            else:
                attack_type = "Normal Traffic"
                result = "Normal Traffic"

        else:

            prediction = model.predict([[duration, src_bytes, dst_bytes, protocol]])

            if prediction[0] == 1:
                result = "Threat Detected"
                attack_type = detect_attack_type(duration, src_bytes, dst_bytes, protocol)

            else:
                result = "Normal Traffic"
                attack_type = "Normal Traffic"

        ip = request.META.get("REMOTE_ADDR")

        try:
            geo = geo_reader.city(ip)
            country = geo.country.name
        except:
            country = "Unknown"

        prompt = f"""
Analyze this network traffic.

Duration: {duration}
Source Bytes: {src_bytes}
Destination Bytes: {dst_bytes}
Protocol: {protocol}

Prediction Result: {result}
Attack Type: {attack_type}

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

        except:

            if result == "Threat Detected":
                ai_analysis = f"Suspicious activity detected. Attack classified as {attack_type}."

            else:
                ai_analysis = "Traffic appears normal."

        TrafficLog.objects.create(
            duration=duration,
            src_bytes=src_bytes,
            dst_bytes=dst_bytes,
            protocol=protocol,
            attack_type=attack_type,
            result=result,
            ai_analysis=ai_analysis,
            attacker_ip=ip
        )

        return JsonResponse({
            "result": result,
            "attack_type": attack_type,
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


# ================================
# LIVE DASHBOARD STATS API
# ================================

def dashboard_stats(request):

    total_logs = TrafficLog.objects.count()
    threats = TrafficLog.objects.filter(result="Threat Detected").count()
    safe = TrafficLog.objects.filter(result="Normal Traffic").count()

    data = {
        "total_logs": total_logs,
        "threats": threats,
        "safe": safe,
        "confidence": 94
    }

    return JsonResponse(data)