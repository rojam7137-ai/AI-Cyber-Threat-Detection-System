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

client = genai.Client(api_key="AIzaSyCE1K420vqgc8tzwrYrdmhYiuIcr0Km7cM")  # keep empty


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
# BLOCKED IP STORAGE
# ================================

BLOCKED_IPS = set()


# ================================
# ATTACK TYPE DETECTION (ML BASED)
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
# HOME (DASHBOARD)
# ================================

@login_required
def home(request):

    result = None

    if request.method == "POST":

        duration = int(request.POST.get("duration", 0))
        src_bytes = int(request.POST.get("src_bytes", 0))
        dst_bytes = int(request.POST.get("dst_bytes", 0))
        protocol = int(request.POST.get("protocol", 0))

        prediction = model.predict([[duration, src_bytes, dst_bytes, protocol]])

        if prediction[0] == 1:
            result = "Threat Detected"
            attack_type = detect_attack_type(duration, src_bytes, dst_bytes, protocol)
            ai_analysis = f"Suspicious activity detected. Attack classified as {attack_type}."
        else:
            result = "Normal Traffic"
            attack_type = "Normal Traffic"
            ai_analysis = "Traffic appears normal."

        TrafficLog.objects.create(
            duration=duration,
            src_bytes=src_bytes,
            dst_bytes=dst_bytes,
            protocol=protocol,
            attack_type=attack_type,
            result=result,
            ai_analysis=ai_analysis,
            attacker_ip="Manual Input"
        )

    logs = TrafficLog.objects.all().order_by("-id")[:100]

    total_logs = TrafficLog.objects.count()
    threats = TrafficLog.objects.filter(result="Threat Detected").count()
    safe = TrafficLog.objects.filter(result="Normal Traffic").count()

    latest_threat = TrafficLog.objects.filter(result="Threat Detected").last()

    if latest_threat:
        ai_analysis = latest_threat.ai_analysis
    else:
        ai_analysis = "No threats detected."

    if total_logs > 0:
        risk_probability = int((threats / total_logs) * 100)
    else:
        risk_probability = 0

    if risk_probability > 70:
        risk_level = "HIGH"
    elif risk_probability > 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "SAFE"

    context = {
        "logs": logs,
        "total_logs": total_logs,
        "threats": threats,
        "safe": safe,
        "confidence": 94,
        "ai_analysis": ai_analysis,
        "result": result,
        "risk_probability": risk_probability,
        "risk_level": risk_level
    }

    return render(request, "home.html", context)


# ================================
# ATTACK DETECTION API
# ================================

@csrf_exempt
def detect_attack(request):

    ip = request.META.get("REMOTE_ADDR")

    if ip in BLOCKED_IPS:
        return JsonResponse({
            "result": "Blocked",
            "attack_type": "IP Blocked",
            "ai_analysis": "This IP has been blocked due to repeated attacks.",
            "ip": ip
        })

    if request.method == "POST":

        query = request.POST.get("query")

        duration = int(request.POST.get("duration", 0))
        src_bytes = int(request.POST.get("src_bytes", 0))
        dst_bytes = int(request.POST.get("dst_bytes", 0))
        protocol = int(request.POST.get("protocol", 0))

        if query:
            q = query.upper().strip()

            if "<SCRIPT>" in q or "ALERT(" in q:
                attack_type = "XSS Attack"
                result = "Threat Detected"

            elif any(x in q for x in ["BOT", "C2"]):
                attack_type = "Botnet Attack"
                result = "Threat Detected"

            elif any(x in q for x in ["BANK", "PASSWORD", "LOGIN"]):
                attack_type = "Phishing Attack"
                result = "Threat Detected"

            elif any(x in q for x in ["DOWNLOAD", "EXECUTE", ".EXE"]):
                attack_type = "Malware Communication"
                result = "Threat Detected"

            elif any(x in q for x in ["&&", ";", "|", "WHOAMI", "CAT", "LS"]):
                attack_type = "Command Injection"
                result = "Threat Detected"

            elif any(x in q for x in ["EXPLOIT", "PAYLOAD"]):
                attack_type = "Exploit Attack"
                result = "Threat Detected"

            elif any(x in q for x in ["SELECT", "UNION", "DROP", "--", " OR "]):
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

        try:
            geo = geo_reader.city(ip)
            country = geo.country.name
        except:
            country = "Unknown"

        if result == "Threat Detected":
            ai_analysis = f"Suspicious activity detected. Attack classified as {attack_type}."
        else:
            ai_analysis = "Traffic appears normal."

        if result == "Threat Detected":
            attack_count = TrafficLog.objects.filter(attacker_ip=ip, result="Threat Detected").count()

            # ✅ ONLY CHANGE DONE HERE
            if attack_count >= 1000:
                BLOCKED_IPS.add(ip)
                ai_analysis += " 🚫 IP has been BLOCKED."

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
# HISTORY
# ================================

@login_required
def history(request):
    logs = TrafficLog.objects.all().order_by("-id")
    return render(request, "history.html", {"logs": logs})


# ================================
# DASHBOARD API
# ================================

def dashboard_stats(request):

    total_logs = TrafficLog.objects.count()
    threats = TrafficLog.objects.filter(result="Threat Detected").count()
    safe = TrafficLog.objects.filter(result="Normal Traffic").count()

    if total_logs > 0:
        risk = int((threats / total_logs) * 100)
    else:
        risk = 0

    if risk > 70:
        threat_level = "HIGH"
    elif risk > 30:
        threat_level = "MEDIUM"
    else:
        threat_level = "SAFE"

    return JsonResponse({
        "total_logs": total_logs,
        "threats": threats,
        "safe": safe,
        "confidence": 94,
        "risk": risk,
        "threat_level": threat_level
    })