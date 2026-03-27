import requests
import time

url = "http://127.0.0.1:8000/detect_attack/"


# =========================
# SQL Injection Payloads
# =========================
sql_injection_payloads = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "' UNION SELECT username,password FROM users --",
    "' DROP TABLE users --"
]


# =========================
# XSS / Exploit Payloads
# =========================
exploit_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<script>document.cookie</script>"
]


# =========================
# Command Injection
# =========================
command_injection_payloads = [
    "; ls",
    "; cat /etc/passwd",
    "&& whoami"
]


# =========================
# Phishing Payload
# =========================
phishing_payloads = [
    "http://fake-login.com",
    "Enter your password to verify account",
    "Update your bank details immediately"
]


# =========================
# Botnet Communication
# =========================
botnet_payloads = [
    "BOT CONNECT SERVER",
    "BOT SEND DATA",
    "BOT RECEIVE COMMAND"
]


# =========================
# Malware Communication
# =========================
malware_payloads = [
    "malware.exe downloading payload",
    "trojan sending system data",
    "ransomware encrypting files"
]


# =========================
# Normal Traffic
# =========================
normal_requests = [
    "hello",
    "login request",
    "fetch user profile",
    "check dashboard status"
]


while True:

    print("\n========== SQL Injection Attacks ==========\n")

    for payload in sql_injection_payloads:

        data = {"query": payload}

        try:
            r = requests.post(url, data=data)

            print("SQL Injection Attempt Sent")
            print("Payload:", payload)
            print("Server Response:", r.text)
            print("--------------------------------")

        except Exception as e:
            print("Server not reachable:", e)

        time.sleep(3)


    print("\n========== Exploit / XSS Attacks ==========\n")

    for payload in exploit_payloads:

        data = {"query": payload}

        try:
            r = requests.post(url, data=data)

            print("Exploit Attempt Sent")
            print("Payload:", payload)
            print("Server Response:", r.text)
            print("--------------------------------")

        except Exception as e:
            print("Server not reachable:", e)

        time.sleep(3)


    print("\n========== Command Injection ==========\n")

    for payload in command_injection_payloads:

        data = {"query": payload}

        try:
            r = requests.post(url, data=data)

            print("Command Injection Attempt Sent")
            print("Payload:", payload)
            print("Server Response:", r.text)
            print("--------------------------------")

        except Exception as e:
            print("Server not reachable:", e)

        time.sleep(3)


    print("\n========== Phishing Attempts ==========\n")

    for payload in phishing_payloads:

        data = {"query": payload}

        try:
            r = requests.post(url, data=data)

            print("Phishing Attempt Sent")
            print("Payload:", payload)
            print("Server Response:", r.text)
            print("--------------------------------")

        except Exception as e:
            print("Server not reachable:", e)

        time.sleep(3)


    print("\n========== Botnet Communication ==========\n")

    for payload in botnet_payloads:

        data = {"query": payload}

        try:
            r = requests.post(url, data=data)

            print("Botnet Communication Sent")
            print("Payload:", payload)
            print("Server Response:", r.text)
            print("--------------------------------")

        except Exception as e:
            print("Server not reachable:", e)

        time.sleep(3)


    print("\n========== Malware Communication ==========\n")

    for payload in malware_payloads:

        data = {"query": payload}

        try:
            r = requests.post(url, data=data)

            print("Malware Communication Sent")
            print("Payload:", payload)
            print("Server Response:", r.text)
            print("--------------------------------")

        except Exception as e:
            print("Server not reachable:", e)

        time.sleep(3)


    print("\n========== Normal Traffic ==========\n")

    for payload in normal_requests:

        data = {"query": payload}

        try:
            r = requests.post(url, data=data)

            print("Normal Request Sent")
            print("Payload:", payload)
            print("Server Response:", r.text)
            print("--------------------------------")

        except Exception as e:
            print("Server not reachable:", e)

        time.sleep(3)