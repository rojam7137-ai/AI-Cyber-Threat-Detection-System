import requests
import random
import time

url = "http://127.0.0.1:8000/detect_attack/"

while True:

    data = {
        "duration": random.randint(100,800),
        "src_bytes": random.randint(5000,40000),
        "dst_bytes": random.randint(1,100),
        "protocol": random.randint(0,1)
    }

    try:
        r = requests.post(url,data=data)
        print("Attack Sent →",data)

    except Exception as e:
        print("Server not reachable",e)

    time.sleep(3)