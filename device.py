import requests
import time
import random
import sys
import json
import base64
from crypto_utils import (generate_hmac, generate_ecdh_keypair,
                          compute_shared_secret, encrypt_data)

# ── Sensor type definitions ────────────────────────────────────────────────────
SENSOR_TYPES = {
    # Standard temp/humidity sensors
    "sensor_001": "temperature",
    "sensor_002": "temperature",
    "sensor_003": "temperature",
    # Specialised devices
    "camera_01":   "camera",
    "doorlock_01": "doorlock",
    "motion_01":   "motion",
}

DEVICE_KEYS = {
    "sensor_001":  "secret_key_abc123",
    "sensor_002":  "secret_key_def456",
    "sensor_003":  "secret_key_ghi789",
    "camera_01":   "secret_key_cam001",
    "doorlock_01": "secret_key_door01",
    "motion_01":   "secret_key_mot001",
}


class SecureIoTDevice:
    def __init__(self, device_id, secret_key):
        self.device_id   = device_id
        self.secret_key  = secret_key
        self.server_url  = "http://localhost:5000"
        self.session_token = None
        self.session_key   = None
        self.sensor_type   = SENSOR_TYPES.get(device_id, "temperature")

    # ── Authentication ─────────────────────────────────────────────────────────
    def authenticate(self):
        print(f"[AUTH] Requesting challenge...")
        try:
            r = requests.post(f"{self.server_url}/get-challenge",
                              json={"device_id": self.device_id}, timeout=5)
        except Exception as e:
            print(f"[AUTH] ✗ Cannot reach server: {e}")
            return False

        if r.status_code == 429:
            print(f"[AUTH] ✗ Rate limited: {r.json().get('error')}")
            return False
        if r.status_code != 200:
            print(f"[AUTH] ✗ {r.json().get('error','unknown error')}")
            return False

        challenge    = r.json()['challenge']
        response_tag = generate_hmac(self.secret_key, challenge)

        auth = requests.post(f"{self.server_url}/authenticate",
                             json={"device_id": self.device_id, "response": response_tag},
                             timeout=5)

        if auth.status_code == 200:
            self.session_token = auth.json()['session_token']
            print(f"[AUTH] ✓ Authenticated!")
            return True
        else:
            print(f"[AUTH] ✗ {auth.json().get('error','failed')}")
            return False

    # ── Key exchange ───────────────────────────────────────────────────────────
    def exchange_keys(self):
        print(f"[ECDH] Generating key pair...")
        device_private, device_public = generate_ecdh_keypair()

        r = requests.post(
            f"{self.server_url}/exchange-keys",
            json={"public_key": base64.b64encode(device_public).decode()},
            headers={"Authorization": self.session_token},
            timeout=5
        )
        if r.status_code != 200:
            print(f"[ECDH] ✗ Key exchange failed")
            return False

        server_pub       = base64.b64decode(r.json()['public_key'])
        self.session_key = compute_shared_secret(device_private, server_pub)
        print(f"[ECDH] ✓ Session key established")
        return True

    # ── Sensor data generators ─────────────────────────────────────────────────
    def generate_sensor_data(self):
        if self.sensor_type == "temperature":
            return {
                "sensor_type": "temperature",
                "temperature": round(random.uniform(20.0, 35.0), 2),
                "humidity":    round(random.uniform(40.0, 80.0), 2),
            }

        elif self.sensor_type == "camera":
            # Simulate image metadata (not real image bytes)
            return {
                "sensor_type":  "camera",
                "resolution":   "1920x1080",
                "fps":          30,
                "motion_zones": random.randint(0, 3),
                "image_hash":   base64.b64encode(
                    bytes(random.getrandbits(8) for _ in range(16))
                ).decode(),
                "ir_active":    random.choice([True, False]),
            }

        elif self.sensor_type == "doorlock":
            states = ["locked", "locked", "locked", "unlocked"]  # mostly locked
            return {
                "sensor_type":   "doorlock",
                "state":         random.choice(states),
                "battery_pct":   random.randint(60, 100),
                "last_event":    random.choice(["key_card", "pin_code", "remote_app", "auto_lock"]),
                "tamper_alert":  random.random() < 0.05,   # 5% chance
            }

        elif self.sensor_type == "motion":
            detected = random.random() < 0.3   # 30% chance motion detected
            return {
                "sensor_type":    "motion",
                "motion_detected": detected,
                "sensitivity":    "high",
                "zone":           random.choice(["front_door", "hallway", "backyard"]),
                "lux_level":      round(random.uniform(0, 800), 1),
            }

        return {"sensor_type": "unknown"}

    # ── Send ───────────────────────────────────────────────────────────────────
    def send_data(self):
        if not self.session_key:
            print("[ERROR] No session key — re-authenticating...")
            if not self.authenticate() or not self.exchange_keys():
                return

        data      = self.generate_sensor_data()
        plaintext = json.dumps(data)
        encrypted = encrypt_data(self.session_key, plaintext)

        try:
            r = requests.post(
                f"{self.server_url}/send-data",
                json=encrypted,
                headers={"Authorization": self.session_token},
                timeout=5
            )
            if r.status_code == 200:
                summary = self._summarise(data)
                print(f"[SENT] [{self.sensor_type.upper()}] {summary}")
            elif r.status_code == 403:
                print(f"[ERROR] Session expired — need to re-authenticate")
                self.session_token = None
                self.session_key   = None
            else:
                print(f"[ERROR] Server returned {r.status_code}")
        except Exception as e:
            print(f"[ERROR] {e}")

    def _summarise(self, data):
        t = data.get("sensor_type", "")
        if t == "temperature":
            return f"Temp={data['temperature']}°C  Humidity={data['humidity']}%"
        if t == "camera":
            return f"Res={data['resolution']}  MotionZones={data['motion_zones']}  IR={data['ir_active']}"
        if t == "doorlock":
            return f"State={data['state'].upper()}  Battery={data['battery_pct']}%  Tamper={data['tamper_alert']}"
        if t == "motion":
            return f"Detected={data['motion_detected']}  Zone={data['zone']}  Lux={data['lux_level']}"
        return str(data)

    # ── Main loop ──────────────────────────────────────────────────────────────
    def run(self, interval=5):
        print(f"\nDevice {self.device_id} ({self.sensor_type}) starting...")

        if not self.authenticate():
            print("Authentication failed. Exiting.")
            return
        if not self.exchange_keys():
            print("Key exchange failed. Exiting.")
            return

        print(f"Sending data every {interval}s  (Ctrl+C to stop)\n")
        while True:
            self.send_data()
            time.sleep(interval)


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    device_id = sys.argv[1] if len(sys.argv) > 1 else "sensor_001"

    if device_id not in DEVICE_KEYS:
        print(f"Unknown device: {device_id}")
        print(f"Available: {list(DEVICE_KEYS.keys())}")
        sys.exit(1)

    device = SecureIoTDevice(device_id, DEVICE_KEYS[device_id])
    device.run()