# SecureIoT Protocol

A lightweight security protocol for resource-constrained IoT devices, built from scratch in Python. Implements mutual authentication, end-to-end encryption, and key exchange — without relying on TLS.

---

## What This Project Does

Most IoT devices are too small and slow to run TLS. This project builds a custom three-layer security protocol that solves that:

1. **HMAC-SHA256 challenge-response** — proves a device is who it claims to be
2. **ECDH key exchange** — two parties derive a shared secret without transmitting it
3. **AES-128-GCM encryption** — all sensor data is encrypted and tamper-proof in transit

The result is a protocol that is ~45x faster than a TLS handshake while still providing authentication, encryption, forward secrecy, and replay attack prevention.

---

The project includes a live web dashboard showing:
- Real-time sensor readings from multiple device types
- Security event log (every auth attempt, key exchange, data receive)
- Performance metrics (actual measured timing per operation)
- Attack simulation — watch MITM, replay, and HMAC spoofing get blocked in real time
- Device revocation — ban a compromised device with one click

---

## Security Features

| Feature | Implementation | Purpose |
|---|---|---|
| Authentication | HMAC-SHA256 challenge-response | Proves device identity |
| Encryption | AES-128-GCM | Hides data in transit |
| Key exchange | ECDH (SECP256R1) | Derives session keys without sharing them |
| Forward secrecy | Ephemeral ECDH keys | Past sessions safe if key is leaked |
| Integrity | AES-GCM auth tag | Detects any tampering |
| Replay prevention | One-time challenges | Old captured messages can't be reused |
| Rate limiting | 3 strikes → 5 min ban | Blocks brute force attacks |
| Device revocation | Admin blacklist | Permanently blocks compromised devices |

---

## Supported Device Types

| Device | Sensor Type | Data Sent |
|---|---|---|
| `sensor_001/002/003` | Temperature sensor | Temperature °C, Humidity % |
| `camera_01` | IP camera | Resolution, motion zones, IR status, frame hash |
| `doorlock_01` | Smart door lock | Lock state, battery %, last event, tamper alert |
| `motion_01` | Motion detector | Detection boolean, zone, lux level, sensitivity |

---

## Project Structure

```
iot-security-project/
├── server.py          # Flask server — auth, key exchange, data receive, admin APIs
├── device.py          # IoT device simulator — 4 sensor types
├── crypto_utils.py    # Cryptographic primitives — HMAC, ECDH, AES-GCM
├── dashboard.html     # Live web dashboard — tabbed UI, attack simulation
├── fake_device.py     # Attack tester — demonstrates rejection of unauthenticated requests
└── README.md
```

---

## Installation

**Requirements:** Python 3.9+

```bash
git clone https://github.com/YOUR_USERNAME/iot-security-project.git
cd iot-security-project

pip install flask flask-cors requests cryptography
```

---

## Running the Project

**Terminal 1 — Start the server:**
```bash
python server.py
```

**Terminal 2, 3, 4 ... — Start devices:**
```bash
python device.py sensor_001
python device.py camera_01
python device.py doorlock_01
python device.py motion_01
```

**Browser — Open the dashboard:**
```
Open dashboard.html in any browser
```

You should see all devices appear on the dashboard within a few seconds.

---

## How the Protocol Works

```
Device                              Server
  |                                   |
  |--- POST /get-challenge ---------->|   Device identifies itself
  |<-- { challenge: "a3f9..." } ------|   Server sends random nonce
  |                                   |
  |  HMAC(secret_key, challenge)      |   Device signs the challenge
  |--- POST /authenticate ----------->|   with its secret key
  |<-- { session_token: "..." } ------|   Server verifies and issues token
  |                                   |
  |--- POST /exchange-keys ---------->|   Device sends ECDH public key
  |<-- { public_key: "..." } ---------|   Server sends its ECDH public key
  |                                   |
  |  Both sides compute:              |
  |  shared_secret = ECDH(priv, pub)  |   Shared session key derived
  |  session_key   = HKDF(secret)     |   without ever transmitting it
  |                                   |
  |--- POST /send-data (encrypted) -->|   AES-GCM encrypted payload
  |    { nonce, ciphertext }          |   Attacker sees only gibberish
  |<-- { status: "success" } ---------|
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/get-challenge` | Step 1 of auth — server issues nonce |
| POST | `/authenticate` | Step 2 of auth — HMAC verification |
| POST | `/exchange-keys` | ECDH public key exchange |
| POST | `/send-data` | Send encrypted sensor payload |
| GET  | `/get-data` | Retrieve all sensor readings |
| GET  | `/get-security-log` | All security events |
| GET  | `/get-performance` | Operation timing measurements |
| GET  | `/get-status` | Active sessions, bans, revocations |
| POST | `/admin/revoke` | Permanently block a device |
| POST | `/admin/unrevoke` | Restore a revoked device |
| POST | `/admin/unban` | Lift a rate-limit ban |
| POST | `/simulate/mitm` | Trigger MITM attack simulation |

---

## Performance

All timings measured on localhost. Actual network adds latency on top but crypto overhead stays the same.

| Operation | Typical time |
|---|---|
| Challenge generation | < 0.1 ms |
| HMAC authentication | < 0.5 ms |
| ECDH key exchange | ~ 10 ms |
| AES-GCM decrypt | < 0.5 ms |
| **Total overhead** | **~ 11 ms** |
| TLS handshake (baseline) | ~ 500 ms |

---

## Demonstrating Attacks

**Test rejection of unauthenticated requests:**
```bash
python fake_device.py
# Expected: 401 Unauthorized
```

**Simulate MITM attack from dashboard:**
- Open the dashboard → click "Attack Sim" tab → click "Simulate MITM Attack"
- Watch all three attack vectors get blocked in real time

**Trigger rate limiting:**
- Attempt to authenticate with a wrong key 3 times
- Device gets banned for 5 minutes
- Server logs the ban in the security event log

---

## Built With

- [Flask](https://flask.palletsprojects.com/) — web server
- [cryptography](https://cryptography.io/) — ECDH, AES-GCM, HKDF primitives
- Python `hmac` / `hashlib` — HMAC-SHA256 (standard library)
- Vanilla JS + HTML/CSS — dashboard (no frameworks, no dependencies)

---

## Week-by-Week Build Log

| Week | What was built |
|---|---|
| Week 1 | Basic Flask server + device simulator, plain HTTP |
| Week 2 | HMAC challenge-response authentication |
| Week 3 | ECDH key exchange + AES-GCM encryption |
| Week 4 | Dashboard, rate limiting, revocation, attack simulation, multiple sensor types |

---

## License

MIT License — free to use, modify, and distribute.
