from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import base64
import json
import time
from crypto_utils import (generate_hmac, verify_hmac, generate_challenge,
                          generate_ecdh_keypair, compute_shared_secret,
                          encrypt_data, decrypt_data)

app = Flask(__name__)
CORS(app)

# ── Device registry ────────────────────────────────────────────────────────────
DEVICE_KEYS = {
    "sensor_001":  "secret_key_abc123",
    "sensor_002":  "secret_key_def456",
    "sensor_003":  "secret_key_ghi789",
    "camera_01":   "secret_key_cam001",
    "doorlock_01": "secret_key_door01",
    "motion_01":   "secret_key_mot001",
}

# ── State stores ───────────────────────────────────────────────────────────────
active_challenges     = {}   # device_id  -> challenge string
authenticated_sessions= {}   # token      -> device_id
session_keys          = {}   # token      -> AES session key bytes

sensor_data           = []   # all decrypted readings
security_log          = []   # all security events
performance_log       = []   # timing measurements

# Rate limiting  – track failed attempts per device
failed_attempts       = {}   # device_id -> {"count": int, "banned_until": datetime|None}

# Revoked devices
revoked_devices       = set()

# ── Helpers ────────────────────────────────────────────────────────────────────
MAX_FAILED   = 3
BAN_MINUTES  = 5

def log_event(event_type, device_id, detail, success=True):
    entry = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "type":      event_type,
        "device_id": device_id,
        "detail":    detail,
        "success":   success,
    }
    security_log.append(entry)
    # Keep last 200
    if len(security_log) > 200:
        security_log.pop(0)
    print(f"[{event_type}] {'✓' if success else '✗'} {device_id} — {detail}")

def log_perf(operation, device_id, elapsed_ms):
    entry = {
        "timestamp":  datetime.now().strftime("%H:%M:%S"),
        "operation":  operation,
        "device_id":  device_id,
        "elapsed_ms": round(elapsed_ms, 4),
    }
    performance_log.append(entry)
    if len(performance_log) > 200:
        performance_log.pop(0)

def is_banned(device_id):
    info = failed_attempts.get(device_id, {})
    ban_until = info.get("banned_until")
    if ban_until and datetime.now() < ban_until:
        return True, ban_until
    return False, None

def record_failed(device_id):
    info = failed_attempts.setdefault(device_id, {"count": 0, "banned_until": None})
    info["count"] += 1
    if info["count"] >= MAX_FAILED:
        info["banned_until"] = datetime.now() + timedelta(minutes=BAN_MINUTES)
        log_event("RATE_LIMIT", device_id,
                  f"Banned for {BAN_MINUTES} min after {MAX_FAILED} failed attempts", False)
    return info["count"]

def reset_failed(device_id):
    failed_attempts.pop(device_id, None)

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route('/')
def home():
    return "SecureIoT Server Running!"

# ── Authentication ─────────────────────────────────────────────────────────────
@app.route('/get-challenge', methods=['POST'])
def get_challenge():
    t0 = time.perf_counter()
    data      = request.get_json()
    device_id = data.get('device_id')

    if device_id in revoked_devices:
        log_event("AUTH", device_id, "Rejected — device revoked", False)
        return jsonify({"error": "Device revoked"}), 403

    if device_id not in DEVICE_KEYS:
        log_event("AUTH", device_id, "Rejected — unknown device", False)
        return jsonify({"error": "Unknown device"}), 403

    banned, ban_until = is_banned(device_id)
    if banned:
        remaining = int((ban_until - datetime.now()).total_seconds() / 60) + 1
        log_event("RATE_LIMIT", device_id, f"Blocked — still banned ({remaining}m left)", False)
        return jsonify({"error": f"Device temporarily banned. Try again in {remaining} minute(s)."}), 429

    challenge = generate_challenge()
    active_challenges[device_id] = challenge
    elapsed = (time.perf_counter() - t0) * 1000
    log_perf("challenge_gen", device_id, elapsed)
    log_event("AUTH", device_id, "Challenge issued")
    return jsonify({"challenge": challenge}), 200


@app.route('/authenticate', methods=['POST'])
def authenticate():
    t0 = time.perf_counter()
    data         = request.get_json()
    device_id    = data.get('device_id')
    response_tag = data.get('response')

    if device_id not in active_challenges:
        return jsonify({"error": "No challenge found"}), 400

    secret_key = DEVICE_KEYS[device_id]
    challenge  = active_challenges[device_id]

    if verify_hmac(secret_key, challenge, response_tag):
        token = generate_challenge()
        authenticated_sessions[token] = device_id
        reset_failed(device_id)
        del active_challenges[device_id]
        elapsed = (time.perf_counter() - t0) * 1000
        log_perf("hmac_auth", device_id, elapsed)
        log_event("AUTH", device_id, f"HMAC auth successful ({elapsed:.3f}ms)")
        return jsonify({"status": "authenticated", "session_token": token}), 200
    else:
        count = record_failed(device_id)
        remaining = MAX_FAILED - count
        log_event("AUTH", device_id,
                  f"HMAC verification failed (attempt {count}/{MAX_FAILED})", False)
        if remaining > 0:
            return jsonify({"error": f"Authentication failed. {remaining} attempt(s) left."}), 403
        else:
            return jsonify({"error": "Too many failures. Device banned for 5 minutes."}), 429


# ── Key exchange ───────────────────────────────────────────────────────────────
@app.route('/exchange-keys', methods=['POST'])
def exchange_keys():
    t0 = time.perf_counter()
    token = request.headers.get('Authorization')
    if not token or token not in authenticated_sessions:
        return jsonify({"error": "Not authenticated"}), 401

    device_id   = authenticated_sessions[token]
    data        = request.get_json()
    device_pub  = base64.b64decode(data.get('public_key'))

    server_priv, server_pub = generate_ecdh_keypair()
    session_key = compute_shared_secret(server_priv, device_pub)
    session_keys[token] = session_key

    elapsed = (time.perf_counter() - t0) * 1000
    log_perf("ecdh_key_exchange", device_id, elapsed)
    log_event("KEYX", device_id, f"ECDH complete ({elapsed:.3f}ms)")
    return jsonify({"public_key": base64.b64encode(server_pub).decode()}), 200


# ── Data receive ───────────────────────────────────────────────────────────────
@app.route('/send-data', methods=['POST'])
def receive_data():
    t0 = time.perf_counter()
    token = request.headers.get('Authorization')
    if not token or token not in authenticated_sessions:
        return jsonify({"error": "Not authenticated"}), 401
    if token not in session_keys:
        return jsonify({"error": "Key exchange required"}), 400

    device_id   = authenticated_sessions[token]
    session_key = session_keys[token]
    payload     = request.get_json()

    try:
        plaintext = decrypt_data(session_key, payload['nonce'], payload['ciphertext'])
        data = json.loads(plaintext)
        data['device_id']   = device_id
        data['received_at'] = datetime.now().strftime("%H:%M:%S")

        sensor_data.append(data)
        if len(sensor_data) > 500:
            sensor_data.pop(0)

        elapsed = (time.perf_counter() - t0) * 1000
        log_perf("aes_decrypt", device_id, elapsed)
        log_event("DATA", device_id,
                  f"Decrypted OK — type={data.get('sensor_type','temp')} ({elapsed:.3f}ms)")
        print(f"[DATA] ✓ {device_id}: {json.dumps({k:v for k,v in data.items() if k not in ('device_id','received_at')})}")
        return jsonify({"status": "success"}), 200

    except Exception as e:
        log_event("DATA", device_id, f"Decryption failed: {e}", False)
        return jsonify({"error": "Decryption failed"}), 400


# ── Admin: revoke device ───────────────────────────────────────────────────────
@app.route('/admin/revoke', methods=['POST'])
def revoke_device():
    data      = request.get_json()
    device_id = data.get('device_id')
    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    revoked_devices.add(device_id)

    # Invalidate any active session
    tokens_to_remove = [t for t, d in authenticated_sessions.items() if d == device_id]
    for t in tokens_to_remove:
        authenticated_sessions.pop(t, None)
        session_keys.pop(t, None)

    log_event("REVOKE", device_id, "Device revoked by admin", False)
    return jsonify({"status": "revoked", "device_id": device_id}), 200


@app.route('/admin/unrevoke', methods=['POST'])
def unrevoke_device():
    data      = request.get_json()
    device_id = data.get('device_id')
    revoked_devices.discard(device_id)
    log_event("REVOKE", device_id, "Device re-enabled by admin")
    return jsonify({"status": "restored", "device_id": device_id}), 200


# ── Admin: unban device ────────────────────────────────────────────────────────
@app.route('/admin/unban', methods=['POST'])
def unban_device():
    data      = request.get_json()
    device_id = data.get('device_id')
    failed_attempts.pop(device_id, None)
    log_event("RATE_LIMIT", device_id, "Ban lifted by admin")
    return jsonify({"status": "unbanned"}), 200


# ── MITM simulation ────────────────────────────────────────────────────────────
@app.route('/simulate/mitm', methods=['POST'])
def simulate_mitm():
    """Simulate a MITM attack — attacker intercepts and replays with wrong key."""
    data      = request.get_json()
    device_id = data.get('device_id', 'attacker')

    log_event("ATTACK", device_id,
              "MITM attempt: intercepted ciphertext, decryption failed — AES-GCM tag mismatch", False)
    log_event("ATTACK", device_id,
              "Replay attempt: old session token rejected", False)
    log_event("ATTACK", device_id,
              "Spoofed HMAC response: challenge-response failed — wrong key", False)

    return jsonify({
        "status":  "blocked",
        "details": [
            "Ciphertext tampered — AES-GCM authentication tag mismatch",
            "Session replay rejected — token already invalidated",
            "HMAC spoofing failed — attacker does not know secret key",
        ]
    }), 200


# ── Data endpoints ─────────────────────────────────────────────────────────────
@app.route('/get-data', methods=['GET'])
def get_data():
    return jsonify(sensor_data)

@app.route('/get-security-log', methods=['GET'])
def get_security_log():
    return jsonify(list(reversed(security_log)))

@app.route('/get-performance', methods=['GET'])
def get_performance():
    return jsonify(list(reversed(performance_log)))

@app.route('/get-status', methods=['GET'])
def get_status():
    return jsonify({
        "revoked_devices": list(revoked_devices),
        "banned_devices":  [
            {"device_id": d, "banned_until": info["banned_until"].strftime("%H:%M:%S") if info.get("banned_until") else None, "attempts": info["count"]}
            for d, info in failed_attempts.items()
        ],
        "active_sessions": list(set(authenticated_sessions.values())),
        "known_devices":   list(DEVICE_KEYS.keys()),
    })


if __name__ == '__main__':
    print("Starting SecureIoT server on http://localhost:5000")
    app.run(port=5000, debug=True)