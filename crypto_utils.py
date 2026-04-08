import hmac
import hashlib
import secrets
import os
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_hmac(key, message):
    """
    Compute HMAC-SHA256
    
    Args:
        key: Secret key (bytes)
        message: Message to authenticate (string)
    
    Returns:
        HMAC tag as hex string
    """
    key_bytes = key.encode() if isinstance(key, str) else key
    message_bytes = message.encode() if isinstance(message, str) else message
    
    tag = hmac.new(key_bytes, message_bytes, hashlib.sha256).digest()
    return tag.hex()

def verify_hmac(key, message, received_tag):
    """
    Verify HMAC tag
    
    Returns:
        True if valid, False otherwise
    """
    expected_tag = generate_hmac(key, message)
    return hmac.compare_digest(expected_tag, received_tag)

def generate_challenge():
    """Generate random challenge for authentication"""
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters

# ECDH Functions
def generate_ecdh_keypair():
    """Generate ECDH key pair"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    # Serialize public key to bytes
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    return private_key, public_bytes

def compute_shared_secret(private_key, peer_public_bytes):
    """Compute ECDH shared secret"""
    # Deserialize peer's public key
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        peer_public_bytes
    )
    
    # Compute shared secret
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    
    # Derive session key using HKDF
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'session-key'
    ).derive(shared_secret)
    
    return session_key

# AES-GCM Functions
def encrypt_data(session_key, plaintext):
    """Encrypt data with AES-GCM"""
    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)  # 96-bit nonce
    
    plaintext_bytes = plaintext.encode() if isinstance(plaintext, str) else plaintext
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

def decrypt_data(session_key, nonce_b64, ciphertext_b64):
    """Decrypt data with AES-GCM"""
    aesgcm = AESGCM(session_key)
    
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext_bytes.decode()