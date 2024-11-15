import json
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from datetime import datetime

# Load biometric data (this could be raw binary data for a real application)
def load_biometric_image(file_path):
    with open(file_path, "rb") as f:
        return f.read()

# Encrypt biometric data with AES-256
def encrypt_biometric_data(biometric_data):
    """
    Encrypt raw biometric data (e.g., fingerprint, face, iris) using AES-256.
    """
    key = os.urandom(32)  # AES-256 key
    iv = os.urandom(16)   # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(biometric_data) + encryptor.finalize()
    return {
        "encrypted_data": encrypted_data.hex(),
        "key": key.hex(),
        "iv": iv.hex()
    }

# Signing the encrypted data
def sign_data(data, private_key):
    """
    Sign encrypted biometric data with RSA to ensure authenticity.
    """
    data_bytes = json.dumps(data, sort_keys=True).encode()
    signature = private_key.sign(
        data_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature.hex()

# Store the encrypted biometric data securely in a digital wallet format
def store_encrypted_biometric_in_wallet(encrypted_data, signature):
    """
    Store encrypted biometric data in a secure JSON format, suitable for digital wallet.
    """
    document = {
        "encrypted_biometric_data": encrypted_data,
        "proof": {
            "type": "RsaSignature2018",
            "created": datetime.now().isoformat(),
            "verificationMethod": "https://example.com/keys/1",
            "proofPurpose": "assertionMethod",
            "jws": signature
        }
    }

    # Save the document as JSON
    filename = f"secure_biometric_document.json"
    with open(filename, "w") as f:
        json.dump(document, f, indent=4)
    print(f"Encrypted biometric document stored securely as '{filename}'")

# Generate RSA keys for signing
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Load, encrypt, and store biometric images
face_data = load_biometric_image("synthetic_human_face.png")
fingerprint_data = load_biometric_image("synthetic_human_fingerprint.png")
iris_data = load_biometric_image("synthetic_human_iris.png")

# Encrypt each biometric data
encrypted_face = encrypt_biometric_data(face_data)
encrypted_fingerprint = encrypt_biometric_data(fingerprint_data)
encrypted_iris = encrypt_biometric_data(iris_data)

# Structure encrypted biometric data
encrypted_biometric_data = {
    "face": encrypted_face,
    "fingerprint": encrypted_fingerprint,
    "iris": encrypted_iris
}

# Sign the encrypted biometric data
signature = sign_data(encrypted_biometric_data, private_key)

# Store the encrypted biometric data in a wallet-compatible JSON format
store_encrypted_biometric_in_wallet(encrypted_biometric_data, signature)
