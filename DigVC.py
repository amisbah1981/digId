import json  # For JSON serialization and deserialization
import os  # For generating secure random keys and IVs
from datetime import datetime  # For timestamps in the credential proof
from cryptography.hazmat.primitives.asymmetric import rsa, padding  # For RSA key generation and signing
from cryptography.hazmat.primitives import hashes, serialization  # For hashing and key serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # For AES encryption
import hashlib  # For creating SHA-256 biometric hashes

# Function to hash biometric images
def image_to_hash(image_path):
    """
    Hash an image file using SHA-256.
    This follows ISO/IEC 27001 for secure hashing of biometric data.
    """
    with open(image_path, "rb") as f:
        image_data = f.read()
    hash_value = hashlib.sha256(image_data).hexdigest()
    print(f"Image hashed: {image_path} -> {hash_value}")
    return hash_value

# Function to encrypt biometric data
def encrypt_biometric_data(biometric_data):
    """
    Encrypt biometric data using AES-256.
    This is compliant with ISO/IEC 27001 standards for confidentiality.
    """
    key = os.urandom(32)  # AES-256 key
    iv = os.urandom(16)   # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(json.dumps(biometric_data).encode()) + encryptor.finalize()
    print("Biometric data encrypted.")
    return {
        "encrypted_data": encrypted_data.hex(),
        "key": key.hex(),  # In real-world usage, store this securely in a KMS
        "iv": iv.hex()
    }

# Function to sign the credential
def sign_credential(credential, private_key):
    """
    Sign the Verifiable Credential (VC) using RSA and SHA-256.
    This ensures the authenticity and integrity of the VC, following W3C standards.
    """
    credential_data = json.dumps(credential, sort_keys=True, separators=(',', ':')).encode()
    print("Serialized data for signing:", credential_data)
    signature = private_key.sign(
        credential_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print("Credential signed.")
    return signature.hex()

# Function to save the public key as PEM
def save_public_key_to_pem(public_key, filename="publicKey.pem"):
    """
    Save the RSA public key to a PEM file for sharing with verifiers.
    This follows standard X.509 PEM format for public key serialization.
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, "wb") as f:
        f.write(pem)
    print(f"Public key saved to {filename}")

# Function to generate Verifiable Credential (VC)
def generate_verifiable_credential(digital_id_data, biometric_hashes, private_key):
    """
    Generate a Verifiable Credential, encrypt biometric data, sign the VC, and store it securely.
    The structure follows W3C's Verifiable Credentials Data Model.
    """
    print("Encrypting biometric data...")
    encrypted_biometric_data = encrypt_biometric_data(biometric_hashes)

    # Create the Verifiable Credential
    credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "IDDocument"],
        "id": f"urn:uuid:{digital_id_data['id']}",
        "issuer": digital_id_data["issuer"],
        "issuanceDate": digital_id_data["issuanceDate"],
        "expirationDate": digital_id_data["expirationDate"],
        "credentialSubject": {
            "id": f"urn:uuid:{digital_id_data['id']}",
            "name": digital_id_data["name"],
            "date_of_birth": digital_id_data["date_of_birth"],
            "nationality": digital_id_data["nationality"],
            "biometric_data": encrypted_biometric_data
        }
    }

    print("Signing the credential...")
    signature = sign_credential(credential, private_key)

    # Add proof for signature
    credential["proof"] = {
        "type": "RsaSignature2018",
        "created": datetime.now().isoformat(),
        "verificationMethod": "https://example.com/keys/1",
        "proofPurpose": "assertionMethod",
        "jws": signature
    }

    # Store the credential securely
    filename = f"{digital_id_data['id']}_digital_wallet.json"
    with open(filename, "w") as f:
        json.dump(credential, f, indent=4)
    print(f"Digital Credential stored in {filename}")

    return credential

# Generate RSA key pair
print("Generating RSA keys...")
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
save_public_key_to_pem(public_key)

# Example digital ID data
digital_id_data = {
    "id": "b02bea3f-6bd5-4583-98f9-d5baa9cf118d",
    "issuer": "Government Authority",
    "issuanceDate": "2024-11-14",
    "expirationDate": "2034-11-12",
    "name": "John Doe",
    "date_of_birth": "1990-01-01",
    "nationality": "USA"
}

# Hash biometric images
print("Hashing biometric images...")
biometric_hashes = {
    "face_image_hash": image_to_hash("synthetic_human_face.png"),
    "fingerprint_image_hash": image_to_hash("synthetic_human_fingerprint.png"),
    "iris_image_hash": image_to_hash("synthetic_human_iris.png")
}

# Generate the Verifiable Credential
generate_verifiable_credential(digital_id_data, biometric_hashes, private_key)
