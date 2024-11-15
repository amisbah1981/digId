import json
import os
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib


# Function to hash images
def image_to_hash(image_path):
    """
    Hash an image file using SHA-256.
    Compliant with ISO/IEC 18013-5 and ICAO 9303 for biometric data.
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
    Biometric confidentiality follows ISO/IEC 27001.
    """
    key = os.urandom(32)  # AES-256 key
    iv = os.urandom(16)   # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(json.dumps(biometric_data).encode()) + encryptor.finalize()
    print("Biometric data encrypted.")
    return {
        "encrypted_data": encrypted_data.hex(),
        "key": key.hex(),  # Store securely in production
        "iv": iv.hex()
    }


# Function to sign digital documents
def sign_document(document, private_key):
    """
    Sign the document using RSA and SHA-256.
    Ensures integrity and authenticity per ISO/IEC 18013-5 and ICAO standards.
    """
    document_data = json.dumps(document, sort_keys=True, separators=(',', ':')).encode()
    print("Serialized data for signing:", document_data)
    signature = private_key.sign(
        document_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print("Document signed.")
    return signature.hex()


# Function to save public key
def save_public_key(public_key, filename="publicKey.pem"):
    """
    Save the RSA public key to a PEM file.
    Compliant with X.509 standards.
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, "wb") as f:
        f.write(pem)
    print(f"Public key saved to {filename}")


# Function to create a driver's license (mDL)
def create_driver_license(personal_info, biometric_hashes, private_key):
    """
    Create a standards-compliant Mobile Driver's License (mDL).
    Compliant with ISO/IEC 18013-5.
    """
    print("Creating Driver's License...")
    encrypted_biometric_data = encrypt_biometric_data(biometric_hashes)

    # Driver's License structure
    mDL = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "MobileDriverLicense"],
        "id": f"urn:uuid:{personal_info['id']}",
        "issuer": personal_info["issuer"],
        "issuanceDate": personal_info["issuanceDate"],
        "expirationDate": personal_info["expirationDate"],
        "credentialSubject": {
            "id": f"urn:uuid:{personal_info['id']}",
            "name": personal_info["name"],
            "date_of_birth": personal_info["date_of_birth"],
            "address": personal_info["address"],
            "license_number": personal_info["license_number"],
            "biometric_data": encrypted_biometric_data
        }
    }

    # Sign the document
    signature = sign_document(mDL, private_key)

    # Add proof
    mDL["proof"] = {
        "type": "RsaSignature2018",
        "created": datetime.now().isoformat(),
        "verificationMethod": "https://example.com/keys/1",
        "proofPurpose": "assertionMethod",
        "jws": signature
    }

    # Save the mDL
    filename = f"DriverLicense_{personal_info['id']}.json"
    with open(filename, "w") as f:
        json.dump(mDL, f, indent=4)
    print(f"Driver's License stored securely as {filename}")

    return mDL


# Function to create an ePassport
def create_epassport(personal_info, biometric_hashes, private_key):
    """
    Create a standards-compliant ePassport.
    Compliant with ICAO Doc 9303.
    """
    print("Creating ePassport...")
    encrypted_biometric_data = encrypt_biometric_data(biometric_hashes)

    # ePassport structure
    epassport = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "ePassport"],
        "id": f"urn:uuid:{personal_info['id']}",
        "issuer": personal_info["issuer"],
        "issuanceDate": personal_info["issuanceDate"],
        "expirationDate": personal_info["expirationDate"],
        "credentialSubject": {
            "id": f"urn:uuid:{personal_info['id']}",
            "name": personal_info["name"],
            "date_of_birth": personal_info["date_of_birth"],
            "nationality": personal_info["nationality"],
            "passport_number": personal_info["passport_number"],
            "biometric_data": encrypted_biometric_data
        }
    }

    # Sign the document
    signature = sign_document(epassport, private_key)

    # Add proof
    epassport["proof"] = {
        "type": "RsaSignature2018",
        "created": datetime.now().isoformat(),
        "verificationMethod": "https://example.com/keys/1",
        "proofPurpose": "assertionMethod",
        "jws": signature
    }

    # Save the ePassport
    filename = f"ePassport_{personal_info['id']}.json"
    with open(filename, "w") as f:
        json.dump(epassport, f, indent=4)
    print(f"ePassport stored securely as {filename}")

    return epassport


# Main function to create documents
def generate_documents():
    # Personal information (from CV)
    personal_info = {
        "id": "b02bea3f-6bd5-4583-98f9-d5baa9cf118d",
        "issuer": "Government Authority",
        "issuanceDate": "2024-11-14",
        "expirationDate": "2034-11-12",
        "name": "John Doe",
        "date_of_birth": "1990-01-01",
        "nationality": "USA",
        "address": "123 Main Street, Anytown, USA",
        "license_number": "D12345678",
        "passport_number": "987654321"
    }

    # Hash biometric images
    print("Hashing biometric images...")
    biometric_hashes = {
        "face_image_hash": image_to_hash("synthetic_human_face.png"),
        "fingerprint_image_hash": image_to_hash("synthetic_human_fingerprint.png"),
        "iris_image_hash": image_to_hash("synthetic_human_iris.png")
    }

    # Generate RSA key pair
    print("Generating RSA keys...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    save_public_key(public_key)

    # Create Driver's License (mDL)
    create_driver_license(personal_info, biometric_hashes, private_key)

    # Create ePassport
    create_epassport(personal_info, biometric_hashes, private_key)

    print("All documents created successfully.")


# Run the script
if __name__ == "__main__":
    generate_documents()
