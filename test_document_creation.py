import pytest
from DigDocCreation import create_driver_license, create_epassport, image_to_hash
from cryptography.hazmat.primitives.asymmetric import rsa

def test_create_driver_license():
    # Sample data
    personal_info = {
        "id": "b02bea3f-6bd5-4583-98f9-d5baa9cf118d",
        "issuer": "Government Authority",
        "issuanceDate": "2024-11-14",
        "expirationDate": "2034-11-12",
        "name": "John Doe",
        "date_of_birth": "1990-01-01",
        "address": "123 Main Street, Anytown, USA",
        "license_number": "D12345678"
    }

    biometric_hashes = {
        "face_image_hash": image_to_hash("synthetic_human_face.png"),
        "fingerprint_image_hash": image_to_hash("synthetic_human_fingerprint.png"),
        "iris_image_hash": image_to_hash("synthetic_human_iris.png")
    }

    # Generate RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Create Driver's License
    mDL = create_driver_license(personal_info, biometric_hashes, private_key)

    # Assertions
    assert mDL["@context"] == ["https://www.w3.org/2018/credentials/v1"]
    assert mDL["type"] == ["VerifiableCredential", "MobileDriverLicense"]
    assert mDL["credentialSubject"]["license_number"] == "D12345678"

def test_create_epassport():
    # Similar to the driver's license test, but for ePassports
    personal_info = {
        "id": "b02bea3f-6bd5-4583-98f9-d5baa9cf118d",
        "issuer": "Government Authority",
        "issuanceDate": "2024-11-14",
        "expirationDate": "2034-11-12",
        "name": "John Doe",
        "date_of_birth": "1990-01-01",
        "nationality": "USA",
        "passport_number": "987654321"
    }

    biometric_hashes = {
        "face_image_hash": image_to_hash("synthetic_human_face.png"),
        "fingerprint_image_hash": image_to_hash("synthetic_human_fingerprint.png"),
        "iris_image_hash": image_to_hash("synthetic_human_iris.png")
    }

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    epassport = create_epassport(personal_info, biometric_hashes, private_key)

    assert epassport["type"] == ["VerifiableCredential", "ePassport"]
    assert epassport["credentialSubject"]["passport_number"] == "987654321"
