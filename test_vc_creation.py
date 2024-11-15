import pytest
import json
from DigVC import generate_verifiable_credential, image_to_hash
from cryptography.hazmat.primitives.asymmetric import rsa

def test_generate_vc():
    # Sample data
    digital_id_data = {
        "id": "b02bea3f-6bd5-4583-98f9-d5baa9cf118d",
        "issuer": "Government Authority",
        "issuanceDate": "2024-11-14",
        "expirationDate": "2034-11-12",
        "name": "John Doe",
        "date_of_birth": "1990-01-01",
        "nationality": "USA"
    }

    biometric_hashes = {
        "face_image_hash": image_to_hash("synthetic_human_face.png"),
        "fingerprint_image_hash": image_to_hash("synthetic_human_fingerprint.png"),
        "iris_image_hash": image_to_hash("synthetic_human_iris.png")
    }

    # Generate RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Generate the Verifiable Credential
    vc = generate_verifiable_credential(digital_id_data, biometric_hashes, private_key)

    # Assertions
    assert vc["@context"] == ["https://www.w3.org/2018/credentials/v1"]
    assert vc["type"] == ["VerifiableCredential", "IDDocument"]
    assert vc["credentialSubject"]["name"] == "John Doe"
    assert vc["credentialSubject"]["biometric_data"]["encrypted_data"] is not None
