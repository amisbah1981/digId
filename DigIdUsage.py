import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib

# Function to decrypt biometric data
def decrypt_biometric_data(encrypted_data, key, iv):
    """
    Decrypt biometric data using AES-256.
    This ensures the confidentiality of sensitive data, compliant with ISO/IEC 27001.
    """
    key = bytes.fromhex(key)
    iv = bytes.fromhex(iv)
    encrypted_data = bytes.fromhex(encrypted_data)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    print("Biometric data decrypted.")
    return json.loads(decrypted_data)

# Function to hash live biometric samples
def image_to_hash(image_path):
    """
    Hash a live biometric sample using SHA-256.
    """
    with open(image_path, "rb") as f:
        image_data = f.read()
    hash_value = hashlib.sha256(image_data).hexdigest()
    print(f"Live biometric hashed: {image_path} -> {hash_value}")
    return hash_value

# Function to verify the VC's signature
def verify_signature(vc, public_key):
    """
    Verify the signature of the Verifiable Credential using RSA and SHA-256.
    """
    signed_data = {k: v for k, v in vc.items() if k != "proof"}
    signed_data_bytes = json.dumps(signed_data, sort_keys=True, separators=(',', ':')).encode()
    print("Serialized data for verification:", signed_data_bytes)
    signature = bytes.fromhex(vc["proof"]["jws"])
    try:
        public_key.verify(
            signature,
            signed_data_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print("Signature verification succeeded.")
        return True
    except Exception as e:
        print("Signature verification failed:", e)
        return False

# Function to verify biometric data
def verify_biometrics(decrypted_biometric_data, live_biometric_hashes):
    """
    Verify live biometric data against the stored decrypted data.
    """
    for biometric_type, live_hash in live_biometric_hashes.items():
        stored_hash = decrypted_biometric_data.get(biometric_type)
        if live_hash != stored_hash:
            print(f"{biometric_type} verification failed.")
            return False
        print(f"{biometric_type} verification succeeded.")
    return True

# Main function to verify identity
def verify_identity(vc_path, live_face_image, live_fingerprint_image, live_iris_image, public_key_path):
    """
    Perform full identity verification by checking the VC's signature and biometric data.
    """
    # Load the Verifiable Credential
    with open(vc_path, "r") as f:
        vc = json.load(f)

    # Load the public key
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    # Step 1: Verify the VC's signature
    if not verify_signature(vc, public_key):
        print("Identity verification failed due to invalid VC signature.")
        return False

    # Step 2: Decrypt stored biometric data
    biometric_data = vc["credentialSubject"]["biometric_data"]
    decrypted_biometric_data = decrypt_biometric_data(
        biometric_data["encrypted_data"],
        biometric_data["key"],
        biometric_data["iv"]
    )

    # Step 3: Hash live biometric samples
    live_biometric_hashes = {
        "face_image_hash": image_to_hash(live_face_image),
        "fingerprint_image_hash": image_to_hash(live_fingerprint_image),
        "iris_image_hash": image_to_hash(live_iris_image)
    }

    # Step 4: Verify biometric data
    if verify_biometrics(decrypted_biometric_data, live_biometric_hashes):
        print("Identity verification successful.")
        return True
    else:
        print("Identity verification failed.")
        return False

# File paths
vc_path = "b02bea3f-6bd5-4583-98f9-d5baa9cf118d_digital_wallet.json"
public_key_path = "publicKey.pem"
live_face_image = "synthetic_human_face.png"
live_fingerprint_image = "synthetic_human_fingerprint.png"
live_iris_image = "synthetic_human_iris.png"

# Verify the identity
verify_identity(vc_path, live_face_image, live_fingerprint_image, live_iris_image, public_key_path)
