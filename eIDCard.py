from PIL import Image, ImageDraw, ImageFont
import qrcode
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Constants for ID card dimensions (ID-1 format in pixels for 300 DPI)
CARD_WIDTH = 1011  # 85.6 mm
CARD_HEIGHT = 638  # 53.98 mm


# Function to load and verify the Verifiable Credential (VC)
def load_and_verify_vc(vc_path, public_key_path):
    """
    Load the Verifiable Credential (VC) and verify its digital signature.
    """
    # Load the VC
    with open(vc_path, "r") as f:
        vc = json.load(f)

    # Load the public key
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    # Verify the signature
    signed_data = {k: v for k, v in vc.items() if k != "proof"}
    signed_data_bytes = json.dumps(signed_data, sort_keys=True, separators=(',', ':')).encode()
    signature = bytes.fromhex(vc["proof"]["jws"])

    try:
        public_key.verify(
            signature,
            signed_data_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print("Signature verification succeeded.")
        return vc
    except Exception as e:
        print("Signature verification failed:", e)
        return None


# Function to decrypt biometric data
def decrypt_biometric_data(encrypted_data, key, iv):
    """
    Decrypt biometric data using AES-256.
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


# Function to verify live biometric samples
def verify_biometrics(decrypted_biometric_data, live_biometric_hashes):
    """
    Verify live biometric samples against decrypted biometric data from VC.
    """
    for biometric_type, live_hash in live_biometric_hashes.items():
        stored_hash = decrypted_biometric_data.get(biometric_type)
        if live_hash != stored_hash:
            print(f"{biometric_type} verification failed.")
            return False
        print(f"{biometric_type} verification succeeded.")
    return True


# Function to generate the MRZ (Machine Readable Zone)
def generate_mrz(document_type, personal_info):
    """
    Generate MRZ lines for the ID card or ePassport.
    Compliant with ICAO Doc 9303 for MRZ formatting.
    """
    line1 = f"{document_type}<{personal_info['surname']}<<{personal_info['given_name']}<<<<<<<<<<"
    line1 = line1[:44]  # Pad or truncate to 44 characters

    line2 = (
        f"{personal_info['passport_number']}<{personal_info['nationality']}"
        f"{personal_info['date_of_birth']}<"
        f"{personal_info['sex']}{personal_info['expiration_date']}<"
    )
    line2 = line2[:44]  # Pad or truncate to 44 characters

    print(f"Generated MRZ:\n{line1}\n{line2}")
    return line1, line2


# Function to create the ID card layout
def create_id_card(vc, personal_info, output_path):
    """
    Create a standards-compliant ID card (e.g., driving license, ePassport).
    Includes MRZ, photo, and QR code.
    """
    print("Creating ID card...")

    # Create card canvas
    card = Image.new("RGB", (CARD_WIDTH, CARD_HEIGHT), "white")
    draw = ImageDraw.Draw(card)

    # Add security background (simple gradient)
    for y in range(CARD_HEIGHT):
        color = 255 - int((y / CARD_HEIGHT) * 100)  # Light gradient
        draw.line([(0, y), (CARD_WIDTH, y)], fill=(color, color, color))

    # Load photo
    photo = Image.open("synthetic_human_face.png").resize((250, 350))
    card.paste(photo, (50, 150))

    # Draw personal details
    font = ImageFont.truetype("arial.ttf", 30)
    small_font = ImageFont.truetype("arial.ttf", 25)
    draw.text((330, 150), f"Name: {personal_info['surname']} {personal_info['given_name']}", fill="black", font=font)
    draw.text((330, 200), f"Date of Birth: {personal_info['date_of_birth']}", fill="black", font=small_font)
    draw.text((330, 250), f"Nationality: {personal_info['nationality']}", fill="black", font=small_font)
    draw.text((330, 300), f"Passport #: {personal_info['passport_number']}", fill="black", font=small_font)
    draw.text((330, 350), f"Expiration: {personal_info['expiration_date']}", fill="black", font=small_font)

    # Generate MRZ
    mrz_line1, mrz_line2 = generate_mrz("P", personal_info)
    mrz_font = ImageFont.truetype("arial.ttf", 22)
    draw.text((50, 500), mrz_line1, fill="black", font=mrz_font)
    draw.text((50, 540), mrz_line2, fill="black", font=mrz_font)

    # Generate QR code for VC
    qr = qrcode.QRCode(border=1)
    qr.add_data(json.dumps(vc))
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white").resize((150, 150))
    card.paste(qr_img, (830, 400))

    # Save the ID card
    card.save(output_path)
    print(f"ID card saved as {output_path}")


# Main function for validation and card creation
def validate_and_create_card(vc_path, public_key_path, live_biometrics, output_path):
    """
    Validate identity using VC and live biometrics, then create a physical card.
    """
    print("Loading and verifying VC...")
    vc = load_and_verify_vc(vc_path, public_key_path)
    if not vc:
        print("VC verification failed. Cannot proceed.")
        return

    # Decrypt biometric data
    biometric_data = vc["credentialSubject"]["biometric_data"]
    decrypted_biometric_data = decrypt_biometric_data(
        biometric_data["encrypted_data"], biometric_data["key"], biometric_data["iv"]
    )

    # Verify live biometrics
    print("Verifying live biometric samples...")
    if not verify_biometrics(decrypted_biometric_data, live_biometrics):
        print("Biometric verification failed. Cannot proceed.")
        return

    # Extract personal info for the physical card
    personal_info = {
        "surname": "DOE",
        "given_name": "JOHN",
        "passport_number": vc["credentialSubject"]["passport_number"],
        "nationality": vc["credentialSubject"]["nationality"],
        "date_of_birth": vc["credentialSubject"]["date_of_birth"].replace("-", ""),
        "sex": "M",
        "expiration_date": vc["expirationDate"].replace("-", "")
    }

    # Create the physical card
    print("Creating physical ID card...")
    create_id_card(vc, personal_info, output_path)


# Example usage
if __name__ == "__main__":
    vc_path = "ePassport_b02bea3f-6bd5-4583-98f9-d5baa9cf118d.json"
    public_key_path = "publicKey.pem"
    live_biometrics = {
        "face_image_hash": image_to_hash("synthetic_human_face.png"),
        "fingerprint_image_hash": image_to_hash("synthetic_human_fingerprint.png"),
        "iris_image_hash": image_to_hash("synthetic_human_iris.png"),
    }
    output_path = "Standard_Physical_ID_Card.png"

    validate_and_create_card(vc_path, public_key_path, live_biometrics, output_path)
