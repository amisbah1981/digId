import pytest
from DigIdUsage import verify_identity, image_to_hash

def test_verify_identity():
    # Paths to required files
    vc_path = "b02bea3f-6bd5-4583-98f9-d5baa9cf118d_digital_wallet.json"
    public_key_path = "publicKey.pem"
    live_face_image = "synthetic_human_face.png"
    live_fingerprint_image = "synthetic_human_fingerprint.png"
    live_iris_image = "synthetic_human_iris.png"

    # Verify identity
    result = verify_identity(vc_path, live_face_image, live_fingerprint_image, live_iris_image, public_key_path)

    # Assertions
    assert result is True
