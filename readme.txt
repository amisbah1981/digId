DIGITAL IDENTITY VERIFICATION AND ID CARD CREATION
==================================================

This project implements a secure and standards-compliant system for verifying identity 
and creating physical ID cards. The system integrates identity verification using a 
Verifiable Credential (VC) with physical card creation following real-world standards 
like ICAO Doc 9303 and ISO/IEC 7810.

==================================================
FEATURES
==================================================

1. IDENTITY VERIFICATION
   - Validates the VC's digital signature using RSA.
   - Decrypts biometric data stored in the VC (AES-256 encrypted).
   - Verifies live biometric samples (face, fingerprint, iris) against the VC.

2. ID CARD CREATION
   - Generates a standards-compliant physical ID card with:
     - Personal details (name, DOB, nationality, passport number).
     - Machine-Readable Zone (MRZ) adhering to ICAO Doc 9303.
     - QR code embedding the VC for verification.
     - Photo and security background.

==================================================
STANDARDS AND LIBRARIES
==================================================

1. STANDARDS
   - W3C Verifiable Credentials: For structuring identity credentials.
   - ICAO Doc 9303: Specifies MRZ formatting for machine-readable travel documents.
   - ISO/IEC 7810: ID-1 format (85.6 mm × 53.98 mm) for physical ID cards.
   - ISO/IEC 27001: AES-256 encryption for securing biometric data.

2. LIBRARIES
   - Pillow: For creating and designing the ID card.
   - qrcode: For generating QR codes to embed VCs.
   - cryptography: For RSA signing, AES encryption, and decryption.
   - hashlib: For hashing biometric samples (SHA-256).
   - json: For handling and storing VC data.

==================================================
PROJECT STRUCTURE
==================================================

project-root/
├── validate_and_create_card.py    # Main script for verification and ID creation
├── ePassport_b02bea3f-6bd5-4583-98f9-d5baa9cf118d.json # Example VC
├── synthetic_human_face.png       # Example face image
├── synthetic_human_fingerprint.png # Example fingerprint image
├── synthetic_human_iris.png       # Example iris image
├── publicKey.pem                  # Public key for VC verification
├── Standard_Physical_ID_Card.png  # Generated ID card output
├── LICENSE                        # GPL v3 license
├── README.txt                     # Project documentation

==================================================
INSTALLATION
==================================================

1. CLONE THE REPOSITORY
   git clone https://github.com/your-username/digital-id-system.git
   cd digital-id-system

2. INSTALL DEPENDENCIES
   This project requires Python 3.x and the following libraries:
   pip install Pillow cryptography qrcode

==================================================
USAGE
==================================================

1. IDENTITY VERIFICATION AND CARD CREATION
   Run the script to verify identity using the VC and generate a physical ID card:
   python validate_and_create_card.py

2. INPUTS
   - VC JSON: `ePassport_b02bea3f-6bd5-4583-98f9-d5baa9cf118d.json` (contains personal details and encrypted biometric data).
   - Public Key: `publicKey.pem` (for verifying the VC's digital signature).
   - Biometric Images:
     - `synthetic_human_face.png`
     - `synthetic_human_fingerprint.png`
     - `synthetic_human_iris.png`

3. OUTPUT
   - Generated Card: `Standard_Physical_ID_Card.png`

==================================================
HOW IT WORKS
==================================================

1. IDENTITY VERIFICATION
   - Step 1: The VC is loaded and its RSA signature is verified.
   - Step 2: Encrypted biometric data in the VC is decrypted using AES-256.
   - Step 3: Live biometric samples are hashed and compared to the decrypted VC data.

2. ID CARD CREATION
   - Step 4: A physical ID card is generated, including:
     - Photo and personal details.
     - Machine-readable MRZ (ICAO Doc 9303 format).
     - QR code embedding the VC.

==================================================
SECURITY CONSIDERATIONS
==================================================

1. KEY MANAGEMENT
   - The private key used for signing the VC should be stored securely.
   - The public key (`publicKey.pem`) is used for verification and can be distributed.

2. DATA SECURITY
   - Biometric data is AES-256 encrypted for confidentiality.
   - MRZ and QR codes are designed for interoperability and machine readability.

3. REAL-TIME VERIFICATION
   - Live biometric samples ensure the person presenting the card matches the VC data.

==================================================
EXAMPLE MRZ
==================================================

For an ePassport, the MRZ lines might look like:

P<DOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<
987654321<USA19900101<M20341112<

==================================================
LICENSE
==================================================

This project is licensed under the GNU General Public License v3.0 (GPL v3).

You can redistribute it and/or modify it under the terms of the GPL v3 as published
by the Free Software Foundation, either version 3 of the License, or (at your option)
any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY 
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with 
this program. If not, see <https://www.gnu.org/licenses/>.

==================================================
CONTRIBUTING
==================================================

Contributions are welcome! Open issues or create pull requests to improve this project.
