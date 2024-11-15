DIGITAL IDENTITY SYSTEM
=======================

This project implements a comprehensive and secure system for managing digital identities. It includes:

1. **Verifiable Credential (VC) Creation**: Standards-compliant digital credentials based on W3C guidelines.
2. **Digital Document Creation**: Generates Mobile Driver's Licenses (mDLs) and ePassports.
3. **Identity Verification**: Uses biometric data to authenticate identities.
4. **Physical ID Card Creation**: Generates real-world physical ID cards with MRZ and embedded digital data.

=======================
FEATURES
=======================

1. **VERIFIABLE CREDENTIAL CREATION**
   - Compliant with **W3C Verifiable Credentials** standards.
   - Secures biometric data using AES-256 encryption.
   - Digitally signs credentials with RSA for integrity.

2. **DIGITAL DOCUMENT CREATION**
   - Generates Mobile Driver's Licenses (mDLs) adhering to **ISO/IEC 18013-5**.
   - Creates ePassports in line with **ICAO Doc 9303** standards.

3. **IDENTITY VERIFICATION**
   - Validates digital signatures on VCs using RSA.
   - Matches encrypted biometric data with live samples.

4. **PHYSICAL ID CARD CREATION**
   - Compliant with **ISO/IEC 7810** for ID-1 card dimensions.
   - Includes Machine Readable Zone (MRZ) and QR codes for embedded VC data.

=======================
STANDARDS AND LIBRARIES
=======================

1. **STANDARDS**
   - **W3C Verifiable Credentials**: For structuring digital identity.
   - **ISO/IEC 18013-5**: Guidelines for mobile driver's licenses.
   - **ICAO Doc 9303**: Defines MRZ formatting for travel documents.
   - **ISO/IEC 7810**: Specifies ID-1 card dimensions.
   - **ISO/IEC 27001**: Ensures data security through AES-256 encryption.

2. **LIBRARIES**
   - Pillow: For designing and creating ID cards.
   - qrcode: For embedding VCs as QR codes.
   - cryptography: For RSA signing, AES encryption, and decryption.
   - hashlib: For hashing biometric samples with SHA-256.
   - json: For handling structured VC data.

=======================
PROJECT STRUCTURE
=======================

project-root/
├── DigVC.py                       # Script for Verifiable Credential creation
├── DigDocCreation.py              # Script for creating digital documents
├── DigIdUsage.py                  # Script for verifying and using digital documents
├── synthetic_human_face.png       # Example face image
├── synthetic_human_fingerprint.png # Example fingerprint image
├── synthetic_human_iris.png       # Example iris image
├── publicKey.pem                  # Public key for VC verification
├── LICENSE                        # GPL v3 license
├── README.txt                     # Project documentation

=======================
INSTALLATION
=======================

1. Clone the repository to your system.
2. Install the required Python libraries: Pillow, cryptography, and qrcode.

=======================
USAGE
=======================

### 1. **VERIFIABLE CREDENTIAL CREATION**
- Run the script for VC creation (DigVC.py).
- Input biometric images and personal details.
- Outputs a standards-compliant JSON file representing the VC.

### 2. **DIGITAL DOCUMENT CREATION**
- Run the document creation script (DigDocCreation.py) to generate Mobile Driver's Licenses and ePassports.
- Outputs JSON files representing the created documents.

### 3. **IDENTITY VERIFICATION**
- Run the identity verification script (DigIdUsage.py).
- Verifies the provided VC and matches it against live biometric samples.

### 4. **PHYSICAL ID CARD CREATION**
- The system generates a physical ID card based on ISO/IEC 7810 standards.
- Includes personal details, photo, MRZ, and QR code for verification.

=======================
SECURITY CONSIDERATIONS
=======================

1. **KEY MANAGEMENT**
   - Private keys used for signing must be securely stored.
   - Public keys can be distributed for verification purposes.

2. **DATA SECURITY**
   - Biometric data is encrypted with AES-256 to ensure confidentiality.
   - MRZ and QR codes enable machine-readable and interoperable identity verification.

3. **REAL-TIME VERIFICATION**
   - Live biometric samples ensure the person presenting the document matches the identity.

=======================
EXAMPLE MRZ
=======================

For an ePassport, the MRZ lines might look like:

P<DOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<
987654321<USA19900101<M20341112<

=======================
LICENSE
=======================

This project is licensed under the GNU General Public License v3.0 (GPL v3).

You can redistribute it and/or modify it under the terms of the GPL v3 as published
by the Free Software Foundation, either version 3 of the License, or (at your option)
any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY 
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with 
this program. If not, see <https://www.gnu.org/licenses/>.

=======================
CONTRIBUTING
=======================

Contributions are welcome! Open issues or create pull requests to improve this project.
