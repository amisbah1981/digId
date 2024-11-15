# Digital Document Management System

This project implements a secure system to generate and verify digital documents, including **Mobile Driver's Licenses (mDL)** and **ePassports**, following real-world standards. The system uses **W3C Verifiable Credentials (VC)** as the foundational data structure.

## Features

- **Standards Compliance**:
  - **Driver's License (mDL)**: Compliant with **ISO/IEC 18013-5** for mobile driver's licenses.
  - **ePassport**: Compliant with **ICAO Doc 9303** for biometric passports.
- **Biometric Data Security**:
  - Encrypts biometric data (face, fingerprint, iris) using **AES-256** for confidentiality.
  - Hashes biometric images using **SHA-256** for secure storage.
- **Integrity and Authenticity**:
  - Documents are signed with **RSA (2048 bits)** using **SHA-256** to ensure authenticity and integrity.
- **Reusability**:
  - Common personal information is reused across both documents for efficiency.
- **Digital Wallet Storage**:
  - Documents are stored securely as JSON files in a digital wallet-compatible format.

---

## Standards and Libraries

### **Standards**
1. **W3C Verifiable Credentials**:
   - [W3C VC Data Model](https://www.w3.org/TR/vc-data-model/) for structuring credentials.
2. **ISO/IEC 18013-5**:
   - For mobile driver's licenses.
   - Specifies digital security, privacy, and data encoding for mDLs.
3. **ICAO Doc 9303**:
   - For biometric passports.
   - Defines ePassport data structure and encryption for international travel.

### **Libraries**
- `cryptography`: For RSA key management, AES encryption, and signing.
- `hashlib`: For hashing biometric data with SHA-256.
- `json`: For JSON serialization and storage.
- `datetime`: For timestamps in the credential proof.

---

