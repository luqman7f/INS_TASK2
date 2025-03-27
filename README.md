# Secure Key Management System

## 1. Overview
Secure key management is crucial for ensuring confidentiality, integrity, and authenticity in cryptographic systems. This project provides a key management system that supports both symmetric and asymmetric encryption. It includes a centralized key distribution system for symmetric keys and a Public Key Infrastructure (PKI) for managing asymmetric keys. The system demonstrates secure key generation, storage, exchange, and revocation while mitigating threats like man-in-the-middle attacks and key compromise.

## 2. Features
- **Symmetric Key Management**: AES key generation, encryption, decryption, and secure storage.
- **Asymmetric Key Management**: RSA key pair generation, encryption, and decryption.
- **Secure Key Exchange**: Implements Diffie-Hellman for establishing shared secrets securely.
- **Key Revocation**: Supports key expiration and revocation mechanisms.
- **Security Measures**: Prevents common cryptographic attacks with authentication and secure storage.

## 3. System Architecture
### Components
- **Centralized Key Distribution System (CKDS)**: Distributes symmetric keys securely.
- **Public Key Infrastructure (PKI)**: Manages RSA keys and digital certificates.
- **Secure Storage**: Ensures encrypted storage of cryptographic keys.
- **Key Exchange Mechanism**: Implements Diffie-Hellman to establish secure connections.
- **Key Revocation & Expiry**: Supports key invalidation and periodic key rotation.

## 4. Code Implementation
The implementation follows structured modules to ensure secure key management:
- **Key Generation**: RSA and AES keys are generated using Python's `cryptography` library.
- **Storage**: Keys are securely stored in encrypted vaults, preventing unauthorized access.
- **Encryption/Decryption**: AES keys encrypt and decrypt data, while RSA keys provide asymmetric security.
- **Key Exchange**: Diffie-Hellman is implemented to establish shared secrets without direct transmission.
- **Revocation**: A key revocation list ensures compromised keys are immediately invalidated.

### Installation and Usage
#### Prerequisites
- Python 3.x
- `cryptography` library

#### Clone the Repository
```sh
git clone https://github.com/your-username/secure-key-management.git
cd secure-key-management
```

#### Install Dependencies
```sh
pip install -r requirements.txt
```

#### Run the System
```sh
python main.py
```

## 5. Security Considerations
- **Man-in-the-Middle Attack Prevention**
  - Digital certificates and PKI ensure authenticity.
  - Mutual TLS (mTLS) secures communications.
  - Ephemeral key exchange for forward secrecy.
- **Key Compromise Mitigation**
  - Secure storage in encrypted vaults.
  - Periodic key rotation to minimize risk.
  - Role-based access control (RBAC) and monitoring.

## 6. Test Results
### Unit Testing
- The system was tested using Python’s `unittest` framework to validate key generation, encryption, and decryption functionalities.
- Results:
  - AES encryption and decryption were successfully tested with various plaintexts.
  - RSA key pair operations performed correctly, ensuring secure data transmission.
  - Diffie-Hellman key exchange established identical shared secrets between parties.
  - Revoked keys were successfully blocked from further usage.

### Performance Testing
- AES encryption time: ~0.002s for 256-bit keys.
- RSA key generation time: ~0.5s for 2048-bit keys.
- Diffie-Hellman shared secret computation: ~0.3s.

### Security Evaluation
- **Mitigation against MITM attacks**: Digital certificates and PKI ensure identity verification.
- **Forward secrecy**: Ephemeral Diffie-Hellman ensures past communications remain secure even if a key is compromised.
- **Storage Security**: All keys are stored using AES-256 encryption to prevent unauthorized access.

## 7. Conclusion
This Secure Key Management System provides a structured approach to handling cryptographic keys efficiently. By integrating centralized key distribution for symmetric encryption and PKI for asymmetric encryption, it ensures secure storage, exchange, and revocation of cryptographic keys. Implementing Diffie-Hellman for secure key exchange and robust revocation mechanisms enhances security against key compromise and man-in-the-middle attacks. Additionally, the inclusion of certificate-based authentication, role-based access control, and secure storage mechanisms further strengthens the security framework. This comprehensive system lays the foundation for secure communications and data protection in modern applications.
