from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

class KeyManager:
    def __init__(self):
        self.symmetric_keys = {}  
        self.asymmetric_keys = {}  

    def generate_aes_key(self, key_id: str):
        """Creates a 256-bit AES key."""
        key = os.urandom(32)  # AES-256
        self.symmetric_keys[key_id] = key
        return base64.b64encode(key).decode()

    def encrypt_aes(self, key_id: str, plaintext: str):
        """Encrypts data using AES-GCM mode."""
        if key_id not in self.symmetric_keys:
            return None
        key = self.symmetric_keys[key_id]
        iv = os.urandom(12)  
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return base64.b64encode(iv + encryptor.tag + ciphertext).decode()

    def decrypt_aes(self, key_id: str, encrypted_text: str):
        """Decrypts AES-GCM encrypted data."""
        if key_id not in self.symmetric_keys:
            return None
        key = self.symmetric_keys[key_id]
        encrypted_data = base64.b64decode(encrypted_text)
        iv, tag, ciphertext = encrypted_data[:12], encrypted_data[12:28], encrypted_data[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def generate_rsa_keys(self, user_id: str):
        """Creates an RSA key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        self.asymmetric_keys[user_id] = (private_key, public_key)
        return public_key

    def encrypt_rsa(self, user_id: str, plaintext: str):
        """Encrypts data using RSA-OAEP."""
        if user_id not in self.asymmetric_keys:
            return None
        _, public_key = self.asymmetric_keys[user_id]
        ciphertext = public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode()

    def decrypt_rsa(self, user_id: str, encrypted_text: str):
        """Decrypts RSA-OAEP encrypted data."""
        if user_id not in self.asymmetric_keys:
            return None
        private_key, _ = self.asymmetric_keys[user_id]
        ciphertext = base64.b64decode(encrypted_text)
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()

    def revoke_key(self, key_id: str):
        """Removes a stored key."""
        if key_id in self.symmetric_keys:
            del self.symmetric_keys[key_id]
            return "AES key revoked."
        elif key_id in self.asymmetric_keys:
            del self.asymmetric_keys[key_id]
            return "RSA key revoked."
        return "Key not found."


if __name__ == "__main__":
    manager = KeyManager()

    aes_key_id = "session123"
    print("Generated AES Key:", manager.generate_aes_key(aes_key_id))
    encrypted_aes = manager.encrypt_aes(aes_key_id, "Hello Secure World")
    print("AES Encrypted:", encrypted_aes)
    print("AES Decrypted:", manager.decrypt_aes(aes_key_id, encrypted_aes))


    rsa_user_id = "user456"
    print("Generated RSA Key Pair")
    manager.generate_rsa_keys(rsa_user_id)
    encrypted_rsa = manager.encrypt_rsa(rsa_user_id, "Confidential Data")
    print("RSA Encrypted:", encrypted_rsa)
    print("RSA Decrypted:", manager.decrypt_rsa(rsa_user_id, encrypted_rsa))

    print(manager.revoke_key(aes_key_id))
