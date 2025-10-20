import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from app.models import db

class EncryptionManager:
    @staticmethod
    def generate_key():
        """Generate a random encryption key"""
        return Fernet.generate_key()

    @staticmethod
    def create_fernet(key):
        """Create a Fernet instance with the given key"""
        return Fernet(key)

    @staticmethod
    def encrypt_text(fernet, text):
        """Encrypt text using Fernet"""
        if isinstance(text, str):
            text = text.encode('utf-8')
        return fernet.encrypt(text)

    @staticmethod
    def decrypt_text(fernet, encrypted_data):
        """Decrypt text using Fernet"""
        decrypted = fernet.decrypt(encrypted_data)
        # Try to decode as text, return bytes if it fails
        try:
            return decrypted.decode('utf-8')
        except:
            return decrypted

    @staticmethod
    def encrypt_file(fernet, file_data):
        """Encrypt file data using Fernet"""
        if isinstance(file_data, str):
            file_data = file_data.encode('utf-8')
        return fernet.encrypt(file_data)

    @staticmethod
    def decrypt_file(fernet, encrypted_data):
        """Decrypt file data using Fernet"""
        return fernet.decrypt(encrypted_data)

# Project-specific encryption
class ProjectEncryption:
    @staticmethod
    def setup_project_encryption(project):
        """Set up encryption for a new project"""
        if not project.encryption_key:
            project.encryption_key = base64.urlsafe_b64encode(
                EncryptionManager.generate_key()
            ).decode()

    @staticmethod
    def get_project_fernet(project):
        """Get Fernet instance for a project"""
        key = base64.urlsafe_b64decode(project.encryption_key.encode())
        return EncryptionManager.create_fernet(key)

    @staticmethod
    def encrypt_secret(project, secret_data):
        """Encrypt secret data for a project"""
        fernet = ProjectEncryption.get_project_fernet(project)
        if isinstance(secret_data, str):
            return EncryptionManager.encrypt_text(fernet, secret_data)
        else:
            return EncryptionManager.encrypt_file(fernet, secret_data)

    @staticmethod
    def decrypt_secret(project, encrypted_data):
        """Decrypt secret data for a project"""
        fernet = ProjectEncryption.get_project_fernet(project)
        try:
            # For text secrets, try to return string
            if hasattr(encrypted_data, 'read'):
                # Handle file-like objects
                encrypted_data = encrypted_data.read()
            
            decrypted = EncryptionManager.decrypt_text(fernet, encrypted_data)
            
            # If it's a string, return as is. If bytes, try to decode.
            if isinstance(decrypted, bytes):
                try:
                    return decrypted.decode('utf-8')
                except UnicodeDecodeError:
                    return decrypted
            return decrypted
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
