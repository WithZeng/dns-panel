"""
AK/SK encryption utility using Fernet symmetric encryption.
Key is loaded from ENCRYPT_KEY environment variable or auto-generated into .env.
"""
import os
import base64
from cryptography.fernet import Fernet

_fernet = None


def _get_fernet():
    global _fernet
    if _fernet is not None:
        return _fernet

    key = os.environ.get('ENCRYPT_KEY')

    if not key:
        # Try loading from .env file
        env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('ENCRYPT_KEY='):
                        key = line.split('=', 1)[1].strip().strip('"').strip("'")
                        break

    if not key:
        # Auto-generate key and write to .env
        key = Fernet.generate_key().decode()
        env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
        mode = 'a' if os.path.exists(env_path) else 'w'
        with open(env_path, mode) as f:
            f.write(f"\nENCRYPT_KEY={key}\n")

    # Ensure key is valid base64
    if isinstance(key, str):
        key = key.encode()

    _fernet = Fernet(key)
    return _fernet


def encrypt(plaintext: str) -> str:
    """Encrypt a plaintext string, return base64-encoded ciphertext."""
    if not plaintext:
        return ''
    f = _get_fernet()
    return f.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt a ciphertext string back to plaintext."""
    if not ciphertext:
        return ''
    f = _get_fernet()
    try:
        return f.decrypt(ciphertext.encode()).decode()
    except Exception:
        # Fallback: might be stored as plaintext (pre-migration)
        return ciphertext
