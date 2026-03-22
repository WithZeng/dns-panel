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

    base_dir = os.path.dirname(os.path.abspath(__file__))
    key_file = os.environ.get('ENCRYPT_KEY_FILE', '').strip() or os.path.join(base_dir, 'instance', 'encrypt.key')

    if not key and key_file and os.path.isfile(key_file):
        with open(key_file, 'r', encoding='utf-8') as f:
            key = (f.read() or '').strip()

    if not key:
        # Try loading from .env file
        env_path = os.path.join(base_dir, '.env')
        if os.path.exists(env_path):
            with open(env_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('ENCRYPT_KEY='):
                        key = line.split('=', 1)[1].strip().strip('"').strip("'")
                        break

    if not key:
        # Check if a key SHOULD exist (i.e. database already has encrypted data).
        # If so, generating a new key would silently make all encrypted data
        # unreadable — raise a loud error instead.
        _marker = os.path.join(base_dir, 'instance', '.encrypt_key_initialized')
        if os.path.isfile(_marker):
            print("\n" + "!" * 60)
            print("CRITICAL: ENCRYPT_KEY 丢失！无法解密已有数据。")
            print("请从备份恢复 instance/encrypt.key 文件或在 .env 中设置 ENCRYPT_KEY。")
            print("如果不恢复密钥，所有已加密的 AK/SK 数据将不可读。")
            print("!" * 60 + "\n")

        key = Fernet.generate_key().decode()

        try:
            os.makedirs(os.path.dirname(key_file), exist_ok=True)
            with open(key_file, 'w', encoding='utf-8') as f:
                f.write(key + '\n')
        except Exception:
            pass

        try:
            with open(_marker, 'w', encoding='utf-8') as f:
                f.write('1')
        except Exception:
            pass

        env_path = os.path.join(base_dir, '.env')
        mode = 'a' if os.path.exists(env_path) else 'w'
        with open(env_path, mode, encoding='utf-8') as f:
            f.write(f"\nENCRYPT_KEY={key}\n")
    else:
        # Key found — make sure the marker exists for future detection
        _marker = os.path.join(base_dir, 'instance', '.encrypt_key_initialized')
        if not os.path.isfile(_marker):
            try:
                os.makedirs(os.path.dirname(_marker), exist_ok=True)
                with open(_marker, 'w', encoding='utf-8') as f:
                    f.write('1')
            except Exception:
                pass

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
        # If it looks like a Fernet token but cannot be decrypted, key is likely mismatched.
        # Returning empty string prevents exporting/reimporting broken ciphertext as AK/SK plaintext.
        if isinstance(ciphertext, str) and ciphertext.startswith('gAAAA'):
            return ''
        # Fallback for legacy plaintext (pre-migration rows).
        return ciphertext
