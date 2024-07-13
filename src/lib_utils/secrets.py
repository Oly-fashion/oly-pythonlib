import base64
import hashlib
from typing import Callable

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from pydantic import SecretBytes

ENCRYPTION_VERSION = "encrypted-secret-v1"


def create_string_encryptor(encryption_key: SecretBytes) -> Callable[[str], str]:
    if not encryption_key.get_secret_value():
        raise ValueError("Encryption key is required")

    def encrypt(plaintext: str) -> str:
        version = ENCRYPTION_VERSION
        iv = get_random_bytes(AES.block_size)
        iv_b64 = base64.b64encode(iv).decode("utf-8")

        cipher = AES.new(
            key=encryption_key.get_secret_value(),
            mode=AES.MODE_CBC,
            iv=iv,
        )

        padtext = pad(plaintext.encode("utf-8"), AES.block_size)
        ctext = cipher.encrypt(padtext)
        encodedctext = base64.b64encode(ctext).decode("utf-8")
        return f"{version},{iv_b64},{encodedctext}"

    return encrypt


def create_string_decryptor(encryption_key: SecretBytes) -> Callable[[str], str]:
    def decrypt(ciphertext) -> str:
        if not is_likely_encrypted_string(ciphertext):
            # not encrypted in the oly way, can assume that it is plaintext
            return ciphertext

        version, iv, ctext = ciphertext.split(",")
        iv_decoded = base64.b64decode(iv)

        if version != ENCRYPTION_VERSION:
            raise ValueError("Invalid version")

        if not iv:
            raise ValueError("Invalid IV")

        cipher = AES.new(
            key=encryption_key.get_secret_value(), mode=AES.MODE_CBC, iv=iv_decoded
        )

        decodedctext = base64.b64decode(ctext)
        padded_plaintext = cipher.decrypt(decodedctext)
        plaintext = unpad(padded_plaintext, AES.block_size).decode("utf-8")

        return plaintext

    return decrypt


def is_likely_encrypted_string(value: str) -> bool:
    if not value:
        return False

    secret_tokens = value.split(",")

    if len(secret_tokens) != 3:
        return False

    version, iv, ctext = secret_tokens

    if not version or not iv or not ctext:
        return False

    return value.startswith(f"{ENCRYPTION_VERSION},")


def generate_aes_256_key_from_password(password: str) -> bytes:
    password = password and password.strip()
    if not password:
        raise ValueError("Password is required")

    # We aren't using this key to generate additional keys.
    # So we can use a constant salt.
    salt = b"oly"

    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 100000, dklen=32
    )
