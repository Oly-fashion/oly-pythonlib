import base64

import pytest
from Crypto.Cipher import AES
from pydantic import SecretBytes

from src.lib_utils.secrets import (
    create_string_decryptor,
    create_string_encryptor,
    generate_aes_256_key_from_password,
    is_likely_encrypted_string,
)


class TestGenerateAESKeyFromPassword:
    def test_generate_with_good_password(self):
        assert len(generate_aes_256_key_from_password("password")) == 32  # bytes

    def test_generate_with_empty_password_raises_exception(self):
        with pytest.raises(ValueError, match="Password is required"):
            generate_aes_256_key_from_password("")


class TestCreateStringEncryptor:
    def test_encrypt_with_empty_key_raises_exception(self):
        with pytest.raises(ValueError, match="Encryption key is required"):
            create_string_encryptor(SecretBytes(b""))

    def test_encrypted_value_does_not_match_the_plaintext(self):
        secret_bytes = SecretBytes(generate_aes_256_key_from_password("password"))
        encryptor = create_string_encryptor(secret_bytes)
        encrypted = encryptor("plaintext")

        assert encrypted != "plaintext" and "plaintext" not in encrypted

    def test_encrypted_value_is_of_correct_format(self):
        secret_bytes = SecretBytes(generate_aes_256_key_from_password("password"))
        encryptor = create_string_encryptor(secret_bytes)
        encrypted = encryptor("plaintext")

        version, iv, ctext = encrypted.split(",")

        assert version == "encrypted-secret-v1"
        assert len(base64.b64decode(iv)) == AES.block_size
        assert len(base64.b64decode(ctext)) % AES.block_size == 0


class TestCreateStringDecryptor:
    def test_encrypted_string_is_correctly_decrypted(self):
        secret_bytes = SecretBytes(generate_aes_256_key_from_password("password"))
        encryptor = create_string_encryptor(secret_bytes)
        decryptor = create_string_decryptor(secret_bytes)
        encrypted = encryptor("plaintext")

        assert decryptor(encrypted) == "plaintext"

    def test_decrypt_non_encrypted_string(self):
        secret_bytes = SecretBytes(generate_aes_256_key_from_password("password"))
        decryptor = create_string_decryptor(secret_bytes)

        assert decryptor("plaintext") == "plaintext"


class TestIsLikelyEncrypted:
    def test_for_encrypted_string(self):
        secret_bytes = SecretBytes(generate_aes_256_key_from_password("password"))
        encryptor = create_string_encryptor(secret_bytes)
        encrypted = encryptor("plaintext")

        assert is_likely_encrypted_string(encrypted)

    def test_for_invalid_string(self):
        assert not is_likely_encrypted_string("plaintext")

    def test_for_null(self):
        assert not is_likely_encrypted_string(None)  # type: ignore
