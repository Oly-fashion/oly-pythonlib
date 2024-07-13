import os

import pytest

from src.lib_auth.password import (
    InvalidPasswordException,
    InvalidPasswordHashException,
    format_hashed_password,
    hash_password,
    verify_password,
)


def test_format_hashed_password():
    algorithm = "scrypt"
    salt = os.urandom(32)
    hashed_password = os.urandom(32)

    hashed_password_hex = hashed_password.hex()
    salt_hex = salt.hex()

    expected = f"{algorithm}/{salt_hex}/{hashed_password_hex}"
    actual = format_hashed_password(algorithm, salt, hashed_password)

    assert expected == actual


def test_has_password_raises_invalid_password_exception_when_password_is_none():
    with pytest.raises(InvalidPasswordException):
        hash_password(None)


def test_verify_password_raises_invalid_password_exception_when_password_is_none():
    with pytest.raises(InvalidPasswordException):
        verify_password(None, "hashed_password")


def test_verify_password_raises_invalid_password_hash_exception_when_hashed_password_is_none():
    with pytest.raises(InvalidPasswordHashException):
        verify_password("password", None)


def test_hash_password_returns_correct_hashed_password():
    password = "password"
    hashed_password = hash_password("password")

    assert password != hashed_password
    assert password not in hashed_password
    assert verify_password(password, hashed_password) is True


def test_incorrect_password_raises_invalid_password_exception():
    password_to_check = "password"
    hashed_password = hash_password("another_password")
    with pytest.raises(InvalidPasswordException):
        verify_password(password_to_check, hashed_password)


def test_incorrect_hashed_password_raises_invalid_password_hash_exception():
    password_to_check = "password"
    hashed_password = "incorrect/hashed/password"
    with pytest.raises(InvalidPasswordHashException):
        verify_password(password_to_check, hashed_password)


def test_unsupported_algorithm_raises_invalid_password_hash_exception():
    password = "password"
    hashed_password = hash_password(password)
    invalid_hashed_password = hashed_password.replace("scrypt", "unsupported")
    with pytest.raises(InvalidPasswordHashException):
        verify_password(password, invalid_hashed_password)


def test_incorrect_salt_length_raises_invalid_password_hash_exception():
    password = "password"
    hashed_password = hash_password(password)
    invalid_hashed_password = hashed_password.replace(
        hashed_password.split("/")[1], os.urandom(16).hex()
    )
    with pytest.raises(InvalidPasswordHashException):
        verify_password(password, invalid_hashed_password)


def test_incorrect_password_hash_length_raises_invalid_password_hash_exception():
    password = "password"
    hashed_password = hash_password(password)
    invalid_hashed_password = hashed_password.replace(
        hashed_password.split("/")[2], os.urandom(32).hex()
    )
    with pytest.raises(InvalidPasswordHashException):
        verify_password(password, invalid_hashed_password)


def test_incorrect_salt_raises_invalid_password_exception():
    password = "password"
    hashed_password = hash_password(password)
    invalid_hashed_password = hashed_password.replace(
        hashed_password.split("/")[1], os.urandom(32).hex()
    )
    with pytest.raises(InvalidPasswordException):
        verify_password(password, invalid_hashed_password)
