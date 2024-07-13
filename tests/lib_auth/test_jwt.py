import base64
from datetime import datetime
from typing import Tuple

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.lib_auth.jwt import (
    JWTClaim,
    JWTDecodeService,
    JWTException,
    JWTSigningService,
    RSA256JWTDecodeService,
    RSA256JWTSigningService,
    build_jwt_claim,
    create_jwt_token,
    decode_and_verify_jwt_token,
    verify_jwt_claim,
)


class RSAJWTTestCase:
    @staticmethod
    def get_jwt_services() -> Tuple[JWTSigningService, JWTDecodeService]:
        # generate a private key using cryptography
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend(),
        )

        public_key = (
            private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )

        # serialize the private key to PEM format with a password
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"a_password"),
        )

        # generate a JWT signing service
        jwt_signing_service = RSA256JWTSigningService(
            private_key_pem.decode("utf-8"), "a_password"
        )

        jwt_decode_service = RSA256JWTDecodeService(public_key)
        return jwt_signing_service, jwt_decode_service


class TestRSAJWTSigningServiceInitialization:
    def test_init_with_empty_private_key_raises_exception(self):
        with pytest.raises(JWTException):
            RSA256JWTSigningService("", "a_password")

    def test_init_with_none_private_key_raises_exception(self):
        with pytest.raises(JWTException):
            RSA256JWTSigningService(None, "")

    def test_init_with_private_key_without_password_raises_exception(self):
        with pytest.raises(JWTException):
            RSA256JWTSigningService("a_private_key", "")

    def test_init_with_invalid_private_key_with_password(self):
        with pytest.raises(ValueError):
            RSA256JWTSigningService("a_private_key", "a_password")

    def test_init_with_valid_private_key_with_valid_password(self):
        # generate a private key using cryptography
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend(),
        )

        # serialize the private key to PEM format with a password
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"a_password"),
        )

        RSA256JWTSigningService(private_key_pem.decode("utf-8"), "a_password")

    def test_init_with_valid_private_key_with_invalid_password(self):
        # generate a private key using cryptography
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend(),
        )

        # serialize the private key to PEM format with a password
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"a_password"),
        )

        with pytest.raises(ValueError):
            RSA256JWTSigningService(private_key_pem.decode("utf-8"), "wrong_password")


class TestRSAJWTDecodeServiceInitialization:
    def test_init_with_empty_public_key_raises_exception(self):
        with pytest.raises(JWTException):
            RSA256JWTDecodeService("")

    def test_init_with_none_public_key_raises_exception(self):
        with pytest.raises(JWTException):
            RSA256JWTDecodeService(None)

    def test_init_with_a_valid_public_key(self):
        RSA256JWTDecodeService("a_valid_public_key")


class TestRSAJWTSigningService:
    def test_jwt_is_generated_correctly(self):
        # generate a private key using cryptography
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend(),
        )

        # serialize the private key to PEM format with a password
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"a_password"),
        )

        # generate a JWT signing service
        jwt_signing_service = RSA256JWTSigningService(
            private_key_pem.decode("utf-8"), "a_password"
        )
        jwt = jwt_signing_service.generate({"a": "payload"})

        # assert the JWT is generated correctly
        [header, payload, signature] = jwt.split(".")
        assert base64.b64decode(header) == b'{"alg":"RS256","typ":"JWT"}'
        assert base64.b64decode(payload) == b'{"a":"payload"}'
        assert len(signature) == 683


class TestRSAJWTDecodeService(RSAJWTTestCase):
    def test_valid_jwt_is_decoded_correctly(self):
        jwt_signing_service, jwt_decode_service = self.get_jwt_services()
        jwt = jwt_signing_service.generate({"a": "payload"})
        jwt_claim = jwt_decode_service.decode(jwt)
        assert jwt_claim == {"a": "payload"}

    def test_jwt_with_invalid_signature_verification_enable_raises_exception(self):
        jwt_signing_service, jwt_decode_service = self.get_jwt_services()
        jwt = jwt_signing_service.generate({"a": "payload"})

        # get another public key
        _, another_jwt_decode_service = self.get_jwt_services()

        with pytest.raises(JWTException, match="Invalid JWT signature"):
            another_jwt_decode_service.decode(jwt)


class TestJWTClaimBuilder:
    def test_sub_is_set_correctly(self):
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
        )
        assert payload.sub == "a_user_id"

    def test_user_id_is_set_correctly(self):
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
        )
        assert payload.custom_claims.user_id == "a_user_id"

    def test_role_is_set_correctly(self):
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
        )
        assert payload.custom_claims.role == "a_role"

    def test_default_organization_id_is_none(self):
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
        )
        assert payload.custom_claims.organization_id is None

    def test_default_organization_role_is_none(self):
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
        )
        assert payload.custom_claims.organization_role is None

    def test_organization_id_is_set_correctly(self):
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
            organization_id="an_organization_id",
        )
        assert payload.custom_claims.organization_id == "an_organization_id"

    def test_organization_role_is_set_correctly(self):
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
            organization_role="an_organization_role",
        )
        assert payload.custom_claims.organization_role == "an_organization_role"

    def test_issuer_is_set_correctly(self):
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
        )
        assert payload.iss == "an_issuer"

    def test_default_expiration_is_set_correctly(self):
        timestamp = datetime.now().timestamp()
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
        )

        # check that the expiration is within 10 seconds of the expected value
        assert payload.exp - (timestamp + 3600) <= 10

    def test_issue_time_is_set_correctly(self):
        timestamp = datetime.now().timestamp()
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
        )

        # check that the issue time is within 10 seconds of the expected value
        assert payload.iat - timestamp <= 10

    def test_jti_is_128_hex_digits(self):
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
        )
        assert len(payload.jti) == 128

    def test_default_impersonator_id_is_none(self):
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
        )
        assert payload.custom_claims.impersonator_user_id is None

    def test_default_impersonator_role_is_none(self):
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
        )
        assert payload.custom_claims.impersonator_user_role is None

    def test_default_impersonator_organization_id_is_none(self):
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
        )
        assert payload.custom_claims.impersonator_organization_id is None

    def test_default_impersonator_organization_role_is_none(self):
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
        )
        assert payload.custom_claims.impersonator_organization_role is None

    def test_impersonator_id_is_set_correctly(self):
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
            impersonator_user_id="an_impersonator_user_id",
        )
        assert payload.custom_claims.impersonator_user_id == "an_impersonator_user_id"

    def test_impersonator_role_is_set_correctly(self):
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
            impersonator_user_role="an_impersonator_user_role",
        )
        assert (
            payload.custom_claims.impersonator_user_role == "an_impersonator_user_role"
        )

    def test_default_impersonator_organization_id_is_set_correctly(self):
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
            impersonator_organization_id="an_impersonator_organization_id",
        )
        assert (
            payload.custom_claims.impersonator_organization_id
            == "an_impersonator_organization_id"
        )

    def test_default_impersonator_organization_role_is_set_correctly(self):
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
            impersonator_organization_role="an_impersonator_organization_role",
        )
        assert (
            payload.custom_claims.impersonator_organization_role
            == "an_impersonator_organization_role"
        )

    def test_expiration_is_set_correctly(self):
        timestamp = datetime.now().timestamp()
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
            expire_in_seconds=100,
        )

        # check that the expiration is within 10 seconds of the expected value
        assert payload.exp - (timestamp + 100) <= 10

    def test_dict_is_correctly_serialized(self):
        payload = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
            organization_id="an_organization_id",
            organization_role="an_organization_role",
            expire_in_seconds=100,
            impersonator_user_id="an_impersonator_user_id",
            impersonator_user_role="an_impersonator_user_role",
            impersonator_organization_id="an_impersonator_organization_id",
            impersonator_organization_role="an_impersonator_organization_role",
        )
        assert payload.as_dict() == {
            "sub": payload.sub,
            "exp": payload.exp,
            "iat": payload.iat,
            "iss": payload.iss,
            "jti": payload.jti,
            "custom_claims": {
                "user_id": payload.custom_claims.user_id,
                "role": payload.custom_claims.role,
                "organization_id": payload.custom_claims.organization_id,
                "organization_role": payload.custom_claims.organization_role,
                "impersonator_user_id": payload.custom_claims.impersonator_user_id,
                "impersonator_user_role": payload.custom_claims.impersonator_user_role,
                "impersonator_organization_id": payload.custom_claims.impersonator_organization_id,
                "impersonator_organization_role": payload.custom_claims.impersonator_organization_role,
            },
        }


class TestJWTTokenCreationAndDecoding(RSAJWTTestCase):
    def test_jwt_token_is_correctly_generated_and_decoded(self):
        jwt_signing_service, jwt_decode_service = self.get_jwt_services()
        claim: JWTClaim = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
        )
        token = create_jwt_token(
            payload=claim,
            signing_service=jwt_signing_service,
        )
        assert decode_and_verify_jwt_token(token, jwt_decode_service) == claim

    def test_expired_jwt_token_raises_exception(self):
        jwt_signing_service, jwt_decode_service = self.get_jwt_services()
        claim: JWTClaim = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
            expire_in_seconds=-100,
        )
        token = create_jwt_token(
            payload=claim,
            signing_service=jwt_signing_service,
        )
        with pytest.raises(JWTException, match="JWT expired"):
            decode_and_verify_jwt_token(token, jwt_decode_service)

    def test_decode_token_verifies_claim_by_raising_exception_on_empty_user(self):
        jwt_signing_service, jwt_decode_service = self.get_jwt_services()
        claim: JWTClaim = build_jwt_claim(
            user_id="",
            role="a_role",
            issuer="an_issuer",
        )
        token = create_jwt_token(
            payload=claim,
            signing_service=jwt_signing_service,
        )
        with pytest.raises(JWTException, match="JWT claim verification failed"):
            decode_and_verify_jwt_token(token, jwt_decode_service)


class TestJWTClaimVerification:
    def test_valid_claim_returns_true(self):
        claim: JWTClaim = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
        )
        assert verify_jwt_claim(claim) is True

    def test_valid_claim_with_organization_returns_true(self):
        claim: JWTClaim = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
            organization_id="an_organization_id",
            organization_role="an_organization_role",
        )
        assert verify_jwt_claim(claim) is True

    def test_valid_claim_with_impersonator_returns_true(self):
        claim: JWTClaim = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
            impersonator_user_id="an_impersonator_user_id",
            impersonator_user_role="an_impersonator_user_role",
            impersonator_organization_id="an_impersonator_organization_id",
            impersonator_organization_role="an_impersonator_organization_role",
        )
        assert verify_jwt_claim(claim) is True

    def test_expired_claim_returns_false(self):
        claim: JWTClaim = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
            expire_in_seconds=-100,
        )
        assert verify_jwt_claim(claim) is False

    def test_claim_without_sub_returns_false(self):
        claim: JWTClaim = build_jwt_claim(
            user_id="",
            role="a_role",
            issuer="an_issuer",
        )
        assert verify_jwt_claim(claim) is False

    def test_claim_without_exp_returns_false(self):
        claim: JWTClaim = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
        )
        claim.exp = None
        assert verify_jwt_claim(claim) is False

    def test_claim_without_iat_returns_false(self):
        claim: JWTClaim = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
        )
        claim.iat = None
        assert verify_jwt_claim(claim) is False

    def test_claim_without_iss_returns_false(self):
        claim: JWTClaim = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="",
        )
        assert verify_jwt_claim(claim) is False

    def test_claim_without_jti_returns_false(self):
        claim: JWTClaim = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
        )
        claim.jti = None
        assert verify_jwt_claim(claim) is False

    def test_claim_without_custom_claims_returns_false(self):
        claim: JWTClaim = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
        )
        claim.custom_claims = None
        assert verify_jwt_claim(claim) is False

    def test_claim_without_user_id_in_custom_claims_returns_false(self):
        claim: JWTClaim = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
        )
        claim.custom_claims.user_id = None
        assert verify_jwt_claim(claim) is False

    def test_claim_without_user_role_in_custom_claims_returns_false(self):
        claim: JWTClaim = build_jwt_claim(
            user_id="a_user_id",
            role="",
            issuer="an_issuer",
        )
        assert verify_jwt_claim(claim) is False

    def test_claim_with_only_organization_id_returns_false(
        self,
    ):
        claim: JWTClaim = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
            organization_id="an_organization_id",
        )
        assert verify_jwt_claim(claim) is False

    def test_claim_with_only_organization_role_returns_false(
        self,
    ):
        claim: JWTClaim = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
            organization_role="an_organization_role",
        )
        assert verify_jwt_claim(claim) is False

    def test_claim_with_only_impersonator_user_id_returns_false(
        self,
    ):
        claim: JWTClaim = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
            impersonator_user_id="an_impersonator_user_id",
        )
        assert verify_jwt_claim(claim) is False

    def test_claim_with_only_impersonator_user_role_returns_false(
        self,
    ):
        claim: JWTClaim = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
            impersonator_user_role="an_impersonator_user_role",
        )
        assert verify_jwt_claim(claim) is False

    def test_claim_with_only_impersonator_organization_id_returns_false(
        self,
    ):
        claim: JWTClaim = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
            impersonator_organization_id="an_impersonator_organization_id",
        )
        assert verify_jwt_claim(claim) is False

    def test_claim_with_only_impersonator_organization_role_returns_false(
        self,
    ):
        claim: JWTClaim = build_jwt_claim(
            user_id="a_user_id",
            role="a_role",
            issuer="an_issuer",
            impersonator_organization_role="an_impersonator_organization_role",
        )
        assert verify_jwt_claim(claim) is False
