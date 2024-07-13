from typing import Annotated, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from src.lib_auth.jwt import (
    JWTClaim,
    JWTDecodeService,
    JWTSigningService,
    RSA256JWTDecodeService,
    RSA256JWTSigningService,
    build_jwt_claim,
    create_jwt_token,
)
from src.lib_fastapi.auth import build_claim_authenticator


class TestGetVerifiedClaim:
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

    def test_valid_claim_via_cookie(self):
        jwt_signing_service, jwt_decode_service = self.get_jwt_services()
        jwt = create_jwt_token(
            build_jwt_claim(
                user_id="a_user_id",
                role="a_role",
                issuer="an_issuer",
            ),
            jwt_signing_service,
        )

        mock_app = FastAPI()

        @mock_app.get("/test")
        def mock_verify_jwt_token(
            jwt_claim: Annotated[
                JWTClaim, Depends(build_claim_authenticator(jwt_decode_service))
            ]
        ) -> JWTClaim:
            return jwt_claim

        client = TestClient(mock_app)
        response = client.get("/test", cookies={"jwt_access_token": jwt})
        result_claim = response.json()

        assert response.status_code == 200
        assert result_claim["custom_claims"]["user_id"] == "a_user_id"
        assert result_claim["custom_claims"]["role"] == "a_role"

    def test_valid_claim_via_header(self):
        jwt_signing_service, jwt_decode_service = self.get_jwt_services()
        jwt = create_jwt_token(
            build_jwt_claim(
                user_id="a_user_id",
                role="a_role",
                issuer="an_issuer",
            ),
            jwt_signing_service,
        )

        mock_app = FastAPI()

        @mock_app.get("/test")
        def mock_verify_jwt_token(
            jwt_claim: Annotated[
                JWTClaim, Depends(build_claim_authenticator(jwt_decode_service))
            ]
        ) -> JWTClaim:
            return jwt_claim

        client = TestClient(mock_app)
        response = client.get("/test", headers={"X-Oly-Authorization": f"Bearer {jwt}"})
        result_claim = response.json()

        assert response.status_code == 200
        assert result_claim["custom_claims"]["user_id"] == "a_user_id"
        assert result_claim["custom_claims"]["role"] == "a_role"

    def test_invalid_claim(self):
        jwt_signing_service, _ = self.get_jwt_services()
        _, other_jwt_decode_service = self.get_jwt_services()

        jwt = create_jwt_token(
            build_jwt_claim(
                user_id="a_user_id",
                role="a_role",
                issuer="an_issuer",
            ),
            jwt_signing_service,
        )

        mock_app = FastAPI()

        @mock_app.get("/test")
        def mock_verify_jwt_token(
            jwt_claim: Annotated[
                JWTClaim, Depends(build_claim_authenticator(other_jwt_decode_service))
            ]
        ) -> JWTClaim:
            return jwt_claim

        client = TestClient(mock_app)
        response = client.get("/test", headers={"Authorization": f"Bearer {jwt}"})

        assert response.status_code == 401
