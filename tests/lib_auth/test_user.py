from datetime import datetime

import pytest

from src.lib_auth.jwt import JWTClaim, PayloadClaim
from src.lib_auth.user import build_user_from_claim


class TestBuildUserFromClaim:
    def test_build_user_from_claim_with_verificiation(self):
        claim = JWTClaim(
            exp=datetime.now().timestamp() + 1000,
            iat=1,
            sub="sub",
            iss="iss",
            jti="jti",
            custom_claims=PayloadClaim(
                user_id="user_id",
                role="user_role",
                organization_id="user_organization_id",
                organization_role="user_organization_role",
                impersonator_user_id="impersonator_user_id",
                impersonator_user_role="impersonator_user_role",
                impersonator_organization_id="impersonator_organization_id",
                impersonator_organization_role="impersonator_organization_role",
            ),
        )

        user = build_user_from_claim(claim, with_verification=True)

        assert user.user_id == "user_id"
        assert user.user_role == "user_role"
        assert user.user_organization_id == "user_organization_id"
        assert user.user_organization_role == "user_organization_role"
        assert user.impersonator_user_id == "impersonator_user_id"
        assert user.impersonator_user_role == "impersonator_user_role"
        assert user.impersonator_organization_id == "impersonator_organization_id"
        assert user.impersonator_organization_role == "impersonator_organization_role"

    def test_build_user_from_expired_claim_with_verificiation(self):
        claim = JWTClaim(
            exp=datetime.now().timestamp() - 10000,
            iat=1,
            sub="sub",
            iss="iss",
            jti="jti",
            custom_claims=PayloadClaim(
                user_id="user_id",
                role="user_role",
                organization_id="user_organization_id",
                organization_role="user_organization_role",
                impersonator_user_id="impersonator_user_id",
                impersonator_user_role="impersonator_user_role",
                impersonator_organization_id="impersonator_organization_id",
                impersonator_organization_role="impersonator_organization_role",
            ),
        )

        with pytest.raises(ValueError, match="Invalid claim provided"):
            build_user_from_claim(claim, with_verification=True)

    def test_build_user_from_expired_claim_without_verificiation(self):
        claim = JWTClaim(
            exp=datetime.now().timestamp() - 10000,
            iat=1,
            sub="sub",
            iss="iss",
            jti="jti",
            custom_claims=PayloadClaim(
                user_id="user_id",
                role="user_role",
                organization_id="user_organization_id",
                organization_role="user_organization_role",
                impersonator_user_id="impersonator_user_id",
                impersonator_user_role="impersonator_user_role",
                impersonator_organization_id="impersonator_organization_id",
                impersonator_organization_role="impersonator_organization_role",
            ),
        )

        user = build_user_from_claim(claim, with_verification=False)

        assert user.user_id == "user_id"
        assert user.user_role == "user_role"
        assert user.user_organization_id == "user_organization_id"
        assert user.user_organization_role == "user_organization_role"
        assert user.impersonator_user_id == "impersonator_user_id"
        assert user.impersonator_user_role == "impersonator_user_role"
        assert user.impersonator_organization_id == "impersonator_organization_id"
        assert user.impersonator_organization_role == "impersonator_organization_role"

    def test_build_user_bad_claim_with_verification(self):
        with pytest.raises(ValueError, match="Invalid claim provided"):
            build_user_from_claim(
                JWTClaim(
                    exp=datetime.now().timestamp() - 10,
                    iat=0,
                    sub="sub",
                    iss="iss",
                    jti="jti",
                    custom_claims=None,
                ),
                with_verification=True,
            )

    def test_build_user_bad_claim_without_verification(self):
        user = build_user_from_claim(
            JWTClaim(
                exp=None,
                iat=None,
                sub=None,
                iss=None,
                jti=None,
                custom_claims=PayloadClaim(
                    user_id=None,
                    role=None,
                    organization_id=None,
                    organization_role=None,
                    impersonator_user_id=None,
                    impersonator_user_role=None,
                    impersonator_organization_id=None,
                    impersonator_organization_role=None,
                ),
            ),
            with_verification=False,
        )

        assert user.user_id is None
        assert user.user_role is None
        assert user.user_organization_id is None
        assert user.user_organization_role is None
        assert user.impersonator_user_id is None
        assert user.impersonator_user_role is None
        assert user.impersonator_organization_id is None
        assert user.impersonator_organization_role is None

    def test_build_user_from_null_claim_without_verification(self):
        with pytest.raises(ValueError, match="No claim provided"):
            build_user_from_claim(None, with_verification=False)
