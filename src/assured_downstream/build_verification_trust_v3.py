from __future__ import annotations

import hmac


TRUSTED_BUILD_VERIFICATION_POLICY_SHA256 = (
    "482715bca2901d3d62dc86d86e5346c7653f720180cec79783da5f05c4f71c76"
)
TRUSTED_BUILD_VERIFIER_SOURCE_SHA256 = (
    "790785a2b5675cfbd59e4498354d96dd2c5616b9f15a3aef307e538b1a7378db"
)
TRUSTED_ARCHIVE_VALIDATOR_SOURCE_SHA256 = (
    "bf86ea2b8cd595cec6260da1276afb21ccb91ad6defd65552cf4ed61e92bb4a0"
)
TRUSTED_BUILD_VERIFIER_MODULE = (
    "src/assured_downstream/build_verification_v3.py"
)
TRUSTED_ARCHIVE_VALIDATOR_MODULE = (
    "src/assured_downstream/archive_validation_v3.py"
)
TRUSTED_BUILD_VERIFIER_IMPORT = "assured_downstream.build_verification_v3"
TRUSTED_ARCHIVE_VALIDATOR_IMPORT = "assured_downstream.archive_validation_v3"


class BuildVerificationTrustError(RuntimeError):
    pass


def require_trusted_build_v3_policy(policy_sha256: str) -> None:
    if not hmac.compare_digest(
        policy_sha256,
        TRUSTED_BUILD_VERIFICATION_POLICY_SHA256,
    ):
        raise BuildVerificationTrustError(
            "Build verification policy is not anchored by the v3 code trust root"
        )


def require_trusted_build_v3_sources(
    *,
    verifier_module: str,
    verifier_source_sha256: str,
    archive_validator_module: str,
    archive_validator_source_sha256: str,
) -> None:
    if (
        verifier_module != TRUSTED_BUILD_VERIFIER_MODULE
        or archive_validator_module != TRUSTED_ARCHIVE_VALIDATOR_MODULE
        or not hmac.compare_digest(
            verifier_source_sha256,
            TRUSTED_BUILD_VERIFIER_SOURCE_SHA256,
        )
        or not hmac.compare_digest(
            archive_validator_source_sha256,
            TRUSTED_ARCHIVE_VALIDATOR_SOURCE_SHA256,
        )
    ):
        raise BuildVerificationTrustError(
            "Portable v3 verifier sources are not anchored by the code trust root"
        )
