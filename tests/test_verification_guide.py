from __future__ import annotations

import unittest

from assured_downstream.verification_guide import create_verification_guide


class VerificationGuideTests(unittest.TestCase):
    def test_creates_verification_guide(self) -> None:
        guide = create_verification_guide(
            {
                "project": {
                    "source_full_name": "owner/project",
                    "target_full_name": "assured-oss/project",
                    "upstream_ref": "abc123",
                    "overlay_ref": "def456",
                    "release_tag": "secure-v1.0.0+org.1",
                    "assurance": "Attested",
                },
                "evidence": {
                    "artifacts": [
                        {
                            "path": "/tmp/tool",
                            "sha256": "0" * 64,
                        }
                    ],
                    "sboms": [],
                    "attestations": [],
                    "traces": [],
                    "reports": [],
                },
            }
        )

        self.assertIn("gh attestation verify /tmp/tool -R assured-oss/project", guide)
        self.assertIn("shasum -a 256 -c -", guide)
        self.assertIn("saucetotal verify-evidence", guide)


if __name__ == "__main__":
    unittest.main()
