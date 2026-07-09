from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from assured_downstream.lifecycle import StateStore


class LifecycleTests(unittest.TestCase):
    def test_state_store_round_trip(self) -> None:
        state = StateStore.empty()
        state.record(
            source_full_name="owner/project",
            target_full_name="org/project",
            event="ForkPlanned",
            status="ok",
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            state.save(path)
            loaded = StateStore.load(path)

        self.assertEqual(
            loaded.data["repositories"]["owner/project"]["target_full_name"],
            "org/project",
        )


if __name__ == "__main__":
    unittest.main()

