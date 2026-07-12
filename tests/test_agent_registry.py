from __future__ import annotations

import unittest

from assured_downstream.agent_registry import load_agent_registry, summarize_agent_registry


class AgentRegistryTests(unittest.TestCase):
    def test_loads_agent_registry_with_required_agents(self) -> None:
        registry = load_agent_registry()
        summary = summarize_agent_registry(registry)

        self.assertEqual(registry["schema_version"], 1)
        self.assertEqual(summary["agent_count"], 19)
        self.assertEqual(summary["agent_count"], summary["required_agent_count"])
        agent_ids = {agent["id"] for agent in registry["agents"]}
        self.assertIn("source-discovery", agent_ids)
        self.assertIn("fork-publisher", agent_ids)
        self.assertIn("publication-requestor", agent_ids)
        self.assertIn("publication-authorizer", agent_ids)
        self.assertIn("secure-branch-publisher", agent_ids)
        self.assertIn("governor", agent_ids)
        self.assertIn("watch", agent_ids)
        self.assertGreater(summary["handoff_invariants"], 0)

    def test_agents_declare_tools_and_human_gates(self) -> None:
        registry = load_agent_registry()

        for agent in registry["agents"]:
            with self.subTest(agent=agent["id"]):
                self.assertTrue(agent["tools"])
                self.assertIn("human_gates", agent)
                self.assertIsInstance(agent["human_gates"], list)


if __name__ == "__main__":
    unittest.main()
