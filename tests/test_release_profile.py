from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from assured_downstream.recon import inspect_repository
from assured_downstream.release_profile import plan_release_profile


class ReleaseProfileTests(unittest.TestCase):
    def test_plans_python_release_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text(
                "[project]\nname = 'demo-package'\n",
                encoding="utf-8",
            )
            report = inspect_repository(root)
            profile = plan_release_profile(report)

        self.assertEqual(profile["status"], "draft-human-review-required")
        self.assertEqual(profile["review"]["status"], "human-review-required")
        self.assertFalse(profile["review"]["release_workflow_confirmed"])
        self.assertFalse(profile["review"]["artifact_paths_confirmed"])
        self.assertEqual(profile["project"]["name"], "demo-package")
        self.assertEqual(profile["project"]["language_family"], "python")
        self.assertIn("actions/attest", profile["release"]["required_actions"])
        self.assertIn("dist/*.whl", profile["release"]["artifact_paths"])
        self.assertEqual(profile["release"]["artifact_candidates"], [])
        self.assertEqual(profile["release"]["confirmed_tag_pattern"], "secure-v*")

    def test_plans_go_release_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "go.mod").write_text("module github.com/example/tool\n", encoding="utf-8")
            (root / "main.go").write_text("package main\n", encoding="utf-8")
            report = inspect_repository(root)
            profile = plan_release_profile(report)

        self.assertEqual(profile["project"]["name"], "tool")
        self.assertEqual(profile["project"]["language_family"], "go")
        self.assertIn("go build", "\n".join(profile["release"]["build_commands"]))

    def test_plans_java_release_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>dev.assured</groupId>
                  <artifactId>java-tool</artifactId>
                  <version>0.1.0</version>
                </project>
                """,
                encoding="utf-8",
            )
            (root / "App.java").write_text("class App {}\n", encoding="utf-8")
            report = inspect_repository(root)
            profile = plan_release_profile(report)

        self.assertEqual(profile["project"]["name"], "java-tool")
        self.assertEqual(profile["project"]["language_family"], "java")
        self.assertIn("mvn -B -DskipTests package", profile["release"]["build_commands"])
        self.assertIn("dist/*.jar", profile["release"]["artifact_paths"])

    def test_plans_dotnet_release_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "DotnetTool.csproj").write_text(
                """
                <Project Sdk="Microsoft.NET.Sdk">
                  <PropertyGroup>
                    <TargetFramework>net8.0</TargetFramework>
                    <PackageId>DotnetTool.Package</PackageId>
                  </PropertyGroup>
                </Project>
                """,
                encoding="utf-8",
            )
            (root / "Program.cs").write_text("Console.WriteLine(\"hi\");\n", encoding="utf-8")
            report = inspect_repository(root)
            profile = plan_release_profile(report)

        self.assertEqual(profile["project"]["name"], "DotnetTool.Package")
        self.assertEqual(profile["project"]["language_family"], "dotnet")
        self.assertIn("dotnet restore", profile["release"]["build_commands"])
        self.assertTrue(
            any(command.startswith("dotnet publish DotnetTool.csproj") for command in profile["release"]["build_commands"])
        )
        self.assertIn("dist/**/*", profile["release"]["artifact_paths"])

    def test_carries_recon_artifact_candidates_for_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text(
                "[project]\nname = 'demo-package'\n",
                encoding="utf-8",
            )
            profile = plan_release_profile(
                {
                    "path": str(root),
                    "package_managers": [{"name": "python"}],
                    "languages": {"Python": 1},
                    "artifact_candidates": [
                        {
                            "workflow": ".github/workflows/publish.yml",
                            "job_id": "publish",
                            "step_name": "Upload",
                            "source": "upload-artifact",
                            "artifact_name": "wheel",
                            "paths": ["dist/*.whl"],
                        }
                    ],
                }
            )

        self.assertEqual(profile["release"]["artifact_candidates"][0]["paths"], ["dist/*.whl"])
        self.assertTrue(
            any("artifact candidates" in note for note in profile["review_notes"])
        )


if __name__ == "__main__":
    unittest.main()
