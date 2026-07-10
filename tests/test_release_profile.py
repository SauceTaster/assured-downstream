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

    def test_go_semantic_import_version_uses_project_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "go.mod").write_text(
                "module github.com/securego/gosec/v2\n",
                encoding="utf-8",
            )
            (root / "main.go").write_text("package main\n", encoding="utf-8")
            profile = plan_release_profile(inspect_repository(root))

        self.assertEqual(profile["project"]["name"], "gosec")

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

    def test_dominant_java_project_outranks_go_helper_module(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "build.gradle").write_text("plugins { id 'java' }\n", encoding="utf-8")
            (root / "go.mod").write_text("module example.com/helper\n", encoding="utf-8")
            for index in range(3):
                (root / f"App{index}.java").write_text("class App {}\n", encoding="utf-8")
            (root / "helper.go").write_text("package helper\n", encoding="utf-8")
            profile = plan_release_profile(inspect_repository(root))

        self.assertEqual(profile["project"]["language_family"], "java")
        self.assertTrue(
            any("gradle" in command for command in profile["release"]["build_commands"])
        )

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

    def test_dotnet_project_outranks_incidental_python_helper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SecurityCodeScan.csproj").write_text(
                '<Project Sdk="Microsoft.NET.Sdk"></Project>\n',
                encoding="utf-8",
            )
            (root / "Program.cs").write_text("class Program {}\n", encoding="utf-8")
            (root / "setup.py").write_text("# build helper\n", encoding="utf-8")
            profile = plan_release_profile(inspect_repository(root))

        self.assertEqual(profile["project"]["language_family"], "dotnet")
        self.assertIn("dotnet restore", profile["release"]["build_commands"])

    def test_dotnet_profile_prefers_nested_main_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "security-code-scan"
            main = root / "SecurityCodeScan" / "SecurityCodeScan.csproj"
            test = root / "SecurityCodeScan.Test" / "SecurityCodeScan.Test.csproj"
            main.parent.mkdir(parents=True)
            test.parent.mkdir(parents=True)
            main.write_text(
                """
                <Project Sdk="Microsoft.NET.Sdk">
                  <PropertyGroup>
                    <AssemblyName>SecurityCodeScan.Main</AssemblyName>
                  </PropertyGroup>
                </Project>
                """,
                encoding="utf-8",
            )
            test.write_text('<Project Sdk="Microsoft.NET.Sdk"></Project>\n', encoding="utf-8")
            (root / "LGTM.sln").write_text("\n", encoding="utf-8")
            profile = plan_release_profile(inspect_repository(root))

        self.assertEqual(profile["project"]["name"], "SecurityCodeScan.Main")
        self.assertTrue(
            any(
                "SecurityCodeScan/SecurityCodeScan.csproj" in command
                for command in profile["release"]["build_commands"]
            )
        )

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
