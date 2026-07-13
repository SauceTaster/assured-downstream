from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from assured_downstream.ecosystem_profile import (
    ecosystem_profiler_sha256,
    load_ecosystem_policy,
    plan_ecosystem_build_profile,
)
from assured_downstream.cli import build_parser


SOURCE_COMMIT = "a" * 40


class EcosystemProfileTests(unittest.TestCase):
    def test_fixed_timestamp_profile_replay_is_deterministic(self) -> None:
        arguments = {
            "root": Path("tests/fixtures/recon/java"),
            "source_repository": "fixture/java-tool",
            "source_commit": SOURCE_COMMIT,
            "source_git_tree": "b" * 40,
            "generated_at": "2026-07-13T18:52:36Z",
            "include_analysis_path": False,
        }

        first = plan_ecosystem_build_profile(**arguments)
        second = plan_ecosystem_build_profile(**arguments)

        self.assertEqual(first, second)
        self.assertEqual(first["generated_at"], arguments["generated_at"])

    def test_descriptor_relative_profile_ignores_substituted_pathname(self) -> None:
        if not hasattr(os, "fchdir") or not hasattr(os, "O_DIRECTORY"):
            self.skipTest("descriptor-rooted profiling is unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            analysis = root / "analysis"
            analysis.mkdir()
            (analysis / "pom.xml").write_text(
                """
                <project><modelVersion>4.0.0</modelVersion>
                  <groupId>dev.assured</groupId><artifactId>trusted</artifactId>
                  <version>1.0</version>
                </project>
                """,
                encoding="utf-8",
            )
            analysis_descriptor = os.open(
                analysis,
                os.O_RDONLY | os.O_DIRECTORY,
            )
            previous_directory = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fchdir(analysis_descriptor)
                held = root / "held"
                moved = root / "moved"
                analysis.rename(held)
                held.rename(moved)
                held.mkdir()
                (held / "pom.xml").write_text(
                    """
                    <project><modelVersion>4.0.0</modelVersion>
                      <groupId>dev.hostile</groupId><artifactId>substituted</artifactId>
                      <version>9.9</version>
                    </project>
                    """,
                    encoding="utf-8",
                )
                profile = plan_ecosystem_build_profile(
                    root=Path("."),
                    source_repository="fixture/descriptor-root",
                    source_commit=SOURCE_COMMIT,
                    source_git_tree="b" * 40,
                    include_analysis_path=False,
                    descriptor_relative=True,
                    source_identity_verified=True,
                    generated_at="2026-07-13T18:52:36Z",
                )
            finally:
                os.fchdir(previous_directory)
                os.close(previous_directory)
                os.close(analysis_descriptor)

        self.assertEqual(
            profile["signals"]["declared_primary_artifact"],
            "trusted-1.0.jar",
        )
        self.assertNotIn("substituted", json.dumps(profile))

    def test_retained_live_profiles_match_validation_index(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        validation = json.loads(
            (
                repository_root
                / "case-studies/001-pilot-cohort/ecosystem-profile-validation.json"
            ).read_text(encoding="utf-8")
        )

        self.assertEqual(
            validation["status"],
            "structural-profiles-blocked-as-designed",
        )
        self.assertFalse(validation["execution_permitted"])
        self.assertEqual(
            validation["replay"]["byte_identical_real_case_replay_evidence"],
            "not-retained-no-claim",
        )
        self.assertEqual(
            ecosystem_profiler_sha256(),
            validation["profiler"]["implementation_sha256"],
        )
        for policy in validation["policies"]:
            path = repository_root / policy["path"]
            self.assertEqual(
                hashlib.sha256(path.read_bytes()).hexdigest(),
                policy["sha256"],
            )
            self.assertFalse(policy["canary_profile_approved"])
        for case in validation["cases"]:
            path = repository_root / case["profile_path"]
            self.assertEqual(
                hashlib.sha256(path.read_bytes()).hexdigest(),
                case["profile_sha256"],
            )
            profile = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(profile["profiler"], validation["profiler"])
            self.assertEqual(profile["source"]["repository"], case["source_repository"])
            self.assertEqual(profile["source"]["commit"], case["source_commit"])
            self.assertEqual(profile["source"]["git_tree"], case["source_git_tree"])
            self.assertEqual(
                profile["generated_at"],
                validation["replay"]["profile_generated_at"],
            )
            self.assertEqual(
                profile["source"]["inventory"]["tree_sha256"],
                case["source_inventory_sha256"],
            )
            self.assertFalse(profile["execution_permitted"])
            self.assertFalse(profile["canary_admission_candidate"])
            self.assertEqual(profile["decision"]["blockers"], case["blockers"])
            self.assertEqual(
                case["canonical_git_url"],
                f"https://github.com/{case['source_repository']}.git",
            )

    def test_java_maven_profile_is_offline_and_fail_closed(self) -> None:
        profile = plan_ecosystem_build_profile(
            root=Path("tests/fixtures/recon/java"),
            source_repository="fixture/java-tool",
            source_commit=SOURCE_COMMIT,
        )

        self.assertEqual(profile["profile_id"], "java-maven-v1")
        self.assertEqual(profile["ecosystem"], "java")
        self.assertEqual(profile["status"], "blocked")
        self.assertFalse(profile["execution_permitted"])
        self.assertEqual(profile["build_plan"]["network"], "none")
        self.assertFalse(profile["build_plan"]["shell"])
        argv = profile["build_plan"]["steps"][0]["argv"]
        self.assertIn("--offline", argv)
        self.assertIn("--strict-checksums", argv)
        self.assertEqual(argv[-1], "package")
        self.assertIn("--settings", argv)
        self.assertIn("--global-settings", argv)
        self.assertIn("-DperformRelease=false", argv)
        self.assertIn("-Dmaven.repo.local=/workspace/m2", argv)
        self.assertNotIn("deploy", argv)
        self.assertNotIn("-DskipTests", argv)
        self.assertIn(
            "DEPENDENCY_MATERIAL_LOCK_MISSING",
            profile["decision"]["blockers"],
        )
        self.assertIn(
            "BUILDER_IMAGE_NOT_DIGEST_PINNED",
            profile["decision"]["blockers"],
        )
        self.assertIn(
            "SOURCE_IDENTITY_HANDOFF_UNVERIFIED",
            profile["decision"]["blockers"],
        )

    def test_maven_profile_records_release_hooks_without_enabling_them(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>dev.assured</groupId>
                  <artifactId>demo</artifactId>
                  <version>1.0-SNAPSHOT</version>
                  <distributionManagement>
                    <repository><url>https://example.invalid/releases</url></repository>
                  </distributionManagement>
                  <build><plugins><plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-gpg-plugin</artifactId><version>3.2.7</version>
                  </plugin></plugins></build>
                </project>
                """,
                encoding="utf-8",
            )

            profile = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/maven-hooks",
                source_commit=SOURCE_COMMIT,
            )

        review_codes = profile["decision"]["review_items"]
        self.assertIn("UPSTREAM_MAVEN_PUBLICATION_CONFIG_PRESENT", review_codes)
        self.assertIn("MAVEN_RELEASE_OR_EXTENSION_PLUGINS_PRESENT", review_codes)
        all_argv = json.dumps(profile["build_plan"]["steps"])
        self.assertNotIn("deploy", all_argv)
        self.assertNotIn("gpg", all_argv)

    def test_maven_multimodule_and_plaintext_repository_are_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>dev.assured</groupId><artifactId>reactor</artifactId>
                  <version>1.0.0</version><packaging>pom</packaging>
                  <modules><module>app</module></modules>
                  <repositories><repository>
                    <url>http://repo.example.invalid/maven</url>
                  </repository></repositories>
                </project>
                """,
                encoding="utf-8",
            )
            profile = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/reactor",
                source_commit=SOURCE_COMMIT,
            )

        blockers = profile["decision"]["blockers"]
        self.assertIn("MAVEN_MULTI_MODULE_SELECTION_REQUIRED", blockers)
        self.assertIn("MAVEN_INSECURE_REPOSITORY", blockers)

    def test_maven_plaintext_repository_scheme_is_case_insensitive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """
                <project><modelVersion>4.0.0</modelVersion>
                  <groupId>dev.assured</groupId><artifactId>demo</artifactId>
                  <version>1.0.0</version><repositories><repository>
                    <url>HTTP://repo.example.invalid/maven</url>
                  </repository></repositories>
                </project>
                """,
                encoding="utf-8",
            )
            profile = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/plaintext",
                source_commit=SOURCE_COMMIT,
            )

        self.assertIn("MAVEN_INSECURE_REPOSITORY", profile["decision"]["blockers"])

    def test_maven_pom_packaging_has_no_primary_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """
                <project><modelVersion>4.0.0</modelVersion>
                  <groupId>dev.assured</groupId><artifactId>parent</artifactId>
                  <version>1.0.0</version><packaging>pom</packaging>
                </project>
                """,
                encoding="utf-8",
            )
            profile = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/parent",
                source_commit=SOURCE_COMMIT,
            )

        self.assertIn(
            "MAVEN_PRIMARY_ARTIFACT_UNAVAILABLE",
            profile["decision"]["blockers"],
        )

    def test_maven_literal_final_name_selects_exact_primary_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """
                <project><modelVersion>4.0.0</modelVersion>
                  <groupId>dev.assured</groupId><artifactId>demo</artifactId>
                  <version>1.0.0</version>
                  <build><finalName>secure-demo</finalName></build>
                </project>
                """,
                encoding="utf-8",
            )
            profile = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/final-name",
                source_commit=SOURCE_COMMIT,
            )

        self.assertEqual(profile["signals"]["final_name"], "secure-demo")
        self.assertEqual(
            profile["build_plan"]["artifact_selection"]["include"],
            ["secure-demo.jar"],
        )

    def test_maven_custom_build_directory_blocks_artifact_collection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """
                <project><modelVersion>4.0.0</modelVersion>
                  <groupId>dev.assured</groupId><artifactId>demo</artifactId>
                  <version>1.0.0</version>
                  <build><directory>out</directory></build>
                </project>
                """,
                encoding="utf-8",
            )
            profile = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/custom-directory",
                source_commit=SOURCE_COMMIT,
            )

        self.assertIn(
            "MAVEN_CUSTOM_BUILD_DIRECTORY_UNSUPPORTED",
            profile["decision"]["blockers"],
        )
        self.assertIsNone(profile["build_plan"]["artifact_selection"]["root"])
        self.assertEqual(profile["build_plan"]["artifact_selection"]["include"], [])

    def test_maven_expression_final_name_is_not_interpreted_structurally(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """
                <project><modelVersion>4.0.0</modelVersion>
                  <groupId>dev.assured</groupId><artifactId>demo</artifactId>
                  <version>1.0.0</version>
                  <build><finalName>${project.artifactId}-secure</finalName></build>
                </project>
                """,
                encoding="utf-8",
            )
            profile = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/final-name-expression",
                source_commit=SOURCE_COMMIT,
            )

        self.assertIn(
            "MAVEN_ARTIFACT_NAME_UNRESOLVED",
            profile["decision"]["blockers"],
        )
        self.assertEqual(profile["build_plan"]["artifact_selection"]["include"], [])

    def test_maven_parent_requires_effective_output_model(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """
                <project><modelVersion>4.0.0</modelVersion>
                  <parent><groupId>dev.parent</groupId><artifactId>base</artifactId>
                    <version>1.0.0</version></parent>
                  <artifactId>demo</artifactId><version>2.0.0</version>
                </project>
                """,
                encoding="utf-8",
            )
            profile = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/parent-output",
                source_commit=SOURCE_COMMIT,
            )

        self.assertIn(
            "MAVEN_PARENT_EFFECTIVE_MODEL_REQUIRED",
            profile["decision"]["blockers"],
        )
        self.assertEqual(
            profile["signals"]["declared_primary_artifact"],
            "demo-2.0.0.jar",
        )
        self.assertIsNone(profile["signals"]["exact_primary_artifact"])
        self.assertIsNone(profile["build_plan"]["artifact_selection"]["root"])

    def test_maven_profile_output_override_requires_effective_model(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """
                <project><modelVersion>4.0.0</modelVersion>
                  <groupId>dev.assured</groupId><artifactId>demo</artifactId>
                  <version>1.0.0</version><profiles><profile><id>release-shape</id>
                    <activation><activeByDefault>true</activeByDefault></activation>
                    <build><finalName>profiled</finalName><directory>profile-out</directory></build>
                  </profile></profiles>
                </project>
                """,
                encoding="utf-8",
            )
            profile = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/profile-output",
                source_commit=SOURCE_COMMIT,
            )

        self.assertIn(
            "MAVEN_PROFILE_BUILD_OUTPUT_UNRESOLVED",
            profile["decision"]["blockers"],
        )
        self.assertEqual(profile["signals"]["profiles"][0]["active_by_default"], "true")
        self.assertEqual(
            profile["signals"]["profile_output_overrides"][0]["directory"],
            "profile-out",
        )
        self.assertEqual(profile["build_plan"]["artifact_selection"]["include"], [])

    def test_maven_profile_plugin_output_override_blocks_exact_collection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """
                <project><modelVersion>4.0.0</modelVersion>
                  <groupId>dev.assured</groupId><artifactId>demo</artifactId>
                  <version>1.0.0</version><profiles><profile><id>release-shape</id>
                    <build><plugins><plugin>
                      <groupId>org.apache.maven.plugins</groupId>
                      <artifactId>maven-jar-plugin</artifactId>
                      <configuration>
                        <finalName>profiled</finalName>
                        <outputDirectory>profile-jars</outputDirectory>
                      </configuration>
                    </plugin></plugins></build>
                  </profile></profiles>
                </project>
                """,
                encoding="utf-8",
            )
            profile = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/profile-plugin-output",
                source_commit=SOURCE_COMMIT,
            )

        self.assertIn(
            "MAVEN_PLUGIN_BUILD_OUTPUT_UNRESOLVED",
            profile["decision"]["blockers"],
        )
        self.assertEqual(
            {
                value["parameter_path"]
                for value in profile["signals"]["plugin_output_overrides"]
            },
            {"configuration/finalName", "configuration/outputDirectory"},
        )
        self.assertIsNone(profile["signals"]["exact_primary_artifact"])
        self.assertIsNone(profile["build_plan"]["artifact_selection"]["root"])
        self.assertEqual(profile["build_plan"]["artifact_selection"]["include"], [])

    def test_source_manifest_symlink_is_rejected(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks are unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root.parent / f"{root.name}-outside-pom.xml"
            outside.write_text("<project />\n", encoding="utf-8")
            try:
                (root / "pom.xml").symlink_to(outside)
                with self.assertRaisesRegex(ValueError, "symlink"):
                    plan_ecosystem_build_profile(
                        root=root,
                        source_repository="fixture/symlink",
                        source_commit=SOURCE_COMMIT,
                    )
            finally:
                outside.unlink(missing_ok=True)

    def test_dotnet_profile_selects_single_target_and_exact_framework(self) -> None:
        profile = plan_ecosystem_build_profile(
            root=Path("tests/fixtures/recon/dotnet"),
            source_repository="fixture/dotnet-tool",
            source_commit=SOURCE_COMMIT,
            self_contained=False,
        )

        self.assertEqual(profile["profile_id"], "dotnet-v1")
        self.assertEqual(
            profile["signals"]["selected_target"]["path"],
            "DotnetTool.csproj",
        )
        self.assertEqual(profile["signals"]["selected_framework"], "net8.0")
        self.assertEqual(profile["signals"]["operation"], "publish")
        self.assertIn(
            "DOTNET_ARTIFACT_MANIFEST_REQUIRES_CANARY",
            profile["decision"]["canary_requirements"],
        )
        self.assertIn("DOTNET_PACKAGES_LOCK_MISSING", profile["decision"]["blockers"])
        steps = profile["build_plan"]["steps"]
        self.assertEqual(
            steps[0]["argv"][:2], ["/opt/dotnet/dotnet", "restore"]
        )
        self.assertIn("--locked-mode", steps[0]["argv"])
        self.assertEqual(
            steps[-1]["argv"][:2], ["/opt/dotnet/dotnet", "publish"]
        )
        self.assertIn("--no-restore", steps[-1]["argv"])
        self.assertEqual(steps[-1]["argv"][-2:], ["--self-contained", "false"])
        self.assertEqual(
            profile["build_plan"]["trusted_preparation"]["source"]["to"],
            "/workspace/src",
        )

    def test_dotnet_multiple_targets_frameworks_rids_and_feed_require_selection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cli.csproj").write_text(
                """
                <Project Sdk="Microsoft.NET.Sdk">
                  <PropertyGroup>
                    <OutputType>Exe</OutputType>
                    <TargetFrameworks>net8.0;net9.0</TargetFrameworks>
                    <RuntimeIdentifiers>linux-x64;win-x64</RuntimeIdentifiers>
                  </PropertyGroup>
                </Project>
                """,
                encoding="utf-8",
            )
            (root / "Library.csproj").write_text(
                '<Project Sdk="Microsoft.NET.Sdk" />\n',
                encoding="utf-8",
            )
            (root / "nuget.config").write_text(
                """
                <configuration><packageSources><clear />
                  <add key="private" value="https://packages.example.invalid/v3/index.json" />
                </packageSources></configuration>
                """,
                encoding="utf-8",
            )
            undecided = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/multi-dotnet",
                source_commit=SOURCE_COMMIT,
            )
            selected = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/multi-dotnet",
                source_commit=SOURCE_COMMIT,
                target="Cli.csproj",
            )

        self.assertIn(
            "DOTNET_TARGET_SELECTION_REQUIRED", undecided["decision"]["blockers"]
        )
        blockers = selected["decision"]["blockers"]
        self.assertIn("DOTNET_TARGET_FRAMEWORK_SELECTION_REQUIRED", blockers)
        self.assertIn("DOTNET_RUNTIME_IDENTIFIER_SELECTION_REQUIRED", blockers)
        self.assertIn("DOTNET_NON_PUBLIC_FEED_REQUIRES_CLOSURE", blockers)
        self.assertIn("DOTNET_DEPLOYMENT_MODE_SELECTION_REQUIRED", blockers)
        self.assertEqual(selected["build_plan"]["steps"], [])

    def test_dotnet_dynamic_msbuild_import_is_a_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Tool.csproj").write_text(
                """
                <Project Sdk="Microsoft.NET.Sdk">
                  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
                  <Import Project="$(ExternalTargets)/unsafe.targets" />
                </Project>
                """,
                encoding="utf-8",
            )
            profile = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/imports",
                source_commit=SOURCE_COMMIT,
            )

        self.assertIn(
            "DOTNET_IMPORT_CLOSURE_UNRESOLVED",
            profile["decision"]["blockers"],
        )

    def test_dotnet_option_like_project_path_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "--output=escaped.csproj").write_text(
                """
                <Project Sdk="Microsoft.NET.Sdk">
                  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
                </Project>
                """,
                encoding="utf-8",
            )
            profile = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/options",
                source_commit=SOURCE_COMMIT,
            )

        self.assertIn(
            "DOTNET_TARGET_PATH_OPTION_LIKE",
            profile["decision"]["blockers"],
        )
        self.assertEqual(profile["build_plan"]["steps"], [])

    def test_dotnet_deceptive_nuget_org_url_is_non_public(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Tool.csproj").write_text(
                """
                <Project Sdk="Microsoft.NET.Sdk">
                  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
                </Project>
                """,
                encoding="utf-8",
            )
            (root / "nuget.config").write_text(
                """
                <configuration><packageSources>
                  <add key="fake" value="https://attacker.invalid/api.nuget.org/v3/index.json" />
                </packageSources></configuration>
                """,
                encoding="utf-8",
            )
            profile = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/feed",
                source_commit=SOURCE_COMMIT,
            )

        self.assertIn(
            "DOTNET_NON_PUBLIC_FEED_REQUIRES_CLOSURE",
            profile["decision"]["blockers"],
        )

    def test_dotnet_conditional_target_property_is_a_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Tool.csproj").write_text(
                """
                <Project Sdk="Microsoft.NET.Sdk">
                  <PropertyGroup>
                    <TargetFramework>net8.0</TargetFramework>
                    <OutputType Condition="'$(Mode)' == 'cli'">Exe</OutputType>
                  </PropertyGroup>
                </Project>
                """,
                encoding="utf-8",
            )
            profile = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/conditional",
                source_commit=SOURCE_COMMIT,
            )

        self.assertIn(
            "DOTNET_CONDITIONAL_TARGET_MODEL_UNRESOLVED",
            profile["decision"]["blockers"],
        )

    def test_dotnet_source_framework_cannot_inject_cli_options(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Tool.csproj").write_text(
                """
                <Project Sdk="Microsoft.NET.Sdk">
                  <PropertyGroup><OutputType>Exe</OutputType>
                    <TargetFramework>--no-restore</TargetFramework></PropertyGroup>
                </Project>
                """,
                encoding="utf-8",
            )
            profile = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/framework-option",
                source_commit=SOURCE_COMMIT,
                self_contained=False,
            )

        self.assertIn(
            "DOTNET_TARGET_FRAMEWORK_TOKEN_INVALID",
            profile["decision"]["blockers"],
        )
        self.assertEqual(profile["build_plan"]["steps"], [])

    def test_dotnet_requested_rid_cannot_inject_msbuild_properties(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Tool.csproj").write_text(
                """
                <Project Sdk="Microsoft.NET.Sdk">
                  <PropertyGroup><OutputType>Exe</OutputType>
                    <TargetFramework>net8.0</TargetFramework></PropertyGroup>
                </Project>
                """,
                encoding="utf-8",
            )
            profile = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/rid-option",
                source_commit=SOURCE_COMMIT,
                runtime_identifier="$(InjectedRid)",
                self_contained=True,
            )

        self.assertIn(
            "DOTNET_RUNTIME_IDENTIFIER_TOKEN_INVALID",
            profile["decision"]["blockers"],
        )
        self.assertEqual(profile["build_plan"]["steps"], [])

    def test_valid_material_lock_closes_only_the_material_lock_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """
                <project><modelVersion>4.0.0</modelVersion>
                  <groupId>dev.assured</groupId><artifactId>demo</artifactId>
                  <version>1.0.0</version>
                </project>
                """,
                encoding="utf-8",
            )
            lock_path = (
                root
                / ".assured-downstream"
                / "materials"
                / "java-maven-v1.json"
            )
            lock_path.parent.mkdir(parents=True)
            lock_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "profile_id": "java-maven-v1",
                        "source_commit": SOURCE_COMMIT,
                        "materials": [
                            {
                                "bundle_path": "m2/example.jar",
                                "kind": "maven-artifact",
                                "name": "dev.assured:example:1.0.0",
                                "sha256": "b" * 64,
                                "size": 42,
                                "source_url": "https://repo1.maven.org/example.jar",
                            }
                        ],
                        "bundle": {"sha256": "c" * 64, "size": 100},
                    }
                ),
                encoding="utf-8",
            )
            profile = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/materials",
                source_commit=SOURCE_COMMIT,
            )

        self.assertNotIn(
            "DEPENDENCY_MATERIAL_LOCK_MISSING", profile["decision"]["blockers"]
        )
        self.assertIn(
            "DEPENDENCY_MATERIAL_LOCK_UNVERIFIED",
            profile["decision"]["blockers"],
        )
        self.assertIn(
            "ECOSYSTEM_POLICY_NOT_CANARY_APPROVED",
            profile["decision"]["blockers"],
        )
        self.assertFalse(profile["execution_permitted"])

    def test_material_lock_rejects_traversal_bundle_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """
                <project><modelVersion>4.0.0</modelVersion>
                  <groupId>dev.assured</groupId><artifactId>demo</artifactId>
                  <version>1.0.0</version>
                </project>
                """,
                encoding="utf-8",
            )
            lock_path = root / ".assured-downstream/materials/java-maven-v1.json"
            lock_path.parent.mkdir(parents=True)
            lock_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "profile_id": "java-maven-v1",
                        "source_commit": SOURCE_COMMIT,
                        "bundle": {"sha256": "c" * 64, "size": 100},
                        "materials": [
                            {
                                "bundle_path": "../escape.jar",
                                "kind": "maven-artifact",
                                "name": "dev.assured:escape:1.0.0",
                                "sha256": "b" * 64,
                                "size": 42,
                                "source_url": "https://repo1.maven.org/escape.jar",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            profile = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/material-traversal",
                source_commit=SOURCE_COMMIT,
            )

        self.assertIn(
            "DEPENDENCY_MATERIAL_LOCK_INVALID",
            profile["decision"]["blockers"],
        )

    def test_gradle_is_explicitly_outside_the_maven_mvp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.gradle").write_text(
                "sourceControl { gitRepository('https://example.invalid/dependency.git') }\n",
                encoding="utf-8",
            )
            (root / "build.gradle").write_text("plugins { id 'java' }\n", encoding="utf-8")
            profile = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/gradle",
                source_commit=SOURCE_COMMIT,
            )

        self.assertEqual(profile["build_system"], "gradle")
        self.assertIn(
            "JAVA_GRADLE_PROFILE_NOT_IMPLEMENTED",
            profile["decision"]["blockers"],
        )
        self.assertEqual(profile["build_plan"]["steps"], [])

    def test_mixed_build_system_requires_explicit_ecosystem_selection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """
                <project><modelVersion>4.0.0</modelVersion>
                  <groupId>dev.assured</groupId><artifactId>mixed</artifactId>
                  <version>1.0.0</version>
                </project>
                """,
                encoding="utf-8",
            )
            (root / "build.gradle").write_text("plugins { id 'java' }\n", encoding="utf-8")
            profile = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/mixed",
                source_commit=SOURCE_COMMIT,
            )
            selected = plan_ecosystem_build_profile(
                root=root,
                source_repository="fixture/mixed",
                source_commit=SOURCE_COMMIT,
                ecosystem="java-maven",
            )

        self.assertIn(
            "BUILD_ECOSYSTEM_SELECTION_REQUIRED",
            profile["decision"]["blockers"],
        )
        self.assertNotIn(
            "BUILD_ECOSYSTEM_SELECTION_REQUIRED",
            selected["decision"]["blockers"],
        )

    def test_development_policies_validate_as_no_network(self) -> None:
        for policy_id in ("java-maven-v1", "dotnet-v1"):
            with self.subTest(policy=policy_id):
                policy = load_ecosystem_policy(policy_id)
                self.assertFalse(policy["canary_profile_approved"])
                self.assertEqual(policy["builder"]["network"], "none")

    def test_policy_rejects_truthy_string_execution_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy_dir = Path(tmp)
            policy = load_ecosystem_policy("java-maven-v1")
            policy.pop("_policy_sha256")
            policy["canary_profile_approved"] = "false"
            (policy_dir / "java-maven-v1.json").write_text(
                json.dumps(policy),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "must be boolean"):
                load_ecosystem_policy("java-maven-v1", policy_dir)

    def test_portable_profile_omits_machine_local_analysis_path(self) -> None:
        profile = plan_ecosystem_build_profile(
            root=Path("tests/fixtures/recon/java"),
            source_repository="fixture/java-tool",
            source_commit=SOURCE_COMMIT,
            include_analysis_path=False,
        )

        self.assertIsNone(profile["source"]["analysis_path"])
        self.assertEqual(
            profile["source"]["identity_binding"],
            "caller-declared-unverified",
        )

    def test_cli_returns_nonzero_for_blocked_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "profile.json"
            args = build_parser().parse_args(
                [
                    "plan-build-profile",
                    "--path",
                    "tests/fixtures/recon/java",
                    "--source-repository",
                    "fixture/java-tool",
                    "--source-commit",
                    SOURCE_COMMIT,
                    "--output",
                    str(output),
                ]
            )

            code = args.func(args)

            self.assertEqual(code, 2)
            self.assertTrue(output.is_file())


if __name__ == "__main__":
    unittest.main()
