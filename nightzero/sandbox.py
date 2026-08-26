from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nightzero.store import IncidentStore

logger = logging.getLogger(__name__)


@dataclass
class ProjectTestProfile:
    repository: str
    language: str
    test_command: list[str]
    install_command: list[str] = field(default_factory=list)
    test_directory: str = ""
    env_vars: dict[str, str] = field(default_factory=dict)
    discovered_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProjectTestProfile:
        return cls(
            repository=data.get("repository", "default/repo"),
            language=data.get("language", "python"),
            test_command=data.get("test_command", [sys.executable, "-B", "-m", "unittest", "discover"]),
            install_command=data.get("install_command", []),
            test_directory=data.get("test_directory", ""),
            env_vars=data.get("env_vars", {}),
            discovered_at=data.get("discovered_at", datetime.now(UTC).isoformat()),
        )


class ProjectSandboxMemory:
    """Persistent Memory Bank for learned repository test configurations."""

    _in_memory_cache: dict[str, ProjectTestProfile] = {}

    @classmethod
    def _key(cls, repository: str) -> str:
        safe_repo = repository.replace("/", "_").replace(":", "_")
        return f"sandbox_profile_{safe_repo}"

    @classmethod
    def get_profile(cls, repository: str, store: IncidentStore | None = None) -> ProjectTestProfile | None:
        if not repository:
            return None
        key = cls._key(repository)
        if key in cls._in_memory_cache:
            return cls._in_memory_cache[key]

        if store:
            try:
                data = store.get_setting(key)
                if isinstance(data, dict):
                    profile = ProjectTestProfile.from_dict(data)
                    cls._in_memory_cache[key] = profile
                    return profile
            except Exception as exc:
                logger.warning("Failed retrieving sandbox profile from Memory Bank: %s", exc)

        return None

    @classmethod
    def save_profile(cls, repository: str, profile: ProjectTestProfile, store: IncidentStore | None = None) -> None:
        if not repository:
            return
        key = cls._key(repository)
        cls._in_memory_cache[key] = profile
        if store:
            try:
                store.set_setting(key, profile.to_dict())
                logger.info("Saved sandbox test profile for '%s' to Memory Bank", repository)
            except Exception as exc:
                logger.warning("Failed persisting sandbox profile to Memory Bank: %s", exc)


class ProjectSandboxAnalyzer:
    """Analyzes a codebase to discover language, test runner, and execution strategies."""

    @classmethod
    def analyze_repository(
        cls,
        repository: str,
        workspace_dir: Path | None = None,
        store: IncidentStore | None = None,
        gemini_model: str = "gemini-3.7-flash",
    ) -> tuple[ProjectTestProfile, bool]:
        """Discovers or retrieves the test profile for a project. Returns (profile, from_memory_bank)."""
        # 1. Memory Bank Lookup
        cached = ProjectSandboxMemory.get_profile(repository, store)
        if cached:
            return cached, True

        # 2. Automated File Manifest Inspection
        discovered = cls._inspect_manifests(repository, workspace_dir)
        if not discovered and os.environ.get("GOOGLE_API_KEY") and workspace_dir and workspace_dir.exists():
            # 3. LLM-Assisted Discovery
            discovered = cls._discover_with_gemini(repository, workspace_dir, gemini_model)

        profile = discovered or ProjectTestProfile(
            repository=repository or "default/repo",
            language="python",
            test_command=[sys.executable, "-B", "-m", "unittest", "discover"],
            env_vars={"PYTHONDONTWRITEBYTECODE": "1"},
        )

        # 4. Remember in Memory Bank
        ProjectSandboxMemory.save_profile(repository, profile, store)
        return profile, False

    @classmethod
    def _inspect_manifests(cls, repository: str, workspace_dir: Path | None) -> ProjectTestProfile | None:
        if not workspace_dir or not workspace_dir.exists():
            return None

        # Check for Python
        if (workspace_dir / "requirements.txt").exists() or (workspace_dir / "pyproject.toml").exists() or (workspace_dir / "setup.py").exists() or list(workspace_dir.glob("**/*.py")):
            # Check test directory
            candidate_dirs = [d for d in ["tests", "test", "demo_target", "src"] if (workspace_dir / d).is_dir()]
            test_dir = next((d for d in candidate_dirs if list((workspace_dir / d).glob("test_*.py"))), candidate_dirs[0] if candidate_dirs else ".")
            
            if (workspace_dir / "pytest.ini").exists():
                return ProjectTestProfile(
                    repository=repository,
                    language="python",
                    test_command=["pytest", test_dir],
                    test_directory=test_dir,
                    env_vars={"PYTHONDONTWRITEBYTECODE": "1"},
                )
            return ProjectTestProfile(
                repository=repository,
                language="python",
                test_command=[sys.executable, "-B", "-m", "unittest", "discover", "-s", test_dir, "-t", "."],
                test_directory=test_dir,
                env_vars={"PYTHONDONTWRITEBYTECODE": "1"},
            )

        # Check for Node.js / TypeScript
        pkg_json = workspace_dir / "package.json"
        if pkg_json.exists():
            try:
                pkg_data = json.loads(pkg_json.read_text(encoding="utf-8"))
                test_script = pkg_data.get("scripts", {}).get("test", "npm test")
                cmd = ["npm", "test"] if "npm" in test_script else test_script.split()
                return ProjectTestProfile(
                    repository=repository,
                    language="typescript" if (workspace_dir / "tsconfig.json").exists() else "javascript",
                    test_command=cmd,
                    install_command=["npm", "ci"],
                )
            except Exception:
                return ProjectTestProfile(repository=repository, language="javascript", test_command=["npm", "test"])

        # Check for Go
        if (workspace_dir / "go.mod").exists():
            return ProjectTestProfile(
                repository=repository,
                language="go",
                test_command=["go", "test", "./..."],
            )

        # Check for Rust
        if (workspace_dir / "Cargo.toml").exists():
            return ProjectTestProfile(
                repository=repository,
                language="rust",
                test_command=["cargo", "test"],
            )

        # Check for Java (Maven / Gradle)
        if (workspace_dir / "pom.xml").exists():
            return ProjectTestProfile(repository=repository, language="java", test_command=["mvn", "test"])
        if (workspace_dir / "build.gradle").exists() or (workspace_dir / "build.gradle.kts").exists():
            return ProjectTestProfile(repository=repository, language="java", test_command=["./gradlew", "test"])

        return None

    @classmethod
    def _discover_with_gemini(cls, repository: str, workspace_dir: Path, model: str) -> ProjectTestProfile | None:
        try:
            from google import genai
            from google.genai import types

            api_key = os.environ.get("GOOGLE_API_KEY")
            use_vertex = os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "true").lower() in ("true", "1", "yes")
            project = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("PROJECT_ID", "nightzero")
            location = os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1")

            if use_vertex or not api_key:
                client = genai.Client(vertexai=True, project=project, location=location)
            else:
                client = genai.Client(api_key=api_key)
            # Gather repository file structure
            file_tree = [str(p.relative_to(workspace_dir)) for p in workspace_dir.glob("**/*") if not any(part.startswith(".") for part in p.parts)][:50]
            prompt = f"""You are a Test Automation & CI/CD Discovery AI.
Analyze the following project file structure and determine the programming language and CLI test execution command for sandbox execution.

Repository: {repository}
File Structure:
{json.dumps(file_tree, indent=2)}

Return ONLY JSON matching:
{{
  "language": "python | javascript | typescript | go | rust | java",
  "test_command": ["python3", "-m", "unittest", "discover"],
  "install_command": [],
  "test_directory": "tests"
}}
"""
            res = client.models.generate_content(
                model=model,
                contents=prompt,
                config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0.2),
            )
            data = json.loads(res.text or "{}")
            if data.get("test_command"):
                return ProjectTestProfile(
                    repository=repository,
                    language=data.get("language", "python"),
                    test_command=data["test_command"],
                    install_command=data.get("install_command", []),
                    test_directory=data.get("test_directory", ""),
                )
        except Exception as exc:
            logger.warning("Gemini test discovery failed: %s", exc)
        return None
