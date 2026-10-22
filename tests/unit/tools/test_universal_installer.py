"""
Tests for the Node/JS install path in UniversalInstaller.

Regression context: ``xscan install https://github.com/cure53/DOMPurify.git``
found no ``setup.py``, ``go.mod`` or ``*.py`` at the repo root, so it fell
through to a useless "Cloned to … Run manually" result — no npm step, no
artifacts, and ``xscan install dompurify`` failed with "Unknown tool".
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from xscan.tools.installers import universal
from xscan.tools.installers.universal import _NODE_RECIPES, UniversalInstaller


def _installer(monkeypatch, tmp_path: Path) -> UniversalInstaller:
    """Installer whose bin/tools dirs live under tmp_path, never $HOME."""
    monkeypatch.setattr(universal, "_XSCAN_BIN", tmp_path / "bin")
    monkeypatch.setattr(universal, "_XSCAN_TOOLS", tmp_path / "tools")
    return UniversalInstaller()


def _patch_node_recipe(monkeypatch, sentinel):
    calls: dict = {"count": 0}

    def fake(self, name, recipe, clone_dir=None, progress_cb=None):
        calls["count"] += 1
        calls.setdefault("name", name)
        calls.setdefault("clone_dir", clone_dir)
        return sentinel

    monkeypatch.setattr(universal.UniversalInstaller, "_install_node_recipe", fake)
    return calls


class TestNodeRecipes:
    def test_dompurify_recipe_is_registered(self):
        recipe = _NODE_RECIPES["dompurify"]
        assert "cure53/DOMPurify" in recipe["git_url"]
        assert "dist/purify.js" in recipe["artifacts"]

    def test_install_by_name_dispatches_to_node_recipe(self, monkeypatch, tmp_path):
        installer = _installer(monkeypatch, tmp_path)
        sentinel = universal.InstallResult(tool_name="dompurify", success=True, method="node")
        calls = _patch_node_recipe(monkeypatch, sentinel)

        for arg in ("dompurify", "DOMPurify", "dom-purify"):
            assert installer.install(arg) is sentinel
            assert calls["name"] == "dompurify"
        assert calls["count"] == 3

    def test_github_url_dispatches_to_node_recipe(self, monkeypatch, tmp_path):
        installer = _installer(monkeypatch, tmp_path)
        sentinel = universal.InstallResult(tool_name="dompurify", success=True, method="node")
        calls = _patch_node_recipe(monkeypatch, sentinel)
        clone = MagicMock(return_value=True)
        monkeypatch.setattr(universal.UniversalInstaller, "_git_clone", clone)

        result = installer.install("https://github.com/cure53/DOMPurify.git")

        assert result is sentinel
        assert calls["name"] == "dompurify"
        # The known recipe short-circuits before any clone is attempted.
        assert not clone.called

    def test_unknown_github_repo_with_package_json_uses_node_path(
        self, monkeypatch, tmp_path
    ):
        repo = tmp_path / "tools" / "SomesLib"
        repo.mkdir(parents=True)
        (repo / "package.json").write_text(
            json.dumps({"name": "someslib", "version": "1.0.0"}), encoding="utf-8"
        )
        installer = _installer(monkeypatch, tmp_path)
        sentinel = universal.InstallResult(tool_name="SomesLib", success=True, method="node")
        calls = _patch_node_recipe(monkeypatch, sentinel)
        monkeypatch.setattr(
            universal.UniversalInstaller, "_git_clone",
            lambda self, url, dest, cb: True,
        )

        result = installer.install("https://github.com/x/SomesLib.git")

        assert result is sentinel
        assert calls["clone_dir"] == repo


class TestPrebuiltDistFastPath:
    """DOMPurify ships dist/ in the repo — npm must not be required."""

    def _clone(self, tmp_path: Path) -> Path:
        repo = tmp_path / "DOMPurify"
        (repo / "dist").mkdir(parents=True)
        (repo / "dist" / "purify.js").write_text("// prebuilt", encoding="utf-8")
        (repo / "package.json").write_text(
            json.dumps({"name": "dompurify", "version": "3.4.16"}), encoding="utf-8"
        )
        return repo

    def test_prebuilt_artifacts_short_circuit_npm(self, monkeypatch, tmp_path):
        repo = self._clone(tmp_path)
        installer = _installer(monkeypatch, tmp_path)
        monkeypatch.setattr(
            universal.UniversalInstaller, "_npm_cmd", staticmethod(lambda: None)
        )

        result = installer._install_node_recipe(
            "dompurify", _NODE_RECIPES["dompurify"], clone_dir=repo
        )

        assert result.success
        assert result.method == "node"
        assert "3.4.16" in result.note
        assert result.binary_path == str(repo / "dist" / "purify.js")

    def test_missing_npm_without_dist_fails_with_clear_error(
        self, monkeypatch, tmp_path
    ):
        repo = tmp_path / "DOMPurify"
        repo.mkdir()
        (repo / "package.json").write_text(
            json.dumps({"name": "dompurify"}), encoding="utf-8"
        )
        installer = _installer(monkeypatch, tmp_path)
        monkeypatch.setattr(
            universal.UniversalInstaller, "_npm_cmd", staticmethod(lambda: None)
        )

        result = installer._install_node_recipe("dompurify", {}, clone_dir=repo)

        assert not result.success
        assert "npm" in result.error

    def test_non_node_repo_is_rejected(self, monkeypatch, tmp_path):
        repo = tmp_path / "notjs"
        repo.mkdir()
        installer = _installer(monkeypatch, tmp_path)

        result = installer._install_node_recipe("notjs", {}, clone_dir=repo)

        assert not result.success
        assert "package.json" in result.error


class TestNpmBuildPath:
    """A JS repo without a shipped dist/ must be installed and built."""

    def _sources(self, tmp_path: Path) -> Path:
        repo = tmp_path / "DOMPurify"
        repo.mkdir()
        (repo / "package.json").write_text(
            json.dumps({"name": "dompurify", "version": "1.0.0"}), encoding="utf-8"
        )
        return repo

    def test_install_then_build_then_verify_artifacts(self, monkeypatch, tmp_path):
        repo = self._sources(tmp_path)
        installer = _installer(monkeypatch, tmp_path)
        monkeypatch.setattr(
            universal.UniversalInstaller, "_npm_cmd", staticmethod(lambda: "npm")
        )
        commands: list[list[str]] = []

        def fake_run_npm(args, cwd):
            commands.append(list(args))
            (repo / "dist").mkdir(exist_ok=True)
            (repo / "dist" / "purify.js").write_text("// built", encoding="utf-8")
            return 0, ""

        monkeypatch.setattr(
            universal.UniversalInstaller, "_run_npm", staticmethod(fake_run_npm)
        )

        result = installer._install_node_recipe(
            "dompurify", _NODE_RECIPES["dompurify"], clone_dir=repo
        )

        assert result.success
        assert result.method == "node"
        assert "built from source" in result.note
        assert commands[0][1] == "install"
        assert commands[1][1:] == ["run", "build"]

    def test_build_failure_is_reported(self, monkeypatch, tmp_path):
        repo = self._sources(tmp_path)
        installer = _installer(monkeypatch, tmp_path)
        monkeypatch.setattr(
            universal.UniversalInstaller, "_npm_cmd", staticmethod(lambda: "npm")
        )

        def failing_run_npm(args, cwd):
            return (1, "boom") if "run" in args else (0, "")

        monkeypatch.setattr(
            universal.UniversalInstaller, "_run_npm", staticmethod(failing_run_npm)
        )

        result = installer._install_node_recipe(
            "dompurify", _NODE_RECIPES["dompurify"], clone_dir=repo
        )

        assert not result.success
        assert "npm run build failed" in result.error
