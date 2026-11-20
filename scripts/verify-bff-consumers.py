"""Build wheel/sdist and test public wiring in isolated installed consumers.

All scratch output is under .run-logs/bff-consumers. Success covers clean package
installation and controlled framework HTTP only. Real IAM/JS combined browser
proof remains a separate required gate owned by the runtime owner.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import venv
import zipfile
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUTPUT = REPO / ".run-logs/bff-consumers"
REPORT = OUTPUT / "report.json"
ENV = {
    **os.environ,
    "HTTP_PROXY": "http://127.0.0.1:7897",
    "HTTPS_PROXY": "http://127.0.0.1:7897",
    "http_proxy": "http://127.0.0.1:7897",
    "https_proxy": "http://127.0.0.1:7897",
    "PYTHONNOUSERSITE": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
}
ENV.pop("PYTHONPATH", None)


def run(argv: list[str], cwd: Path, label: str) -> None:
    log = OUTPUT / (label + ".log")
    with log.open("w") as stream:
        result = subprocess.run(
            argv, cwd=cwd, env=ENV, stdout=stream, stderr=subprocess.STDOUT, check=False
        )
    if result.returncode:
        print(log.read_text()[-6000:])
        raise RuntimeError(f"{label}: exit {result.returncode}; see {log}")
    print(label + ": PASS", flush=True)


def archive_manifest(artifact: Path) -> dict[str, str]:
    contents: dict[str, bytes]
    if artifact.suffix == ".whl":
        with zipfile.ZipFile(artifact) as archive:
            contents = {n: archive.read(n) for n in archive.namelist() if not n.endswith("/")}
    else:
        with tarfile.open(artifact) as source_archive:
            contents = {}
            for member in source_archive.getmembers():
                if member.isfile():
                    file = source_archive.extractfile(member)
                    assert file is not None
                    contents[member.name] = file.read()
    for name, data in contents.items():
        if any(part in name for part in (
            ".pyc", ".env", ".codex", ".run-logs", "docs/tasks/", "iam_sdk/",
        )):
            raise RuntimeError(f"unintended archive entry: {name}")
        if b"/home/chaos/" in data or b"controlled-access" in data or b"controlled-refresh" in data:
            raise RuntimeError(f"private fixture/path in archive: {name}")
        if "axis_vertex/" in name:
            source = REPO / "src/axis_vertex" / name.split("axis_vertex/", 1)[1]
            if source.is_file() and data != source.read_bytes():
                raise RuntimeError(f"artifact differs from source: {name}")
    for suffix in (
        "axis_vertex/web_session/client.py",
        "axis_vertex/web_session/store.py",
        "axis_vertex/web_session/wire-records.json",
        "axis_vertex/fastapi/web_session.py",
        "axis_vertex/django/web_session.py",
        "axis_vertex/py.typed",
    ):
        if not any(n.endswith(suffix) for n in contents):
            raise RuntimeError(f"missing package surface: {suffix}")
    return {name: hashlib.sha256(data).hexdigest() for name, data in sorted(contents.items())}


PROBE = """from pathlib import Path
import importlib.util
import asyncio
import sys
import types
from unittest.mock import patch
import axis_vertex
from fastapi.testclient import TestClient
from django.test import Client, override_settings
from bff_fixture import Fixture
from bff_fastapi import create_app
from bff_django import build_urls

def test_installed_distribution_and_public_examples():
    root = Path(axis_vertex.__file__).resolve().parent
    assert "site-packages" in str(root)
    assert (root / "py.typed").is_file()
    assert importlib.util.find_spec("iam_sdk") is None
    fixture = Fixture()
    sync = fixture.sync()
    try:
        assert build_urls(sync)
        with TestClient(create_app(fixture.config), base_url=fixture.config.origin) as client:
            assert client.get("/auth/session/bootstrap").json()["state"] == "PRELOGIN"
            assert client.get("/documents").status_code == 401
    finally:
        sync.close()
        fixture.store.close()

def test_public_example_factories_protect_actual_business_writes():
    fixture = Fixture()
    fixture.permissions["permissions"].append("documents:write")
    core = fixture.sync()
    module = types.ModuleType("installed_example_write_urls")
    try:
        cookie = asyncio.run(fixture.hosted())
        csrf = fixture.store.read_sync(cookie).csrf
        # Inject only the controlled protocol/core instance; execute the shipped factory/routes.
        with patch("bff_fastapi.ServerSession", return_value=fixture.session):
            with TestClient(create_app(fixture.config), base_url=fixture.config.origin) as client:
                client.cookies.set(fixture.config.cookie_name, cookie)
                assert client.post("/documents").status_code == 403
                assert client.post("/documents", headers={
                    "Origin": fixture.config.origin, "X-CSRF-Token": csrf
                }).json() == {"created": True}
        module.urlpatterns = build_urls(core)
        sys.modules[module.__name__] = module
        with override_settings(ROOT_URLCONF=module.__name__, MIDDLEWARE=[]):
            client = Client()
            client.cookies[fixture.config.cookie_name] = cookie
            assert client.post("/documents/create").status_code == 403
            assert client.post("/documents/create", HTTP_ORIGIN=fixture.config.origin,
                HTTP_X_CSRF_TOKEN=csrf).json() == {"created": True}
    finally:
        core.close()
        asyncio.run(fixture.close())
        sys.modules.pop(module.__name__, None)
"""


def main() -> int:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    artifacts = OUTPUT / "dist"
    if artifacts.exists():
        shutil.rmtree(artifacts)  # Generated output owned by this runner only.
    run([sys.executable, "-m", "build", "--outdir", str(artifacts)], REPO, "build")
    results: list[dict[str, object]] = []
    report: dict[str, object] = {
        "utc": datetime.now(UTC).isoformat(),
        "validation_scope": "CONTROLLED_PACKAGE_CONSUMERS",
        "artifacts": results,
        "controlled_consumers": "PENDING",
    }
    produced = sorted(artifacts.iterdir())
    wheel = next(p for p in produced if p.suffix == ".whl")
    matrix = [(p, "current") for p in produced] + [(wheel, "minimum")]
    for artifact, profile in matrix:
        kind = ("wheel" if artifact.suffix == ".whl" else "sdist")
        if profile == "minimum":
            kind += "-minimum"
        manifest = archive_manifest(artifact)
        (OUTPUT / (kind + "-manifest.json")).write_text(json.dumps(manifest, indent=2) + "\n")
        root = OUTPUT / kind
        if root.exists():
            shutil.rmtree(root)
        root.mkdir()
        env_dir = root / "venv"
        venv.EnvBuilder(with_pip=True).create(env_dir)
        python = str(env_dir / "bin/python")
        run([
            python, "-m", "pip", "install", str(artifact) + "[fastapi,django]",
            "pytest>=8", "pytest-asyncio>=0.24", "itsdangerous>=2.2",
            *(["fastapi==0.115.0", "django==5.0", "httpx==0.27.0"]
              if profile == "minimum" else []),
        ], root, kind + "-install")
        tests = root / "consumer"
        tests.mkdir()
        # Stop pytest configuration discovery before the checkout's pythonpath=src.
        # -I clears interpreter injection, but does not disable pytest config.
        (tests / "pytest.ini").write_text(
            "[pytest]\nasyncio_mode=auto\nasyncio_default_fixture_loop_scope=function\n"
        )
        for name in ("bff_fixture.py", "test_web_fastapi.py", "test_web_django.py"):
            shutil.copyfile(REPO / "tests" / name, tests / name)
        shutil.copytree(
            REPO / "tests/fixtures/connected-app-bff", tests / "fixtures/connected-app-bff"
        )
        for name in ("bff_fastapi.py", "bff_django.py"):
            shutil.copyfile(REPO / "examples" / name, tests / name)
        (tests / "test_distribution.py").write_text(PROBE)
        run([
            python, "-I", "-m", "pytest", "-q", "--import-mode=prepend",
            "-o", "asyncio_mode=auto", "-o", "asyncio_default_fixture_loop_scope=function",
            "test_distribution.py", "test_web_fastapi.py", "test_web_django.py",
        ], tests, kind + "-runtime")
        results.append({
            "kind": kind, "name": artifact.name,
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "entries": len(manifest), "clean_install": "PASS", "controlled_frameworks": "PASS",
        })
    bound_inputs: dict[str, str] = {}
    for folder in ("src/axis_vertex", "tests", "examples", "docs"):
        for path in sorted((REPO / folder).rglob("*")):
            if path.is_file() and (path.suffix in {".py", ".json", ".md"} or
                                   path.name == "py.typed"):
                bound_inputs[str(path.relative_to(REPO))] = hashlib.sha256(
                    path.read_bytes()).hexdigest()
    for name in ("pyproject.toml", "README.md", "scripts/verify-bff-consumers.py"):
        bound_inputs[name] = hashlib.sha256((REPO / name).read_bytes()).hexdigest()
    report["bound_inputs"] = bound_inputs
    report["controlled_consumers"] = "PASS"
    REPORT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    # Earlier failures raise; success covers only the consumers executed here.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
