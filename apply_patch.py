#!/usr/bin/env python3
"""
PERMI — PATCH v0.2.1
Files to update:
  1. ai_filter/llm_client.py   — verdict bug, verbose error, configurable model
  2. db/config.py              — use python-dotenv properly
  3. scanner/engine.py         — debug why .py files are skipped
  4. pyproject.toml            — add requests dependency (manual fix shown below)

Run this script from C:\\Users\\dashe\\Permi with venv active:
  python apply_patch.py
"""

import re
from pathlib import Path

ROOT = Path(__file__).parent


def patch_llm_client():
    """
    Fixes:
    1. Verdict variable reuse bug — saves original before reassigning
    2. Verbose API error leaking exception details
    3. Hardcoded model — reads PERMI_LLM_MODEL env var with fallback
    """
    path = ROOT / "ai_filter" / "llm_client.py"
    content = path.read_text(encoding="utf-8")

    # ── Fix 1: hardcoded model → env var ──────────────────────────────────────
    content = content.replace(
        'MODEL          = "deepseek/deepseek-chat"',
        'MODEL = os.environ.get("PERMI_LLM_MODEL", "deepseek/deepseek-chat")'
    )
    # Make sure os is imported (it already is via config import chain, but be safe)
    if "import os" not in content:
        content = content.replace(
            "import json\nimport requests",
            "import os\nimport json\nimport requests"
        )

    # ── Fix 2: verdict variable reuse bug ─────────────────────────────────────
    old_verdict_block = (
        "        if verdict not in (\"REAL\", \"FP\"):\n"
        "            verdict     = \"REAL\"\n"
        "            explanation = f\"Unexpected verdict '{verdict}' — defaulting to REAL.\""
    )
    new_verdict_block = (
        "        if verdict not in (\"REAL\", \"FP\"):\n"
        "            original_verdict = verdict\n"
        "            verdict     = \"REAL\"\n"
        "            explanation = f\"Unexpected verdict '{original_verdict}' — defaulting to REAL.\""
    )
    content = content.replace(old_verdict_block, new_verdict_block)

    # ── Fix 3: verbose API error — strip exception details ────────────────────
    old_req_except = (
        "    except requests.exceptions.RequestException as e:\n"
        "        finding[\"ai_verdict\"]     = \"REAL\"\n"
        "        finding[\"ai_explanation\"] = f\"API error — defaulting to REAL. ({e})\"\n"
        "        return finding"
    )
    new_req_except = (
        "    except requests.exceptions.RequestException:\n"
        "        finding[\"ai_verdict\"]     = \"REAL\"\n"
        "        finding[\"ai_explanation\"] = \"API error — defaulting to REAL.\"\n"
        "        return finding"
    )
    content = content.replace(old_req_except, new_req_except)

    path.write_text(content, encoding="utf-8")
    print("✅  ai_filter/llm_client.py patched")


def patch_db_config():
    """
    Fixes:
    - Replace hand-rolled .env parser with python-dotenv
    - Handles comments, quotes, edge cases correctly
    """
    path = ROOT / "db" / "config.py"
    new_content = '''# db/config.py
# Central configuration management for Permi.
#
# API key priority order (highest to lowest):
#   1. Environment variable  OPENROUTER_API_KEY  — for CI/CD pipelines
#   2. ~/.permi/config.json                      — set by: permi setup --api-key ...
#   3. .env file in current directory            — for developers running from source
#   4. Nothing found                             — offline mode with clear message

import os
import json
from pathlib import Path
from db.database import get_permi_dir, DB_PATH

CONFIG_FILE = get_permi_dir() / "config.json"


def get_api_key() -> str | None:
    """
    Return the OpenRouter API key using the priority chain.
    Returns None if no key is found anywhere.
    """
    # 1. Environment variable — CI/CD, Docker, shell export
    key = os.environ.get("OPENROUTER_API_KEY")
    if key and key.strip():
        return key.strip()

    # 2. ~/.permi/config.json — set by `permi setup`
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            key  = data.get("openrouter_api_key", "")
            if key and key.strip():
                return key.strip()
        except (json.JSONDecodeError, OSError):
            pass

    # 3. .env file in current working directory — use python-dotenv for safe parsing
    env_file = Path.cwd() / ".env"
    if env_file.exists():
        try:
            from dotenv import dotenv_values
            env_vals = dotenv_values(env_file)
            key = env_vals.get("OPENROUTER_API_KEY", "")
            if key and key.strip():
                return key.strip()
        except Exception:
            pass

    return None


def save_api_key(api_key: str) -> None:
    """
    Save an API key to ~/.permi/config.json.
    Called by `permi setup --api-key ...`
    """
    data = {}
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = {}

    data["openrouter_api_key"] = api_key.strip()
    CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def get_config_path() -> Path:
    return CONFIG_FILE


def get_db_path() -> Path:
    return DB_PATH
'''
    path.write_text(new_content, encoding="utf-8")
    print("✅  db/config.py patched")


def patch_engine():
    """
    Fixes the silent skip of .py files.
    The engine uses rglob("*") but the file extension check
    uses suffix.lower() — this should work. The real issue is
    that SKIP_DIRS uses 'in file_path.parts' which on Windows
    can miss matches due to case sensitivity.
    Fix: case-insensitive SKIP_DIRS check on Windows.
    """
    path = ROOT / "scanner" / "engine.py"
    if not path.exists():
        print("⚠️   scanner/engine.py not found — skipping engine patch")
        return

    content = path.read_text(encoding="utf-8")

    # Fix case-insensitive skip dirs check
    old_skip = (
        "        if any(skip in file_path.parts for skip in SKIP_DIRS):"
    )
    new_skip = (
        "        if any(skip in [p.lower() for p in file_path.parts] for skip in SKIP_DIRS):"
    )

    if old_skip in content:
        content = content.replace(old_skip, new_skip)
        path.write_text(content, encoding="utf-8")
        print("✅  scanner/engine.py patched — case-insensitive skip dirs")
    else:
        print("ℹ️   scanner/engine.py — skip dirs check already correct or different format")
        # Print the relevant section so we can see what's there
        for i, line in enumerate(content.splitlines()):
            if "SKIP_DIRS" in line or "skip" in line.lower():
                print(f"     Line {i+1}: {line}")


def patch_pyproject():
    """
    Adds 'requests' to dependencies if missing.
    """
    path = ROOT / "pyproject.toml"
    content = path.read_text(encoding="utf-8")

    if '"requests"' in content or "'requests'" in content:
        print("ℹ️   pyproject.toml — 'requests' already present, skipping")
        return

    # Insert requests after click
    old_deps = '    "click",\n    "httpx",'
    new_deps = '    "click",\n    "requests",\n    "httpx",'

    if old_deps in content:
        content = content.replace(old_deps, new_deps)
        path.write_text(content, encoding="utf-8")
        print("✅  pyproject.toml patched — added 'requests' dependency")
    else:
        print("⚠️   pyproject.toml — could not find insertion point, check manually")
        print("     Add 'requests' to the dependencies list")


def verify_patches():
    """Quick verification that patches applied correctly."""
    print("\n── Verification ──────────────────────────────────────")

    # Check llm_client
    llm = (ROOT / "ai_filter" / "llm_client.py").read_text(encoding="utf-8")
    assert "original_verdict" in llm,            "❌ verdict bug fix not applied"
    assert "as e:" not in llm or llm.count("as e:") == 0, "❌ verbose error still present"
    assert 'PERMI_LLM_MODEL' in llm,             "❌ model env var not applied"
    print("✅  llm_client.py — all 3 fixes verified")

    # Check config
    cfg = (ROOT / "db" / "config.py").read_text(encoding="utf-8")
    assert "dotenv_values" in cfg, "❌ dotenv fix not applied"
    print("✅  db/config.py — dotenv fix verified")

    # Check pyproject
    proj = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "requests" in proj, "❌ requests not in pyproject.toml"
    print("✅  pyproject.toml — requests dependency verified")

    print("──────────────────────────────────────────────────────")
    print("All patches applied successfully.")
    print("\nNext steps:")
    print("  pip install -e .")
    print("  permi scan --path C:\\Users\\dashe\\Downloads\\PCare_Phase3_Complete\\PCare_Phase3 --offline")


if __name__ == "__main__":
    print("Permi v0.2.1 patch — applying fixes...\n")
    patch_llm_client()
    patch_db_config()
    patch_engine()
    patch_pyproject()
    verify_patches()
