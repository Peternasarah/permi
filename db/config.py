# db/config.py
# Central configuration management for Permi.
#
# API key priority order (highest to lowest):
#   1. Environment variable  OPENROUTER_API_KEY  — for CI/CD pipelines
#   2. ~/.permi/config.json  openrouter_api_key  — set by: permi setup --api-key
#   3. .env file in current directory            — for developers running from source
#   4. Community proxy token                     — set by: permi setup --community
#   5. Nothing found                             — offline mode with clear message
#
# FIX v0.2.17: CONFIG_FILE is now computed lazily.
# Previously it ran get_permi_dir() at module level which triggered
# filesystem access at import time — causing Windows Defender to freeze.

from __future__ import annotations

import os
import json
from pathlib import Path

PROXY_URL = "https://permi-proxy.onrender.com"

# ── Lazy path resolution ──────────────────────────────────────────────────────
_CONFIG_FILE: Path | None = None


def get_config_path() -> Path:
    """Return the config file path, computing it on first call only."""
    global _CONFIG_FILE
    if _CONFIG_FILE is None:
        from db.database import get_permi_dir
        _CONFIG_FILE = get_permi_dir() / "config.json"
    return _CONFIG_FILE


def get_db_path() -> Path:
    """Return the database path."""
    from db.database import get_db_path as _get_db_path
    return _get_db_path()


# ── API key ───────────────────────────────────────────────────────────────────

def get_api_key() -> str | None:
    """Return the OpenRouter API key using the priority chain."""
    # 1. Environment variable
    key = os.environ.get("OPENROUTER_API_KEY")
    if key and key.strip():
        return key.strip()

    # 2. ~/.permi/config.json
    cfg = get_config_path()
    if cfg.exists():
        try:
            data = json.loads(cfg.read_text(encoding="utf-8"))
            key  = data.get("openrouter_api_key", "")
            if key and key.strip():
                return key.strip()
        except (json.JSONDecodeError, OSError):
            pass

    # 3. .env file in current directory
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


def get_community_token() -> str | None:
    """Return the community proxy token if configured."""
    cfg = get_config_path()
    if cfg.exists():
        try:
            data  = json.loads(cfg.read_text(encoding="utf-8"))
            token = data.get("community_token", "")
            if token and token.strip():
                return token.strip()
        except (json.JSONDecodeError, OSError):
            pass
    return None


def save_api_key(api_key: str) -> None:
    """Save OpenRouter API key to ~/.permi/config.json."""
    data = _load_config()
    data["openrouter_api_key"] = api_key.strip()
    data.pop("community_token", None)  # remove community token when using personal key
    _save_config(data)


def save_community_token(token: str) -> None:
    """Save community proxy token to ~/.permi/config.json."""
    data = _load_config()
    data["community_token"] = token.strip()
    data.pop("openrouter_api_key", None)  # remove personal key when using community
    _save_config(data)


def get_proxy_url() -> str:
    """Return the proxy URL — overridable via environment for testing."""
    return os.environ.get("PERMI_PROXY_URL", PROXY_URL)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _load_config() -> dict:
    cfg = get_config_path()
    if cfg.exists():
        try:
            return json.loads(cfg.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_config(data: dict) -> None:
    get_config_path().write_text(json.dumps(data, indent=2), encoding="utf-8")
