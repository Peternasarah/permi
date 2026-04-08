# config.py
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
    # 1. Environment variable — CI/CD, Docker, etc.
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

    # 3. .env file in current working directory — for local dev
    env_file = Path.cwd() / ".env"
    if env_file.exists():
        try:
            for line in env_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith("OPENROUTER_API_KEY"):
                    parts = line.split("=", 1)
                    if len(parts) == 2:
                        key = parts[1].strip().strip('"').strip("'")
                        if key:
                            return key
        except OSError:
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
    """Return the path to the config file — used by `permi setup` to show the user."""
    return CONFIG_FILE


def get_db_path() -> Path:
    """Return the path to the database — used by `permi info`."""
    from db.database import DB_PATH
    return DB_PATH
