"""Configuration helpers for CyberNewsFeed scripts."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

CONFIG_FILENAME = "cybernewsfeed_config.json"


class ConfigurationError(RuntimeError):
    """Raised when configuration data cannot be loaded."""


def _resolve_config_path(path: str | Path | None = None) -> Path:
    env_override = os.getenv("CYBERNEWSFEED_CONFIG")
    if path is not None:
        return Path(path).expanduser()
    if env_override:
        return Path(env_override).expanduser()
    return Path(CONFIG_FILENAME)


def _prompt_with_default(message: str, default: str | None = None, *, allow_empty: bool = False) -> str:
    while True:
        if default:
            prompt = f"{message} [{default}]: "
        else:
            prompt = f"{message}: "
        try:
            response = input(prompt)
        except EOFError as exc:  # pragma: no cover - defensive for non-interactive runs
            raise ConfigurationError("Input aborted while reading configuration.") from exc
        response = response.strip()
        if response:
            return response
        if response == "" and allow_empty:
            return ""
        if default is not None:
            return default
        print("Please provide a value.")


def _prompt_yes_no(message: str, default: bool = False) -> bool:
    default_label = "Y/n" if default else "y/N"
    while True:
        try:
            response = input(f"{message} [{default_label}]: ")
        except EOFError as exc:  # pragma: no cover - defensive for non-interactive runs
            raise ConfigurationError("Input aborted while reading configuration.") from exc
        response = response.strip().lower()
        if not response:
            return default
        if response in {"y", "yes"}:
            return True
        if response in {"n", "no"}:
            return False
        print("Please answer 'y' or 'n'.")


def _collect_config(existing: Dict[str, Any] | None = None) -> Dict[str, Any]:
    existing = existing or {}
    print("\nConfigure default paths for CyberNewsFeed. Press Enter to keep the suggested value.\n")
    json_default = existing.get("json_output") or "cybersec_news.json"
    csv_default = existing.get("csv_output") or ""
    html_default = existing.get("html_output") or "index.html"
    template_default = existing.get("template_path") or ""
    assets_default = existing.get("assets_dir") or ""
    summary_default = bool(existing.get("print_summary", False))

    json_output = _prompt_with_default("Default JSON export path", json_default)
    csv_export = _prompt_with_default(
        "Default CSV export path (leave blank to disable)", csv_default or None, allow_empty=True
    )
    html_output = _prompt_with_default("Default HTML dashboard path", html_default)
    template_path = _prompt_with_default(
        "Default HTML template override (optional)", template_default or None, allow_empty=True
    )
    assets_dir = _prompt_with_default(
        "Default assets directory override (optional)", assets_default or None, allow_empty=True
    )
    print_summary = _prompt_yes_no("Print a scrape summary by default?", summary_default)

    return {
        "json_output": json_output,
        "csv_output": csv_export,
        "html_output": html_output,
        "template_path": template_path,
        "assets_dir": assets_dir,
        "print_summary": print_summary,
    }


def load_config(path: str | Path | None = None) -> Dict[str, Any]:
    config_path = _resolve_config_path(path)
    if not config_path.exists():
        raise ConfigurationError(f"Configuration file not found at {config_path}.")
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:  # pragma: no cover - invalid user edits
        raise ConfigurationError(f"Configuration file {config_path} is not valid JSON.") from exc
    if not isinstance(data, dict):
        raise ConfigurationError(f"Configuration file {config_path} must contain a JSON object.")
    return data


def save_config(data: Dict[str, Any], path: str | Path | None = None) -> Path:
    config_path = _resolve_config_path(path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with config_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
    print(f"✓ Saved configuration to {config_path}")
    return config_path


def ensure_config(path: str | Path | None = None) -> Dict[str, Any]:
    config_path = _resolve_config_path(path)
    if config_path.exists():
        print(f"Existing configuration detected at {config_path}.")
        overwrite = _prompt_yes_no("Would you like to overwrite it with new defaults?", False)
        if overwrite:
            config = _collect_config(load_config(config_path))
            save_config(config, config_path)
        else:
            config = load_config(config_path)
    else:
        config = _collect_config()
        save_config(config, config_path)
    return config


def prompt_runtime_path(message: str, default: str | Path | None = None, *, allow_empty: bool = False) -> Path | None:
    default_str = str(default) if default else None
    response = _prompt_with_default(message, default_str, allow_empty=allow_empty)
    if response == "" and allow_empty:
        return None
    return Path(response).expanduser()


def prompt_runtime_yes_no(message: str, default: bool = False) -> bool:
    return _prompt_yes_no(message, default)


__all__ = [
    "ConfigurationError",
    "CONFIG_FILENAME",
    "ensure_config",
    "load_config",
    "save_config",
    "prompt_runtime_path",
    "prompt_runtime_yes_no",
]
