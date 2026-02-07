# ================================
# Project: SolidCore Foundation future-
# Description:
# A rock-solid foundation for scalable and secure projects.
# Focused on creating robust, well-structured, and future-proof code.
# ================================

# ---------- main.py ----------
"""
Main entry point for the SolidCore Foundation.
"""

from core import security, infrastructure


def run():
    print("🧱 SolidCore Foundation Initialized")
    print("🔒 Secure | ⚙️ Scalable | 🧩 Future-Proof\n")

    # Demo: hashing + config system
    message = "Build strong code!"
    print(f"🔐 SHA256 Hash: {security.hash_text(message)}")
    print(f"⚙️ Config Loaded: {infrastructure.load_config()}")


if __name__ == "__main__":
    run()


# ---------- core/security.py ----------
"""
Security and data protection utilities.
Handles hashing, encryption, and safe validation logic.
"""

import hashlib

def hash_text(text: str) -> str:
    """Return a SHA-256 hash of the given text."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def validate_password_strength(password: str) -> bool:
    """
    Basic password strength validator.
    At least 8 chars, contains a digit and uppercase letter.
    """
    if len(password) < 8:
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(c.isupper() for c in password):
        return False
    return True


# ---------- core/infrastructure.py ----------
"""
Infrastructure and system-level utilities.
For managing configuration, logging, and scalability setup.
"""

import json
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / "config.json"

def load_config() -> dict:
    """Load a configuration file (or create default if missing)."""
    default_config = {
        "version": "1.0.0",
        "logging": True,
        "security_level": "high"
    }
    if not CONFIG_PATH.exists():
        save_config(default_config)
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

def save_config(config: dict):
    """Save configuration to JSON file."""
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=4)


# ---------- tests/test_security.py ----------
"""
Unit tests for security module.
Run with: pytest
"""

from core import security

def test_hash_text():
    assert isinstance(security.hash_text("hello"), str)
    assert len(security.hash_text("test")) == 64  # SHA256 length

def test_validate_password_strength():
    assert security.validate_password_strength("StrongPass1") is True
    assert security.validate_password_strength("weak") is False
