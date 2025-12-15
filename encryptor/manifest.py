"""
Manifest loading, validation, and normalization.

This module answers one question:
    "What does the user want the tool to do?"

Responsibilities:
- Load the manifest YAML file
- Validate structure and version
- Normalize defaults
- Expose a clean Python representation

This module does NOT:
- Match files
- Encrypt or scramble data
- Walk the filesystem
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .config import SUPPORTED_MANIFEST_VERSION, DEFAULT_PROFILE


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class RuleConfig:
    include: str
    exclude: List[str] = field(default_factory=list)
    scramble: Optional[bool] = None
    encrypt: Optional[bool] = None
    chunk_size: Optional[int] = None


@dataclass
class ProfileConfig:
    name: str
    rules: List[RuleConfig]


@dataclass
class EncryptionConfig:
    algorithm: str = "AES-GCM"
    scramble: bool = True
    filename_obfuscation: bool = False


@dataclass
class Manifest:
    version: int
    encryption: EncryptionConfig
    profiles: Dict[str, ProfileConfig]

    # ------------------------------------------------------------------
    # Loading API
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path) -> "Manifest":
        """
        Load and validate a manifest file.

        Args:
            path: Path to the manifest YAML file

        Raises:
            RuntimeError: if the manifest is invalid

        Returns:
            Manifest
        """

        path = Path(path)
        if not path.exists():
            raise RuntimeError(f"Manifest file not found: {path}")

        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}

        return cls._from_dict(raw)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @classmethod
    def _from_dict(cls, data: Dict[str, Any]) -> "Manifest":
        version = data.get("version")
        if version != SUPPORTED_MANIFEST_VERSION:
            raise RuntimeError(
                f"Unsupported manifest version: {version}"
            )

        encryption_cfg = cls._parse_encryption(data.get("encryption", {}))
        profiles_cfg = cls._parse_profiles(data.get("profiles", {}))

        if DEFAULT_PROFILE not in profiles_cfg:
            raise RuntimeError(
                f"Default profile '{DEFAULT_PROFILE}' not defined in manifest"
            )

        return cls(
            version=version,
            encryption=encryption_cfg,
            profiles=profiles_cfg,
        )

    @staticmethod
    def _parse_encryption(data: Dict[str, Any]) -> EncryptionConfig:
        return EncryptionConfig(
            algorithm=data.get("algorithm", "AES-GCM"),
            scramble=bool(data.get("scramble", True)),
            filename_obfuscation=bool(data.get("filename_obfuscation", False)),
        )

    @staticmethod
    def _parse_profiles(data: Dict[str, Any]) -> Dict[str, ProfileConfig]:
        profiles: Dict[str, ProfileConfig] = {}

        for name, profile_data in data.items():
            rules_raw = profile_data.get("rules", [])
            if not rules_raw:
                raise RuntimeError(f"Profile '{name}' has no rules")

            rules: List[RuleConfig] = []
            for rule in rules_raw:
                if "include" not in rule:
                    raise RuntimeError(
                        f"Rule in profile '{name}' missing 'include'"
                    )

                rules.append(
                    RuleConfig(
                        include=rule["include"],
                        exclude=rule.get("exclude", []),
                        scramble=rule.get("scramble"),
                        encrypt=rule.get("encrypt"),
                        chunk_size=rule.get("chunk_size"),
                    )
                )

            profiles[name] = ProfileConfig(name=name, rules=rules)

        return profiles

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def get_profile(self, name: Optional[str] = None) -> ProfileConfig:
        """
        Return a profile by name, falling back to default.
        """

        name = name or DEFAULT_PROFILE
        try:
            return self.profiles[name]
        except KeyError:
            raise RuntimeError(f"Profile not found: {name}")
