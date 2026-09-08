"""
WebAdminMapper - Advanced Path Generator Module
===============================================
Compiles, permutes, mutates, and streams directory paths and file extensions
for web administration discovery and structure mapping.

Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import sys
from pathlib import Path
from typing import Generator, List, Optional, Set

from .config import ScanConfig
from .wordlists import (
    ADMIN_LIST_PATH,
    CLOUD_LIST_PATH,
    COMMON_LIST_PATH,
    SENSITIVE_LIST_PATH,
)

__author__ = "Ahmed Wael"
__copyright__ = "Copyright (c) 2026, Ahmed Wael"


class PathGenerator:
    """
    High-performance path permutation, mutation, and generator engine.
    Authored and designed by Ahmed Wael.
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self._raw_words: List[str] = []
        self._load_words()

    def _read_file_lines(self, filepath: Path) -> List[str]:
        """Read sanitized non-empty, non-comment lines from a file."""
        lines: List[str] = []
        if not filepath.exists() or not filepath.is_file():
            return lines

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        lines.append(stripped)
        except Exception:
            pass
        return lines

    def _load_words(self) -> None:
        """Load candidate words from file, stdin, or curated dictionaries."""
        words: List[str] = []

        # 1. Custom Wordlist File or Stdin
        if self.config.wordlist_path:
            if self.config.wordlist_path == "-":
                # Read from standard input pipeline
                for line in sys.stdin:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        words.append(stripped)
            else:
                custom_path = Path(self.config.wordlist_path).expanduser().resolve()
                if not custom_path.exists():
                    raise FileNotFoundError(f"Specified wordlist not found: {custom_path}")
                words.extend(self._read_file_lines(custom_path))
        else:
            # 2. Curated Wordlist Categories
            wtype = self.config.wordlist_type.lower()
            if wtype in ("admin", "all"):
                words.extend(self._read_file_lines(ADMIN_LIST_PATH))
            if wtype in ("common", "all"):
                words.extend(self._read_file_lines(COMMON_LIST_PATH))
            if wtype in ("sensitive", "all"):
                words.extend(self._read_file_lines(SENSITIVE_LIST_PATH))
            if wtype in ("cloud", "all"):
                words.extend(self._read_file_lines(CLOUD_LIST_PATH))

        # Deduplicate while preserving order
        seen: Set[str] = set()
        deduped: List[str] = []
        for w in words:
            clean = w.strip()
            if clean and clean not in seen:
                seen.add(clean)
                deduped.append(clean)

        self._raw_words = deduped

    def generate(self, base_prefix: str = "") -> Generator[str, None, None]:
        """
        Generate candidate paths with prefix/suffix mutations, casing, and extensions.
        Authored by Ahmed Wael.
        """
        seen: Set[str] = set()
        extensions = [ext.strip().lstrip(".") for ext in self.config.extensions if ext.strip()]

        for word in self._raw_words:
            # Case mutations
            if self.config.case_transform == "lower":
                word = word.lower()
            elif self.config.case_transform == "upper":
                word = word.upper()
            elif self.config.case_transform == "title":
                word = word.title()

            # Prefix & Suffix application
            if self.config.prefix:
                word = f"{self.config.prefix}{word}"
            if self.config.suffix:
                word = f"{word}{self.config.suffix}"

            # Ensure clean slash formatting
            clean_word = word.lstrip("/")
            if base_prefix:
                clean_base = "/" + base_prefix.strip("/")
                candidate_base = f"{clean_base}/{clean_word}"
            else:
                candidate_base = "/" + clean_word

            # Base path
            if candidate_base not in seen:
                seen.add(candidate_base)
                yield candidate_base

            # If path ends with slash, also generate without slash
            if candidate_base.endswith("/"):
                no_slash = candidate_base.rstrip("/")
                if no_slash and no_slash not in seen:
                    seen.add(no_slash)
                    yield no_slash

            # Extension permutations
            has_ext = "." in candidate_base.split("/")[-1]
            is_dir = candidate_base.endswith("/")

            if extensions and not is_dir and not has_ext:
                for ext in extensions:
                    ext_path = f"{candidate_base}.{ext}"
                    if ext_path not in seen:
                        seen.add(ext_path)
                        yield ext_path

    def get_all_paths(self, base_prefix: str = "") -> List[str]:
        """Return all generated paths in memory."""
        return list(self.generate(base_prefix=base_prefix))

    def get_total_count(self, base_prefix: str = "") -> int:
        """Calculate total number of candidates."""
        return len(self.get_all_paths(base_prefix=base_prefix))
