"""
WebAdminMapper - Curated Wordlists Package
==========================================
Provides curated wordlists for web administration, directory mapping,
and file structure discovery.

Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

from pathlib import Path

__author__ = "Ahmed Wael"
__copyright__ = "Copyright (c) 2026, Ahmed Wael"

WORDLISTS_DIR = Path(__file__).resolve().parent

ADMIN_LIST_PATH = WORDLISTS_DIR / "admin_paths.txt"
COMMON_LIST_PATH = WORDLISTS_DIR / "common_dirs.txt"
SENSITIVE_LIST_PATH = WORDLISTS_DIR / "sensitive_files.txt"
CLOUD_LIST_PATH = WORDLISTS_DIR / "cloud_devops.txt"
