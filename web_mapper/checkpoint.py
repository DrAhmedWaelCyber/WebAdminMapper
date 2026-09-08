"""
WebAdminMapper - Session Checkpoint & Resumption Module
=======================================================
Manages session persistence, saving state checkpoints to disk, and
resuming interrupted directory exploration jobs.

Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .requester import ScanResult

__author__ = "Ahmed Wael"
__copyright__ = "Copyright (c) 2026, Ahmed Wael"


class SessionCheckpoint:
    """
    Manages saving and loading discovery session checkpoints.
    Authored and designed by Ahmed Wael.
    """

    @staticmethod
    def save(
        filepath: str,
        target_url: str,
        completed_paths: Set[str],
        results: List[ScanResult],
        duration_sec: float,
    ) -> Path:
        """Serialize current scan progress to disk."""
        p = Path(filepath).expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "metadata": {
                "author": __author__,
                "tool": "WebAdminMapper",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": round(duration_sec, 2),
                "target_url": target_url,
                "total_completed": len(completed_paths),
                "total_found": len(results),
            },
            "completed_paths": sorted(list(completed_paths)),
            "results": [r.to_dict() for r in results],
        }

        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return p

    @staticmethod
    def load(filepath: str) -> Dict[str, Any]:
        """Load session checkpoint from file."""
        p = Path(filepath).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(f"Checkpoint file not found: {p}")

        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)

        return data

    @staticmethod
    def deserialize_results(raw_results: List[Dict[str, Any]]) -> List[ScanResult]:
        """Reconstruct ScanResult objects from serialized dictionary items."""
        deserialized: List[ScanResult] = []
        for item in raw_results:
            clean = dict(item)
            clean.pop("author", None)
            # Backward-compatibility for any missing fields
            if "discovered_links" not in clean:
                clean["discovered_links"] = []
            deserialized.append(ScanResult(**clean))
        return deserialized

