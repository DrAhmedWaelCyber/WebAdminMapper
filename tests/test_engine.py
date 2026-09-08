"""
WebAdminMapper - Unit Tests for ExecutionEngine Module
======================================================
Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from web_mapper.checkpoint import SessionCheckpoint
from web_mapper.config import ScanConfig
from web_mapper.engine import ExecutionEngine
from web_mapper.requester import HTTPRequester, ScanResult

__author__ = "Ahmed Wael"


class TestExecutionEngine(unittest.TestCase):

    def test_engine_resumption_and_link_crawling(self):
        config = ScanConfig(target_url="https://example.com", threads=2, recursive=False)
        mock_requester = MagicMock(spec=HTTPRequester)

        def mock_probe(path: str):
            if path == "/admin":
                return ScanResult(
                    path="/admin",
                    url="https://example.com/admin",
                    status_code=200,
                    content_length=500,
                    response_time_ms=10.0,
                    discovered_links=["/custom_internal_panel", "/secret_api_endpoint"],
                )
            elif path in ("/custom_internal_panel", "/secret_api_endpoint"):
                return ScanResult(
                    path=path,
                    url=f"https://example.com{path}",
                    status_code=200,
                    content_length=300,
                    response_time_ms=8.0,
                )
            return None

        mock_requester.probe_path.side_effect = mock_probe
        engine = ExecutionEngine(config, mock_requester)

        # Seed with initial completed paths (so generator paths are skipped except /admin)
        all_gen = set(engine.generator.get_all_paths())
        initial_completed = all_gen - {"/admin"}

        results = engine.run(
            initial_completed_paths=initial_completed,
            extra_seed_paths={"/admin"},
        )

        # Discovered links from /admin should have been enqueued and found
        found_paths = {r.path for r in results}
        self.assertIn("/admin", found_paths)
        self.assertIn("/custom_internal_panel", found_paths)
        self.assertIn("/secret_api_endpoint", found_paths)

    def test_engine_checkpoint_saving(self):
        config = ScanConfig(target_url="https://example.com", threads=2)
        mock_requester = MagicMock(spec=HTTPRequester)
        mock_requester.probe_path.return_value = None

        engine = ExecutionEngine(config, mock_requester)

        with tempfile.TemporaryDirectory() as tmpdir:
            chk_path = Path(tmpdir) / "test_session.json"
            engine.run(checkpoint_path=str(chk_path))

            self.assertTrue(chk_path.exists())
            loaded = SessionCheckpoint.load(str(chk_path))
            self.assertEqual(loaded["metadata"]["target_url"], "https://example.com")
            self.assertTrue(len(loaded["completed_paths"]) > 0)


if __name__ == "__main__":
    unittest.main()
