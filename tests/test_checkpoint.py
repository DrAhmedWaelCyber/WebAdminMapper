"""
WebAdminMapper - Unit Tests for Session Checkpoint Module
=========================================================
Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import tempfile
import unittest
from web_mapper.checkpoint import SessionCheckpoint
from web_mapper.requester import ScanResult

__author__ = "Ahmed Wael"


class TestSessionCheckpoint(unittest.TestCase):

    def test_save_and_load_checkpoint(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            path = tf.name

        results = [
            ScanResult(path="/admin", url="https://example.com/admin", status_code=200, content_length=500, response_time_ms=12.0)
        ]
        completed = {"/admin", "/login", "/test"}

        SessionCheckpoint.save(
            filepath=path,
            target_url="https://example.com",
            completed_paths=completed,
            results=results,
            duration_sec=3.5,
        )

        loaded = SessionCheckpoint.load(path)
        self.assertEqual(loaded["metadata"]["target_url"], "https://example.com")
        self.assertEqual(loaded["metadata"]["total_completed"], 3)
        self.assertEqual(len(loaded["results"]), 1)
        self.assertEqual(loaded["results"][0]["path"], "/admin")


if __name__ == "__main__":
    unittest.main()
