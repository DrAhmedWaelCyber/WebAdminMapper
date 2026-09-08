"""
WebAdminMapper - Soft-404 & Heuristic Engine Validation Suite
=============================================================
Systematically benchmarks and validates the heuristic engine against:
  1. Standard 404 Not Found responses
  2. Dynamic Soft-404 error templates returning HTTP 200
  3. Single-Page-App (SPA) / Wildcard catch-all routes
  4. Legitimate content pages sharing structural layout

Measures:
  - True Positives (TP)
  - False Positives (FP)
  - True Negatives (TN)
  - False Negatives (FN)
  - Precision, Recall, Specificity, Accuracy
  - Jaccard token similarity metrics

Developer & Author: Ahmed Wael
Email: ahmedwael6143@gmail.com
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import unittest
from typing import Dict, List, Tuple
from web_mapper.heuristics import (
    Soft404Detector,
    compute_token_set,
    compute_words_and_lines,
    jaccard_similarity,
)

__author__ = "Ahmed Wael"


class TestHeuristicValidationSuite(unittest.TestCase):
    """Rigorous evaluation of heuristic engine precision and false positive rates."""

    def setUp(self):
        self.detector = Soft404Detector()

        # Seed baseline 1: Standard generic soft-404 error page returning HTTP 200
        self.soft404_baseline_body = (
            b"<!DOCTYPE html><html><head><title>Page Not Found - System Portal</title></head>"
            b"<body><div class='error-box'><h1>404 Not Found</h1>"
            b"<p>The requested URL was not found on this server. Incident ID: ERR-100293</p>"
            b"<footer>Copyright (c) 2026 Portal System. All rights reserved.</footer></div></body></html>"
        )
        self.detector.add_baseline(
            status_code=200,
            body=self.soft404_baseline_body,
            title="Page Not Found - System Portal",
        )

        # Seed baseline 2: SPA Wildcard router shell returning HTTP 200
        self.wildcard_baseline_body = (
            b"<!DOCTYPE html><html><head><title>App Router Shell</title></head>"
            b"<body><div id='root'>Loading application router components... Please wait.</div>"
            b"<script src='/static/js/bundle.js'></script></body></html>"
        )
        self.detector.add_baseline(
            status_code=200,
            body=self.wildcard_baseline_body,
            title="App Router Shell",
        )

    def test_normal_404_handling(self):
        """Verify normal 404 responses are NOT misidentified as soft-404s."""
        body = b"404 Not Found: Resource does not exist on origin."
        is_soft, sim, reason = self.detector.evaluate(
            status_code=404,
            content_length=len(body),
            body_sample=body,
            title=None,
        )
        self.assertFalse(is_soft, "Normal 404 status must not trigger soft-404 suppression")
        self.assertEqual(reason, "distinct_legitimate_content")

    def test_soft_404_detection_with_dynamic_tokens(self):
        """Verify soft-404 error pages with dynamic IDs or timestamps are detected."""
        dynamic_bodies = [
            # Different incident ID
            b"<!DOCTYPE html><html><head><title>Page Not Found - System Portal</title></head>"
            b"<body><div class='error-box'><h1>404 Not Found</h1>"
            b"<p>The requested URL was not found on this server. Incident ID: ERR-887123</p>"
            b"<footer>Copyright (c) 2026 Portal System. All rights reserved.</footer></div></body></html>",
            # Slight whitespace or micro timestamp delta
            b"<!DOCTYPE html><html><head><title>Page Not Found - System Portal</title></head>"
            b"<body><div class='error-box'><h1>404 Not Found</h1>"
            b"<p>The requested URL was not found on this server. Incident ID: ERR-994102  </p>"
            b"<footer>Copyright (c) 2026 Portal System. All rights reserved.</footer></div></body></html>",
        ]

        for sample in dynamic_bodies:
            is_soft, sim, reason = self.detector.evaluate(
                status_code=200,
                content_length=len(sample),
                body_sample=sample,
                title="Page Not Found - System Portal",
            )
            self.assertTrue(is_soft, f"Dynamic soft-404 should be suppressed (Reason: {reason})")
            self.assertGreaterEqual(sim, 0.85, f"Similarity should be high for soft-404 (Got: {sim})")

    def test_wildcard_application_routes(self):
        """Verify dynamic SPA / wildcard catch-all routes returning 200 are detected."""
        wildcard_queries = [
            b"<!DOCTYPE html><html><head><title>App Router Shell</title></head>"
            b"<body><div id='root'>Loading application router components... Please wait.</div>"
            b"<script src='/static/js/bundle.js'></script></body></html>",
            b"<!DOCTYPE html><html><head><title>App Router Shell</title></head>"
            b"<body><div id='root'>Loading application router components... Please wait. </div>"
            b"<script src='/static/js/bundle.js'></script></body></html>",
        ]

        for sample in wildcard_queries:
            is_soft, sim, reason = self.detector.evaluate(
                status_code=200,
                content_length=len(sample),
                body_sample=sample,
                title="App Router Shell",
            )
            self.assertTrue(is_soft, f"Wildcard application route must be suppressed (Reason: {reason})")

    def test_legitimate_similar_pages_not_misclassified(self):
        """
        Verify legitimate pages sharing footer/header boilerplate are NOT misclassified as soft-404.
        Ensures Zero False Positives on valid application features.
        """
        legitimate_pages = [
            # Legitimate admin dashboard
            (
                b"<!DOCTYPE html><html><head><title>Administration Dashboard - System Portal</title></head>"
                b"<body><div class='main-container'><h1>Superuser Administrative Portal</h1>"
                b"<p>Metrics: CPU 12%, Memory 45%. Active Sessions: 18 users.</p>"
                b"<table><tr><th>User</th><th>Role</th></tr><tr><td>admin</td><td>Superuser</td></tr></table>"
                b"<footer>Copyright (c) 2026 Portal System. All rights reserved.</footer></div></body></html>",
                "Administration Dashboard - System Portal",
            ),
            # Legitimate user profile
            (
                b"<!DOCTYPE html><html><head><title>User Profile - System Portal</title></head>"
                b"<body><div class='profile-card'><h1>User Profile Settings</h1>"
                b"<form><input name='email' value='user@example.com'><input type='submit'></form>"
                b"<footer>Copyright (c) 2026 Portal System. All rights reserved.</footer></div></body></html>",
                "User Profile - System Portal",
            ),
            # Legitimate API status
            (
                b"{\"status\":\"ok\",\"service\":\"authentication-gateway\",\"uptime_seconds\":91823,\"healthy\":true}",
                None,
            ),
        ]

        for body, title in legitimate_pages:
            is_soft, sim, reason = self.detector.evaluate(
                status_code=200,
                content_length=len(body),
                body_sample=body,
                title=title,
            )
            self.assertFalse(is_soft, f"Legitimate page must NOT be suppressed (Title: {title}, Reason: {reason})")
            self.assertLess(sim, 0.85, f"Similarity should remain below threshold for distinct content (Got: {sim})")

    def test_statistical_confusion_matrix_and_accuracy(self):
        """
        Generate a multi-sample statistical benchmark dataset to compute:
        True Positives, False Positives, True Negatives, False Negatives,
        Precision, Recall, and Overall Accuracy.
        """
        # 10 Soft-404 variants (Ground Truth: Positive = Soft-404)
        positive_samples: List[Tuple[int, bytes, str]] = []
        for i in range(10):
            body = (
                f"<!DOCTYPE html><html><head><title>Page Not Found - System Portal</title></head>"
                f"<body><div class='error-box'><h1>404 Not Found</h1>"
                f"<p>The requested URL was not found on this server. Incident ID: ERR-{900000 + i}</p>"
                f"<footer>Copyright (c) 2026 Portal System. All rights reserved.</footer></div></body></html>"
            ).encode("utf-8")
            positive_samples.append((200, body, "Page Not Found - System Portal"))

        # 10 Legitimate distinct pages (Ground Truth: Negative = Legitimate)
        negative_samples: List[Tuple[int, bytes, str]] = []
        for i in range(10):
            body = (
                f"<!DOCTYPE html><html><head><title>Catalog Category {i} - System Portal</title></head>"
                f"<body><div class='catalog-grid'><h1>Product Category #{i}</h1>"
                f"<p>Viewing detailed specifications for product SKU-{i * 77 + 104}. Price: ${i * 15 + 10}.99</p>"
                f"<button>Add to Cart</button>"
                f"<footer>Copyright (c) 2026 Portal System. All rights reserved.</footer></div></body></html>"
            ).encode("utf-8")
            negative_samples.append((200, body, f"Catalog Category {i} - System Portal"))

        # Add 5 standard HTTP 404 responses (Ground Truth: Negative = Not Soft-404)
        for i in range(5):
            body = f"Not Found: Invalid path endpoint {i}".encode("utf-8")
            negative_samples.append((404, body, None))

        tp = 0
        fn = 0
        fp = 0
        tn = 0

        soft_similarities: List[float] = []
        legit_similarities: List[float] = []

        # Evaluate positives (True Soft-404s)
        for status, body, title in positive_samples:
            is_soft, sim, _ = self.detector.evaluate(status, len(body), body, title)
            soft_similarities.append(sim)
            if is_soft:
                tp += 1
            else:
                fn += 1

        # Evaluate negatives (True Legitimate Content)
        for status, body, title in negative_samples:
            is_soft, sim, _ = self.detector.evaluate(status, len(body), body, title)
            legit_similarities.append(sim)
            if is_soft:
                fp += 1
            else:
                tn += 1

        total = tp + fn + fp + tn
        accuracy = (tp + tn) / total
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0

        avg_soft_sim = sum(soft_similarities) / len(soft_similarities)
        avg_legit_sim = sum(legit_similarities) / len(legit_similarities)

        # Assert zero false positives and high accuracy
        self.assertEqual(fp, 0, f"Expected 0 False Positives, got {fp}")
        self.assertEqual(fn, 0, f"Expected 0 False Negatives, got {fn}")
        self.assertEqual(tp, len(positive_samples))
        self.assertEqual(tn, len(negative_samples))
        self.assertEqual(accuracy, 1.0, f"Accuracy must be 100% on controlled test sets (Got {accuracy})")
        self.assertEqual(precision, 1.0)
        self.assertEqual(recall, 1.0)
        self.assertGreater(avg_soft_sim, 0.90)
        self.assertLess(avg_legit_sim, 0.70)


if __name__ == "__main__":
    unittest.main()
