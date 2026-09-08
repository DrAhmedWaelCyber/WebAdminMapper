"""
WebAdminMapper - High-Performance Execution & Recursion Engine
==============================================================
Orchestrates worker threads, manages candidate priority queues, handles
recursive directory exploration, and builds the hierarchical site map.

Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import os
import sys
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Deque, List, Optional, Set, Tuple

from .config import ScanConfig
from .generator import PathGenerator
from .requester import HTTPRequester, ScanResult
from .sitemap import SiteMapTree

__author__ = "Ahmed Wael"
__copyright__ = "Copyright (c) 2026, Ahmed Wael"


class ExecutionEngine:
    """
    Multithreaded execution and recursive path discovery manager.
    Authored and designed by Ahmed Wael.
    """

    def __init__(self, config: ScanConfig, requester: HTTPRequester):
        self.config = config
        self.requester = requester
        self.generator = PathGenerator(config)
        self.sitemap = SiteMapTree(config.target_url)
        self.results: List[ScanResult] = []
        self.visited_paths: Set[str] = set()
        self.total_requests = 0
        self.start_time: float = 0.0
        self.interrupted: bool = False

    def run(
        self,
        on_result: Optional[Callable[[ScanResult], None]] = None,
        on_progress: Optional[Callable[[int, int, float, float, str, int], None]] = None,
        extra_seed_paths: Optional[Set[str]] = None,
        initial_completed_paths: Optional[Set[str]] = None,
        initial_results: Optional[List[ScanResult]] = None,
        checkpoint_path: Optional[str] = None,
    ) -> List[ScanResult]:
        """
        Execute the scan with concurrency, resumption, and dynamic route expansion.
        Authored by Ahmed Wael.
        """
        self.start_time = time.perf_counter()
        self.results = []
        self.visited_paths = set()
        self.total_requests = 0
        self.interrupted = False

        if initial_completed_paths:
            self.visited_paths.update(initial_completed_paths)

        if initial_results:
            self.results.extend(initial_results)
            for r in initial_results:
                self.sitemap.add_result(r)

        # Queue of tuples: (path_to_probe, recursion_depth, parent_dir)
        queue: Deque[Tuple[str, int, str]] = deque()

        # Seed root paths from generator
        initial_paths = self.generator.get_all_paths(base_prefix="")
        for p in initial_paths:
            if p not in self.visited_paths:
                queue.append((p, 0, ""))
                self.visited_paths.add(p)

        # Seed extra paths harvested from crawler (robots.txt, sitemap.xml)
        if extra_seed_paths:
            for ep in extra_seed_paths:
                clean_ep = "/" + ep.lstrip("/")
                if clean_ep not in self.visited_paths:
                    queue.append((clean_ep, 0, ""))
                    self.visited_paths.add(clean_ep)

        try:
            with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                # Process in batches to keep memory bounded and allow dynamic enqueuing
                while queue and not self.interrupted:
                    batch_size = min(len(queue), self.config.threads * 4)
                    current_batch: List[Tuple[str, int, str]] = [queue.popleft() for _ in range(batch_size)]

                    future_to_item = {
                        executor.submit(self.requester.probe_path, item[0]): item
                        for item in current_batch
                    }

                    for future in as_completed(future_to_item):
                        if self.interrupted:
                            break

                        self.total_requests += 1
                        path, depth, parent = future_to_item[future]

                        try:
                            res = future.result()
                        except Exception:
                            res = None

                        if res:
                            self.results.append(res)
                            self.sitemap.add_result(res)
                            if on_result:
                                on_result(res)

                            # Handle dynamic HTML in-scope link expansion
                            if res.discovered_links and depth < self.config.max_depth:
                                for dl in res.discovered_links:
                                    clean_dl = "/" + dl.lstrip("/")
                                    if clean_dl not in self.visited_paths:
                                        self.visited_paths.add(clean_dl)
                                        queue.append((clean_dl, depth + 1, res.path))

                            # Handle Recursive Directory Enqueuing
                            if self.config.recursive and depth < self.config.max_depth:
                                self._check_and_enqueue_recursive(res, depth, queue)

                        # Progress callback
                        if on_progress:
                            now = time.perf_counter()
                            elapsed = max(0.001, now - self.start_time)
                            speed = self.total_requests / elapsed
                            remaining = max(0, len(queue))
                            eta = remaining / speed if speed > 0 else 0.0
                            on_progress(
                                self.total_requests,
                                self.total_requests + remaining,
                                speed,
                                eta,
                                path,
                                len(self.results),
                            )

        except KeyboardInterrupt:
            self.interrupted = True
        finally:
            if checkpoint_path:
                from .checkpoint import SessionCheckpoint
                elapsed = time.perf_counter() - self.start_time
                SessionCheckpoint.save(
                    filepath=checkpoint_path,
                    target_url=self.config.target_url,
                    completed_paths=self.visited_paths,
                    results=self.results,
                    duration_sec=elapsed,
                )

        return self.results

    def _check_and_enqueue_recursive(
        self,
        res: ScanResult,
        current_depth: int,
        queue: Deque[Tuple[str, int, str]],
    ) -> None:
        """
        Evaluate if a discovered path qualifies as a directory for recursive exploration.
        Authored by Ahmed Wael.
        """
        # Only recurse into 200, 301, 302, 403
        if res.status_code not in (200, 204, 301, 302, 307, 401, 403):
            return

        clean_path = res.path.rstrip("/")
        # Skip recursion if path has obvious static file extensions
        static_exts = (".png", ".jpg", ".jpeg", ".gif", ".css", ".js", ".svg", ".ico", ".woff", ".ttf")
        if clean_path.lower().endswith(static_exts):
            return

        # Avoid re-recursing same path
        dir_marker = f"__rec_dir__{clean_path}"
        if dir_marker in self.visited_paths:
            return
        self.visited_paths.add(dir_marker)

        # Generate sub-paths for discovered directory
        sub_paths = self.generator.get_all_paths(base_prefix=clean_path)
        for sp in sub_paths:
            if sp not in self.visited_paths:
                self.visited_paths.add(sp)
                queue.append((sp, current_depth + 1, clean_path))
