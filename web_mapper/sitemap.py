"""
WebAdminMapper - Site Map & Structure Tree Visualizer
=====================================================
Constructs and renders hierarchical tree graphs of discovered endpoints,
administrative interfaces, and file paths.

Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

from typing import Dict, List, Optional

from .requester import ScanResult

__author__ = "Ahmed Wael"
__copyright__ = "Copyright (c) 2026, Ahmed Wael"


class SiteMapNode:
    """
    Represents an endpoint or directory node in the site hierarchy.
    Authored and designed by Ahmed Wael.
    """

    def __init__(self, name: str, full_path: str):
        self.name = name
        self.full_path = full_path
        self.result: Optional[ScanResult] = None
        self.children: Dict[str, "SiteMapNode"] = {}

    def get_or_create_child(self, name: str, child_full_path: str) -> "SiteMapNode":
        if name not in self.children:
            self.children[name] = SiteMapNode(name, child_full_path)
        return self.children[name]

    def to_dict(self) -> dict:
        """Serialize tree node to dictionary."""
        return {
            "name": self.name,
            "full_path": self.full_path,
            "status_code": self.result.status_code if self.result else None,
            "content_length": self.result.content_length if self.result else None,
            "title": self.result.title if self.result else None,
            "redirect": self.result.redirect_location if self.result else None,
            "children": [child.to_dict() for child in self.children.values()],
        }


class SiteMapTree:
    """
    Builds and renders interactive and ASCII structure maps.
    Authored and designed by Ahmed Wael.
    """

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.root = SiteMapNode(base_url, "/")

    def add_result(self, result: ScanResult) -> None:
        """Insert a ScanResult into the hierarchical tree."""
        clean = result.path.strip("/")
        if not clean:
            self.root.result = result
            return

        parts = clean.split("/")
        current = self.root
        accumulated = ""

        for part in parts:
            accumulated += f"/{part}"
            current = current.get_or_create_child(part, accumulated)

        current.result = result

    def render_ascii(self) -> str:
        """Render a formatted box-drawing ASCII tree representation."""
        lines = [f"\033[1m{self.base_url}\033[0m"]
        self._render_node_children(self.root, "", lines)
        return "\n".join(lines)

    def _render_node_children(self, node: SiteMapNode, prefix: str, lines: List[str]) -> None:
        child_items = sorted(node.children.values(), key=lambda n: n.name)
        count = len(child_items)

        for i, child in enumerate(child_items):
            is_last = (i == count - 1)
            connector = "└── " if is_last else "├── "
            child_prefix = "    " if is_last else "│   "

            # Format status and metadata
            meta = ""
            if child.result:
                r = child.result
                status_color = "\033[92m" if r.status_code < 300 else "\033[93m" if r.status_code < 500 else "\033[91m"
                meta = f" {status_color}[{r.status_code}]\033[0m ({r.content_length}B)"
                if r.redirect_location:
                    meta += f" -> \033[96m{r.redirect_location}\033[0m"
                if r.title:
                    meta += f' "\033[2m{r.title}\033[0m"'
            else:
                meta = " \033[2m[dir]\033[0m"

            lines.append(f"{prefix}{connector}{child.name}{meta}")
            self._render_node_children(child, prefix + child_prefix, lines)

    def count_nodes(self) -> int:
        """Count total endpoints and directories mapped."""
        def _count(node: SiteMapNode) -> int:
            return 1 + sum(_count(c) for c in node.children.values())
        return _count(self.root) - 1
