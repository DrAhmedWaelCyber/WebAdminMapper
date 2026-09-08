"""
WebAdminMapper - Dedicated Integration Test Web Server
======================================================
Controlled multi-threaded HTTP test server providing precise endpoints
for verifying status code handling, redirects, soft-404 suppression,
wildcard detection, sensitive file detection, rate limiting, and recursive discovery.

Developer & Author: Ahmed Wael
Email: ahmedwael6143@gmail.com
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import argparse
import http.server
import io
import socket
import socketserver
import sys
import threading
import time
import urllib.request
from typing import Optional, Tuple

__author__ = "Ahmed Wael"
__version__ = "1.1.0"


class IntegrationTestHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP request handler serving controlled endpoints for WebAdminMapper integration tests.
    Authored and designed by Ahmed Wael.
    """

    server_version = "WebAdminMapperTestServer/1.1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        """Suppress standard logging to keep test output clean."""
        pass

    def do_GET(self):
        url_path = self.path.split("?")[0]

        # 1. Successful 200 endpoint
        if url_path in ("/test-200", "/status-200", "/page200"):
            body = b"<html><head><title>Test Success Page</title></head><body>Welcome to the test 200 OK endpoint.</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", "WebAdminMapper-MockServer/1.1")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        # 2. Permanent Redirect 301
        elif url_path == "/test-301":
            self.send_response(301)
            self.send_header("Location", "/test-200")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

        # 3. Temporary Redirect 302
        elif url_path in ("/test-302", "/redirect"):
            self.send_response(302)
            self.send_header("Location", "/admin")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

        # 4. Forbidden 403
        elif url_path == "/test-403":
            body = b"Access Denied: Administrative policy forbids public access."
            self.send_response(403)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        # 5. Explicit 404 Not Found
        elif url_path == "/test-404":
            body = b"Endpoint not found on this server."
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        # 6. Server Error 500
        elif url_path == "/test-500":
            body = b"Internal Server Error: Database Connection Failed Traceback (most recent call last):\n  File 'app.py', line 42 in query\nOperationalError: connection refused"
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        # 7. Soft-404 Custom Error Page (HTTP 200 with 'Not Found' error text)
        elif url_path in ("/soft-404", "/soft404-page") or url_path.startswith("/_wm_probe_"):
            body = b"<html><head><title>Page Not Found</title></head><body><h1>404 Error</h1><p>The document you requested does not exist on this server. Error code: ERR_NOT_FOUND_99182</p></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        # 8. Wildcard application handler
        elif url_path.startswith("/wildcard"):
            body = b"<html><head><title>Catch-All Application Router</title></head><body>Standard single page application shell. Route resolved dynamically.</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        # 9. Slow endpoint for timeout and latency measurement
        elif url_path == "/slow":
            time.sleep(0.35)
            body = b"Slow response successfully delivered after artificial delay."
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        # 10. Unprotected Admin Portal
        elif url_path == "/admin":
            body = b"<html><head><title>Administrative Control Panel</title></head><body><h1>Superuser Dashboard</h1><p>Welcome Administrator</p></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        # 11. Sensitive .env file
        elif url_path == "/.env":
            body = b"DB_HOST=127.0.0.1\nDB_USER=root\nDB_PASS=SuperSecretP@ssw0rd!2026\nAWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        # 12. Sensitive .git/config
        elif url_path == "/.git/config":
            body = b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote \"origin\"]\n\turl = git@github.com:Company/internal-secrets.git\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        # 13. Recursive directory discovery hierarchy
        elif url_path == "/dir":
            body = b"<html><head><title>Directory Index</title></head><body><a href='/dir/secret'>secret</a><a href='/dir/sub'>sub</a></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        elif url_path == "/dir/secret":
            body = b"Confidential nested resource reached through directory recursion."
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        # Root probe
        elif url_path in ("", "/"):
            body = b"<html><head><title>WebAdminMapper Integration Server</title></head><body>WebAdminMapper Test Suite Root</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", "WebAdminMapper-MockServer/1.1")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        # Default 404 for non-existent routes
        else:
            body = b"Not Found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Multi-threaded test server for concurrent scan verification."""
    daemon_threads = True
    allow_reuse_address = True


def start_local_test_server(port: int = 0) -> Tuple[ThreadedHTTPServer, threading.Thread, str]:
    """
    Launch the integration test server on loopback interface.

    :param port: TCP port to bind (0 = automatically choose free ephemeral port).
    :return: (server_instance, server_thread, base_url)
    """
    server = ThreadedHTTPServer(("127.0.0.1", port), IntegrationTestHandler)
    server_port = server.server_port
    base_url = f"http://127.0.0.1:{server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, base_url


class SocketPairHTTPConnection(http.client.HTTPConnection):
    """
    HTTP connection communicating directly via a local socketpair.
    Bypasses restricted loopback network sandboxes while maintaining real
    HTTP wire serialization, header formatting, and protocol parsing.
    Authored by Ahmed Wael.
    """

    def __init__(self, handler_cls, host: str, port: Optional[int] = None, timeout: float = 10.0, **kwargs):
        super().__init__(host, port=port, timeout=timeout, **kwargs)
        self.handler_cls = handler_cls

    def connect(self) -> None:
        s_server, s_client = socket.socketpair()
        self.sock = s_client
        if self.timeout is not None:
            self.sock.settimeout(self.timeout)

        def run_handler():
            try:
                self.handler_cls(s_server, ("127.0.0.1", 12345), None)
            except (ConnectionError, OSError, ValueError):
                pass
            finally:
                try:
                    s_server.close()
                except (OSError, ValueError):
                    pass

        worker = threading.Thread(target=run_handler, daemon=True)
        worker.start()


class LocalTestServerHTTPHandler(urllib.request.HTTPHandler):
    """urllib HTTPHandler bridging requests directly into IntegrationTestHandler."""

    def __init__(self, handler_cls=IntegrationTestHandler):
        super().__init__()
        self.handler_cls = handler_cls

    def http_open(self, req: urllib.request.Request):
        return self.do_open(
            lambda host, **kwargs: SocketPairHTTPConnection(self.handler_cls, host, **kwargs),
            req,
        )


def create_test_opener(
    handler_cls=IntegrationTestHandler,
    follow_redirects: bool = False,
) -> urllib.request.OpenerDirector:
    """Construct an OpenerDirector pre-configured to communicate with the local test handler."""
    from web_mapper.requester import NoRedirectHandler

    handlers = [LocalTestServerHTTPHandler(handler_cls)]
    if not follow_redirects:
        handlers.append(NoRedirectHandler())
    return urllib.request.build_opener(*handlers)


def stop_local_test_server(server: ThreadedHTTPServer, thread: threading.Thread) -> None:
    """Shut down and clean up test server resources."""
    try:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
    except (OSError, ValueError):
        pass


def main():
    parser = argparse.ArgumentParser(description="WebAdminMapper Integration Test Server")
    parser.add_argument("--port", type=int, default=8888, help="Port to bind (default: 8888)")
    args = parser.parse_args()

    print(f"[*] Starting WebAdminMapper Test Server on http://127.0.0.1:{args.port}...")
    server = ThreadedHTTPServer(("127.0.0.1", args.port), IntegrationTestHandler)
    try:
        print("[+] Test server active. Press Ctrl+C to terminate.")
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping test server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
