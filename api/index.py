import mimetypes
from pathlib import Path
import sys
from urllib.parse import parse_qs, unquote

# Ensure project root is on sys.path so backend and src can be imported
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.main import app as fastapi_app

DIST_DIR = ROOT_DIR / "frontend" / "dist"

# Pre-cache static frontend assets in memory for zero disk I/O and instant responses
STATIC_CACHE = {}
if DIST_DIR.is_dir():
    for f in DIST_DIR.rglob("*"):
        if f.is_file():
            rel_path = f.relative_to(DIST_DIR).as_posix()
            mime_type = mimetypes.guess_type(str(f))[0] or "application/octet-stream"
            if mime_type.startswith("text/") or mime_type in ("image/svg+xml", "application/javascript"):
                content_type = f"{mime_type}; charset=utf-8"
            else:
                content_type = mime_type
            STATIC_CACHE[rel_path] = (f.read_bytes(), content_type)

INDEX_HTML = STATIC_CACHE.get("index.html")


async def serve_static(send, data: bytes, content_type: str, status: int = 200):
    cache_control = (
        b"public, max-age=31536000, immutable"
        if "assets/" in content_type
        else b"public, max-age=0, must-revalidate"
    )
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            [b"content-type", content_type.encode("utf-8")],
            [b"content-length", str(len(data)).encode("utf-8")],
            [b"cache-control", cache_control],
        ],
    })
    await send({
        "type": "http.response.body",
        "body": data,
        "more_body": False,
    })


async def app(scope, receive, send):
    if scope.get("type") == "http":
        query_string = scope.get("query_string", b"").decode("utf-8", errors="ignore")
        headers = dict(scope.get("headers", []))

        # 1. Handle static assets and SPA routes via __static__ param
        if "__static__=" in query_string:
            qs = parse_qs(query_string)
            static_req = qs.get("__static__", [""])[0].strip("/")

            # Direct static file hit (assets, favicon, icons, etc.)
            if static_req in STATIC_CACHE:
                data, ctype = STATIC_CACHE[static_req]
                await serve_static(send, data, ctype)
                return

            # Client-side SPA routing fallback (returns index.html)
            if INDEX_HTML:
                data, ctype = INDEX_HTML
                await serve_static(send, data, ctype)
                return

        # 2. Handle API routes via __path__ param
        if "__path__=" in query_string:
            qs = parse_qs(query_string)
            api_path = qs.get("__path__", [""])[0].lstrip("/")
            scope["path"] = f"/api/{api_path}" if api_path else "/api"

            # Clean __path__ parameter from query_string for FastAPI endpoints
            remaining = [
                p for p in query_string.split("&") if not p.startswith("__path__=")
            ]
            scope["query_string"] = "&".join(remaining).encode("utf-8")
        else:
            # Fallback header unwrap if called directly without query rewrite
            matched_path = headers.get(b"x-matched-path", b"").decode("utf-8", errors="ignore")
            if matched_path and not matched_path.endswith("/index.py"):
                scope["path"] = matched_path.split("?")[0]

    await fastapi_app(scope, receive, send)
