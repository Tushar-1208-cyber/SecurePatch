import sys
from pathlib import Path
from urllib.parse import unquote

# Ensure project root is on sys.path so backend and src can be imported
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.main import app as fastapi_app

async def app(scope, receive, send):
    if scope.get("type") == "http":
        headers = dict(scope.get("headers", []))
        current_path = scope.get("path", "")
        
        # When Vercel rewrites /api/(.*) to /api/index.py, restore original requested path
        matched_path = headers.get(b"x-matched-path", b"").decode("utf-8", errors="ignore")
        forwarded_uri = headers.get(b"x-forwarded-uri", b"").decode("utf-8", errors="ignore")
        route_matches = headers.get(b"x-now-route-matches", b"").decode("utf-8", errors="ignore")
        
        chosen_path = None
        if matched_path and not matched_path.endswith("/index.py"):
            chosen_path = matched_path.split("?")[0]
        elif forwarded_uri and not forwarded_uri.endswith("/index.py"):
            chosen_path = forwarded_uri.split("?")[0]
        elif route_matches:
            for part in route_matches.split("&"):
                if part.startswith("1="):
                    sub = unquote(part[2:])
                    chosen_path = f"/api/{sub}" if not sub.startswith("/") else f"/api{sub}"
                    break
                    
        if chosen_path:
            scope["path"] = chosen_path

    await fastapi_app(scope, receive, send)
