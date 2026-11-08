import json
from datetime import datetime

def utc_timestamp():
    return datetime.utcnow().isoformat()

def safe_json(data):
    return json.dumps(data, default=str, sort_keys=True)

def paginate(items, page=1, size=20):
    page = max(1, int(page))
    size = max(1, int(size))
    start = (page - 1) * size
    return items[start:start + size]

def chunk(items, size):
    if size <= 0:
        raise ValueError("Chunk size must be positive")
    for start in range(0, len(items), size):
        yield items[start:start + size]

def normalize_text(value):
    return " ".join(str(value).strip().split())

def merge_dicts(left, right):
    result = dict(left)
    result.update(right)
    return result
