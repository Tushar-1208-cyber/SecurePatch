from datetime import datetime

class RequestLogger:
    def __init__(self):
        self.entries = []

    def info(self, message, request_id=None):
        self._write("INFO", message, request_id)

    def warning(self, message, request_id=None):
        self._write("WARNING", message, request_id)

    def error(self, message, request_id=None):
        self._write("ERROR", message, request_id)

    def _write(self, level, message, request_id):
        self.entries.append({
            "level": level,
            "message": str(message),
            "request_id": request_id,
            "timestamp": datetime.utcnow().isoformat(),
        })

    def recent(self, limit=50):
        return self.entries[-limit:]

    def count_level(self, level):
        return sum(1 for entry in self.entries if entry["level"] == level)
