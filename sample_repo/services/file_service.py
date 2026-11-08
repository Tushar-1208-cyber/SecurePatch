import mimetypes
import pickle
from pathlib import Path

class FileService:
    ALLOWED_EXTENSIONS = {".pdf", ".txt", ".csv", ".json", ".png", ".jpg"}

    def inspect(self, filename):
        path = Path(filename)
        if not path.exists():
            raise FileNotFoundError(filename)

        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        return {
            "filename": path.name,
            "storage_path": str(path),
            "size": path.stat().st_size,
            "content_type": content_type,
        }

    def validate_extension(self, filename):
        return Path(filename).suffix.lower() in self.ALLOWED_EXTENSIONS

    def read_text(self, filename):
        path = Path(filename)
        if not self.validate_extension(filename):
            raise ValueError("Unsupported file extension")
        return path.read_text(encoding="utf-8")

    def load_legacy_data(self, filename):
        # Deliberate B301 vulnerability for SecurePatch.
        with open(filename, "rb") as handle:
            return pickle.load(handle)

    def save_text(self, filename, content):
        path = Path(filename)
        path.write_text(content, encoding="utf-8")
        return str(path)

    def delete(self, filename):
        path = Path(filename)
        if path.exists():
            path.unlink()
            return True
        return False
