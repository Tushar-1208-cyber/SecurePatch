from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

@dataclass
class Document:
    document_id: int
    owner_id: int
    filename: str
    storage_path: str
    size: int
    content_type: str
    status: str = "uploaded"
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def extension(self):
        return Path(self.filename).suffix.lower()

    def is_image(self):
        return self.content_type.startswith("image/")

    def is_archived(self):
        return self.status == "archived"

    def archive(self):
        self.status = "archived"
        self.updated_at = datetime.utcnow()

    def restore(self):
        self.status = "uploaded"
        self.updated_at = datetime.utcnow()

    def to_dict(self):
        return {
            "id": self.document_id,
            "owner_id": self.owner_id,
            "filename": self.filename,
            "storage_path": self.storage_path,
            "size": self.size,
            "content_type": self.content_type,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
