from models.document import Document
from utils.database import DocumentRepository
from utils.validators import validate_document_size

class DocumentService:
    def __init__(self):
        self.repository = DocumentRepository()

    def create(self, owner_id, metadata):
        validate_document_size(metadata["size"])
        document = Document(
            self.repository.next_id(),
            owner_id,
            metadata["filename"],
            metadata["storage_path"],
            metadata["size"],
            metadata["content_type"],
        )
        self.repository.save(document.to_dict())
        return document.to_dict()

    def list_for_user(self, user_id):
        records = self.repository.for_user(user_id)
        return [self._model(record) for record in records]

    def import_records(self, owner_id, records):
        created = []
        for record in records:
            metadata = {
                "filename": record.get("filename", "imported.bin"),
                "storage_path": record.get("storage_path", ""),
                "size": record.get("size", 0),
                "content_type": record.get("content_type", "application/octet-stream"),
            }
            created.append(self.create(owner_id, metadata))
        return created

    def archive(self, user_id, document_id):
        return self._change_status(user_id, document_id, "archived")

    def restore(self, user_id, document_id):
        return self._change_status(user_id, document_id, "uploaded")

    def find(self, document_id):
        record = self.repository.find(document_id)
        return self._model(record) if record else None

    def _change_status(self, user_id, document_id, status):
        record = self.repository.find(document_id)
        if record is None or record["owner_id"] != user_id:
            return {"success": False, "error": "Document not found"}

        record["status"] = status
        self.repository.save(record)
        return {"success": True, "status": status}

    @staticmethod
    def _model(record):
        return Document(
            record["id"],
            record["owner_id"],
            record["filename"],
            record["storage_path"],
            record["size"],
            record["content_type"],
            record["status"],
        )
