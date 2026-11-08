from services.document_service import DocumentService
from services.file_service import FileService
from services.audit_service import AuditService
from utils.validators import validate_user_id

class DocumentController:
    def __init__(self):
        self.documents = DocumentService()
        self.files = FileService()
        self.audit = AuditService()

    def upload(self, user_id, path):
        validate_user_id(user_id)
        metadata = self.files.inspect(path)
        document = self.documents.create(user_id, metadata)
        self.audit.record("DOCUMENT_UPLOAD", str(user_id), str(document["id"]), True)
        return document

    def import_legacy(self, user_id, path):
        validate_user_id(user_id)
        records = self.files.load_legacy_data(path)
        documents = self.documents.import_records(user_id, records)
        self.audit.record("LEGACY_IMPORT", str(user_id), path, True)
        return documents

    def list_documents(self, user_id):
        validate_user_id(user_id)
        return [doc.to_dict() for doc in self.documents.list_for_user(user_id)]

    def archive(self, user_id, document_id):
        result = self.documents.archive(user_id, document_id)
        self.audit.record("DOCUMENT_ARCHIVE", str(user_id), str(document_id), result["success"])
        return result

    def restore(self, user_id, document_id):
        result = self.documents.restore(user_id, document_id)
        self.audit.record("DOCUMENT_RESTORE", str(user_id), str(document_id), result["success"])
        return result
