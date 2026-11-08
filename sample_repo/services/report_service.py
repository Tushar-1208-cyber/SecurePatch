from services.user_service import UserService
from utils.database import UserRepository, DocumentRepository, AuditRepository

class ReportService:
    def __init__(self):
        self.users = UserService()
        self.user_repository = UserRepository()
        self.document_repository = DocumentRepository()
        self.audit_repository = AuditRepository()

    def build_user_report(self, user_id):
        user = self.users.get_user(user_id)
        if user is None:
            return {"error": "User not found"}

        documents = self.document_repository.for_user(user_id)
        return {
            "user": user.to_dict(),
            "document_count": len(documents),
            "documents": documents,
        }

    def system_summary(self):
        users = self.user_repository.all()
        documents = self.document_repository.all()
        return {
            "users": len(users),
            "active_users": sum(1 for user in users if user["active"]),
            "documents": len(documents),
            "archived_documents": sum(
                1 for document in documents
                if document["status"] == "archived"
            ),
        }

    def audit_summary(self):
        events = self.audit_repository.all()
        return {
            "events": len(events),
            "successful": sum(1 for event in events if event["success"]),
            "failed": sum(1 for event in events if not event["success"]),
        }
