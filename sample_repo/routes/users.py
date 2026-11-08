from services.user_service import UserService
from services.audit_service import AuditService
from utils.validators import validate_email, validate_user_id

class UserController:
    def __init__(self):
        self.service = UserService()
        self.audit = AuditService()

    def profile(self, user_id):
        validate_user_id(user_id)
        user = self.service.get_user(user_id)
        if user is None:
            return {"error": "User not found"}
        return user.public_profile()

    def search(self, query):
        if not isinstance(query, str):
            raise ValueError("Search query must be text")
        return [u.public_profile() for u in self.service.search(query)]

    def update_email(self, user_id, email):
        validate_user_id(user_id)
        validate_email(email)
        user = self.service.update_email(user_id, email)
        if user is None:
            return {"error": "User not found"}
        self.audit.record("EMAIL_UPDATE", str(user_id), "users", True)
        return user.public_profile()

    def deactivate(self, user_id):
        validate_user_id(user_id)
        result = self.service.deactivate(user_id)
        self.audit.record("USER_DEACTIVATE", str(user_id), "users", result["success"])
        return result

    def reactivate(self, user_id):
        validate_user_id(user_id)
        result = self.service.reactivate(user_id)
        self.audit.record("USER_REACTIVATE", str(user_id), "users", result["success"])
        return result
