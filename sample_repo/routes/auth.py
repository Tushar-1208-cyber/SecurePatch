from services.auth_service import AuthenticationService
from services.audit_service import AuditService
from utils.validators import validate_username

class AuthController:
    def __init__(self):
        self.service = AuthenticationService()
        self.audit = AuditService()

    def login(self, username, password):
        validate_username(username)
        user = self.service.authenticate(username, password)
        if user is None:
            self.audit.record("LOGIN_FAILED", username, "authentication", False)
            return {"success": False, "error": "Invalid credentials"}

        self.audit.record("LOGIN_SUCCESS", username, "authentication", True)
        return {
            "success": True,
            "user": user.public_profile(),
            "token": self.service.create_session(user),
        }

    def logout(self, username):
        self.audit.record("LOGOUT", username, "authentication", True)
        return {"success": True}

    def change_password(self, user_id, old_password, new_password):
        result = self.service.change_password(user_id, old_password, new_password)
        self.audit.record("PASSWORD_CHANGE", str(user_id), "authentication", result["success"])
        return result

    def refresh_session(self, token):
        return self.service.refresh_session(token)
