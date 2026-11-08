from utils.database import UserRepository

class AuthMiddleware:
    def __init__(self):
        self.users = UserRepository()

    def require_user(self, user_id):
        user = self.users.find_by_id(user_id)
        if user is None or not user["active"]:
            raise PermissionError("Active user required")
        return user

    def require_admin(self, user_id):
        user = self.require_user(user_id)
        if user["role"] != "admin":
            raise PermissionError("Administrator role required")
        return user

    def require_manager(self, user_id):
        user = self.require_user(user_id)
        if user["role"] not in {"admin", "manager"}:
            raise PermissionError("Manager role required")
        return user

    def can_access_document(self, user_id, owner_id):
        user = self.require_user(user_id)
        return user["role"] == "admin" or user["id"] == owner_id
