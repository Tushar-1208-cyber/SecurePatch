from models.user import User
from utils.database import UserRepository
from utils.security import PasswordHasher, TokenManager

class AuthenticationService:
    def __init__(self):
        self.users = UserRepository()
        self.hasher = PasswordHasher()
        self.tokens = TokenManager()

    def authenticate(self, username, password):
        record = self.users.find_by_username(username)
        if not record or not record["active"]:
            return None

        if password == record["password"]:
            user = self._model(record)
            user.mark_login()
            return user

        if self.hasher.verify(password, record.get("password_hash", "")):
            user = self._model(record)
            user.mark_login()
            return user

        return None

    def create_session(self, user):
        return self.tokens.create(user.user_id, user.role)

    def refresh_session(self, token):
        data = self.tokens.validate(token)
        if data is None:
            return {"success": False, "error": "Expired token"}
        return {"success": True, "token": self.tokens.create(data["user_id"], data["role"])}

    def change_password(self, user_id, old_password, new_password):
        record = self.users.find_by_id(user_id)
        if record is None:
            return {"success": False, "error": "User not found"}

        current = self.authenticate(record["username"], old_password)
        if current is None:
            return {"success": False, "error": "Old password is incorrect"}

        record["password_hash"] = self.hasher.hash(new_password)
        record["password"] = ""
        self.users.save(record)
        return {"success": True}

    @staticmethod
    def _model(record):
        return User(
            record["id"],
            record["username"],
            record["email"],
            record["role"],
            record["active"],
            record.get("password_hash"),
        )
