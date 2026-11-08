from models.user import User
from utils.database import UserRepository

class UserService:
    def __init__(self):
        self.repository = UserRepository()

    def get_user(self, user_id):
        record = self.repository.find_by_id(user_id)
        return self._to_model(record) if record else None

    def search(self, query):
        records = self.repository.search(query)
        return [self._to_model(record) for record in records]

    def update_email(self, user_id, email):
        record = self.repository.find_by_id(user_id)
        if record is None:
            return None
        record["email"] = email
        self.repository.save(record)
        return self._to_model(record)

    def deactivate(self, user_id):
        record = self.repository.find_by_id(user_id)
        if record is None:
            return {"success": False, "error": "User not found"}
        record["active"] = False
        self.repository.save(record)
        return {"success": True}

    def reactivate(self, user_id):
        record = self.repository.find_by_id(user_id)
        if record is None:
            return {"success": False, "error": "User not found"}
        record["active"] = True
        self.repository.save(record)
        return {"success": True}

    def count_active(self):
        return sum(1 for record in self.repository.all() if record["active"])

    @staticmethod
    def _to_model(record):
        return User(
            record["id"],
            record["username"],
            record["email"],
            record["role"],
            record["active"],
            record.get("password_hash"),
        )
