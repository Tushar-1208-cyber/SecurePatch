from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass
class User:
    user_id: int
    username: str
    email: str
    role: str = "user"
    active: bool = True
    password_hash: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None

    def is_admin(self):
        return self.role == "admin"

    def can_manage_documents(self):
        return self.role in {"admin", "manager"}

    def deactivate(self):
        self.active = False

    def activate(self):
        self.active = True

    def mark_login(self):
        self.last_login = datetime.utcnow()

    def to_dict(self):
        return {
            "id": self.user_id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "active": self.active,
            "created_at": self.created_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }

    def public_profile(self):
        return {
            "id": self.user_id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
        }
