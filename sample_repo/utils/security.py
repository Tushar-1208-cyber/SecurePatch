import hashlib
import hmac
import secrets
from datetime import datetime, timedelta

class PasswordHasher:
    def hash(self, password):
        salt = secrets.token_hex(16)
        digest = hashlib.sha256((salt + password).encode()).hexdigest()
        return f"{salt}${digest}"

    def verify(self, password, stored):
        if not stored or "$" not in stored:
            return False
        salt, expected = stored.split("$", 1)
        actual = hashlib.sha256((salt + password).encode()).hexdigest()
        return hmac.compare_digest(actual, expected)

class TokenManager:
    def __init__(self):
        self.tokens = {}

    def create(self, user_id, role):
        token = secrets.token_urlsafe(32)
        self.tokens[token] = {
            "user_id": user_id,
            "role": role,
            "expires": datetime.utcnow() + timedelta(hours=1),
        }
        return token

    def validate(self, token):
        data = self.tokens.get(token)
        if data is None:
            return None
        if data["expires"] <= datetime.utcnow():
            self.tokens.pop(token, None)
            return None
        return data

    def revoke(self, token):
        return self.tokens.pop(token, None) is not None
