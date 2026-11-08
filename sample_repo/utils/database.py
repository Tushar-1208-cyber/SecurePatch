from copy import deepcopy

USERS = [
    {
        "id": 1,
        "username": "admin",
        "email": "admin@example.com",
        "role": "admin",
        "active": True,
        "password": "admin123",
        "password_hash": "",
    },
    {
        "id": 2,
        "username": "demo_user",
        "email": "user@example.com",
        "role": "user",
        "active": True,
        "password": "user123",
        "password_hash": "",
    },
    {
        "id": 3,
        "username": "analyst",
        "email": "analyst@example.com",
        "role": "manager",
        "active": True,
        "password": "analyst123",
        "password_hash": "",
    },
]

DOCUMENTS = [
    {
        "id": 1,
        "owner_id": 2,
        "filename": "profile.pdf",
        "storage_path": "storage/uploads/profile.pdf",
        "size": 12000,
        "content_type": "application/pdf",
        "status": "uploaded",
    },
    {
        "id": 2,
        "owner_id": 2,
        "filename": "notes.txt",
        "storage_path": "storage/uploads/notes.txt",
        "size": 5000,
        "content_type": "text/plain",
        "status": "archived",
    },
]

AUDIT_EVENTS = []

class UserRepository:
    def find_by_id(self, user_id):
        return deepcopy(next((u for u in USERS if u["id"] == user_id), None))

    def find_by_username(self, username):
        return deepcopy(next((u for u in USERS if u["username"] == username), None))

    def search(self, query):
        value = query.lower()
        matches = [
            user for user in USERS
            if value in user["username"].lower()
            or value in user["email"].lower()
        ]
        return deepcopy(matches)

    def save(self, record):
        for index, user in enumerate(USERS):
            if user["id"] == record["id"]:
                USERS[index] = deepcopy(record)
                return

    def all(self):
        return deepcopy(USERS)

    def count(self):
        return len(USERS)

class DocumentRepository:
    def next_id(self):
        return max((d["id"] for d in DOCUMENTS), default=0) + 1

    def find(self, document_id):
        record = next(
            (d for d in DOCUMENTS if d["id"] == document_id),
            None,
        )
        return deepcopy(record)

    def for_user(self, user_id):
        return deepcopy([
            d for d in DOCUMENTS
            if d["owner_id"] == user_id
        ])

    def save(self, record):
        existing = next(
            (d for d in DOCUMENTS if d["id"] == record["id"]),
            None,
        )
        if existing:
            existing.update(deepcopy(record))
        else:
            DOCUMENTS.append(deepcopy(record))

    def all(self):
        return deepcopy(DOCUMENTS)

class AuditRepository:
    def next_id(self):
        return len(AUDIT_EVENTS) + 1

    def save(self, record):
        AUDIT_EVENTS.append(deepcopy(record))

    def recent(self, limit=20):
        return deepcopy(AUDIT_EVENTS[-limit:])

    def all(self):
        return deepcopy(AUDIT_EVENTS)
