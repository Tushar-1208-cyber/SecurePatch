from models.audit import AuditEvent
from utils.database import AuditRepository

class AuditService:
    def __init__(self):
        self.repository = AuditRepository()

    def record(self, action, actor, resource, success=True, details=""):
        event = AuditEvent(
            self.repository.next_id(),
            action,
            actor,
            resource,
            success,
            details,
        )
        self.repository.save(event.to_dict())
        return event

    def recent(self, limit=20):
        return self.repository.recent(limit)

    def failures(self):
        return [event for event in self.repository.all() if not event["success"]]

    def count_action(self, action):
        return sum(
            1 for event in self.repository.all()
            if event["action"] == action
        )
