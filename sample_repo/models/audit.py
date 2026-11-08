from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class AuditEvent:
    event_id: int
    action: str
    actor: str
    resource: str
    success: bool
    details: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)

    def level(self):
        return "INFO" if self.success else "WARNING"

    def to_dict(self):
        return {
            "id": self.event_id,
            "action": self.action,
            "actor": self.actor,
            "resource": self.resource,
            "success": self.success,
            "details": self.details,
            "level": self.level(),
            "created_at": self.created_at.isoformat(),
        }

    def summary(self):
        state = "completed" if self.success else "failed"
        return f"{self.action} {state} for {self.resource}"
