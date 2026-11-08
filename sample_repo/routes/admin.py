from services.command_service import CommandService
from services.report_service import ReportService
from services.audit_service import AuditService
from utils.validators import validate_user_id

class AdminController:
    def __init__(self):
        self.commands = CommandService()
        self.reports = ReportService()
        self.audit = AuditService()

    def execute(self, command):
        result = self.commands.execute(command)
        self.audit.record("ADMIN_COMMAND", "admin", command, result == 0)
        return {"return_code": result}

    def execute_safe(self, command):
        result = self.commands.execute_safe(command)
        self.audit.record("ADMIN_SAFE_COMMAND", "admin", command, result == 0)
        return {"return_code": result}

    def user_report(self, user_id):
        validate_user_id(user_id)
        return self.reports.build_user_report(user_id)

    def system_summary(self):
        return self.reports.system_summary()

    def audit_summary(self):
        return self.reports.audit_summary()
