from routes.auth import AuthController
from routes.users import UserController
from routes.documents import DocumentController
from routes.admin import AdminController
from middleware.auth_middleware import AuthMiddleware
from middleware.logging_middleware import RequestLogger
from services.audit_service import AuditService
from config import Settings

class Application:
    def __init__(self):
        self.settings = Settings.from_environment()
        self.auth = AuthController()
        self.users = UserController()
        self.documents = DocumentController()
        self.admin = AdminController()
        self.authz = AuthMiddleware()
        self.logger = RequestLogger()
        self.audit = AuditService()

    def boot(self):
        self.logger.info("application boot")
        self.audit.record("SYSTEM_BOOT", "system", "application")
        return {
            "name": self.settings.app_name,
            "version": self.settings.version,
            "environment": self.settings.environment,
        }

    def login(self, username, password):
        return self.auth.login(username, password)

    def user_profile(self, user_id):
        self.authz.require_user(user_id)
        return self.users.profile(user_id)

    def upload_document(self, user_id, path):
        self.authz.require_user(user_id)
        return self.documents.upload(user_id, path)

    def import_document(self, user_id, path):
        self.authz.require_user(user_id)
        return self.documents.import_legacy(user_id, path)

    def execute_admin_task(self, user_id, command):
        self.authz.require_admin(user_id)
        return self.admin.execute(command)

    def health(self):
        return {
            "status": "healthy",
            "database": self.settings.database_url,
            "debug": self.settings.debug,
        }

application = Application()
