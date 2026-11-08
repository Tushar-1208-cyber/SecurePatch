import os
from dataclasses import dataclass

@dataclass
class Settings:
    app_name: str
    version: str
    environment: str
    debug: bool
    database_url: str
    admin_password: str
    upload_directory: str
    max_upload_size: int
    session_timeout: int

    @classmethod
    def from_environment(cls):
        environment = os.getenv("APP_ENV", "development")
        return cls(
            app_name=os.getenv("APP_NAME", "SecureDemo"),
            version=os.getenv("APP_VERSION", "2.4.0"),
            environment=environment,
            debug=os.getenv("DEBUG", "true").lower() == "true",
            database_url=os.getenv("DATABASE_URL", "sqlite:///secure_demo.db"),
            admin_password=os.getenv("ADMIN_PASSWORD", "admin123"),
            upload_directory=os.getenv("UPLOAD_DIR", "storage/uploads"),
            max_upload_size=int(os.getenv("MAX_UPLOAD_SIZE", "20971520")),
            session_timeout=int(os.getenv("SESSION_TIMEOUT", "1800")),
        )

    def is_production(self):
        return self.environment.lower() == "production"

    def validate(self):
        errors = []
        if not self.database_url:
            errors.append("DATABASE_URL is required")
        if self.max_upload_size <= 0:
            errors.append("MAX_UPLOAD_SIZE must be positive")
        if self.session_timeout < 60:
            errors.append("SESSION_TIMEOUT is too small")
        return errors

    def as_dict(self):
        return {
            "app_name": self.app_name,
            "version": self.version,
            "environment": self.environment,
            "debug": self.debug,
            "database_url": self.database_url,
            "upload_directory": self.upload_directory,
            "max_upload_size": self.max_upload_size,
            "session_timeout": self.session_timeout,
        }
