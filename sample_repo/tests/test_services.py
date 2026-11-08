from services.user_service import UserService
from services.report_service import ReportService
from services.command_service import CommandService
from utils.security import PasswordHasher

def test_user_service_count():
    service = UserService()
    assert service.count_active() >= 2

def test_report_service():
    service = ReportService()
    summary = service.system_summary()
    assert summary["users"] >= 3
    assert summary["documents"] >= 2

def test_password_hashing():
    hasher = PasswordHasher()
    stored = hasher.hash("secret")
    assert hasher.verify("secret", stored)
    assert not hasher.verify("wrong", stored)

def test_command_exists():
    service = CommandService()
    assert service.command_exists("python") or service.command_exists("python3")
