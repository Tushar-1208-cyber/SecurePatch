import pytest
from services.command_service import CommandService

@pytest.fixture
def command_service():
    return CommandService()

def test_execute_safe_with_allowed_command(command_service):
    result = command_service.execute_safe("echo Hello")
    assert result == 0

def test_execute_safe_with_disallowed_command(command_service):
    with pytest.raises(ValueError) as exc_info:
        command_service.execute_safe("rm -rf /")
    assert "Command is not allowed" in str(exc_info.value)

def test_execute_safe_with_empty_command(command_service):
    with pytest.raises(ValueError) as exc_info:
        command_service.execute_safe("")
    assert "Command is empty" in str(exc_info.value)