import subprocess
from services.command_service import CommandService

def test_execute_command():
    command_service = CommandService()
    result = command_service.execute_safe("echo Hello, World!")
    assert result == 0
    assert "Hello, World!" in command_service.last_output

def test_execute_invalid_command():
    command_service = CommandService()
    with pytest.raises(ValueError) as exc_info:
        command_service.execute_safe("invalid_command")
    assert str(exc_info.value) == "Command is not allowed"

def test_execute_empty_command():
    command_service = CommandService()
    with pytest.raises(ValueError) as exc_info:
        command_service.execute_safe("")
    assert str(exc_info.value) == "Command is empty"