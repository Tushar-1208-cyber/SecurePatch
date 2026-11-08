import pytest
from services.command_service import CommandService

def test_command_execution():
    service = CommandService()
    result = service.execute("echo Hello")
    assert result == 0

def test_command_execution_with_invalid_command():
    service = CommandService()
    with pytest.raises(ValueError):
        service.execute("invalid_command")

def test_command_execution_with_empty_command():
    service = CommandService()
    with pytest.raises(ValueError):
        service.execute("")