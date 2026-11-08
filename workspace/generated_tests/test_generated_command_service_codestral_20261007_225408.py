import pytest
from unittest import mock
from services.command_service import CommandService

def test_execute():
    command = "echo 'Hello World'"
    service = CommandService()

    # Test intended normal behavior
    result = service.execute(command)
    assert result == 0

    # Test security property: shell injection
    malicious_command = "rm -rf /"
    with pytest.raises(Exception):
        service.execute(malicious_command)