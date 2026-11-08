import pytest
from services.command_service import CommandService

def test_execute_normal_behavior():
    command = "echo Hello World"
    service = CommandService()
    result = service.execute(command)
    assert result == 0

def test_execute_security_property():
    command = "ls -l"
    service = CommandService()
    with pytest.raises(subprocess.CalledProcessError):
        service.execute(command)

def test_execute_safe_normal_behavior():
    command = "echo Hello World"
    service = CommandService()
    result = service.execute_safe(command)
    assert result.returncode == 0

def test_execute_safe_security_property():
    command = "ls -l"
    service = CommandService()
    result = service.execute_safe(command)
    assert result.returncode != 0

Note: The above tests are designed to check the normal behavior of the `execute` method, as well as its security properties. The `test_execute_security_property` test checks that an invalid command raises a `CalledProcessError`. The `test_execute_safe_security_property` test checks that the `execute_safe` method returns a non-zero return code for an invalid command.