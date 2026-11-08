import subprocess
from services.command_service import CommandService

def test_execute_command_with_shell_true():
    command_service = CommandService()
    with pytest.raises(subprocess.CalledProcessError) as e:
        command_service.execute("ls /nonexistent_directory")
    assert e.value.returncode != 0

def test_execute_safe_command():
    command_service = CommandService()
    result = command_service.execute_safe("echo Hello, World!")
    assert result == 0