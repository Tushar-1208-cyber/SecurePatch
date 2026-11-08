import pytest
from services.command_service import CommandService

def test_command_execution():
    service = CommandService()
    # Test valid command execution
    result = service.execute("python --version")
    assert result == 0

    # Test echo command (shell-free)
    result = service.execute("echo Hello World!")
    assert result == 0

    # Test invalid command execution
    with pytest.raises(ValueError):
        service.execute("invalid-command")

    # Test empty command execution
    with pytest.raises(ValueError):
        service.execute("")

    # Test disallowed command execution
    with pytest.raises(ValueError):
        service.execute("rm -rf /")

    # Test malicious input
    with pytest.raises(subprocess.SubprocessError):
        service.execute("ls > /dev/null; rm -rf /")

Note: This test suite covers various scenarios to ensure the patched function behaves as expected:

1.  Valid command execution: Tests if a valid command is executed successfully.
2.  Echo command (shell-free): Verifies that the `echo` command is handled correctly without using shell=True.
3.  Invalid command execution: Checks if an invalid command raises a ValueError.
4.  Empty command execution: Ensures that an empty command raises a ValueError.
5.  Disallowed command execution: Validates that a disallowed command raises a ValueError.
6.  Malicious input: Simulates a malicious input and checks if it raises a subprocess error.

These tests cover both normal behavior and security properties relevant to the finding, ensuring the patched function is secure and functional.