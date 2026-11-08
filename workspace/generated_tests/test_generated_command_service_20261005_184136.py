import subprocess
from services.command_service import CommandService

def test_execute_with_shell_true():
    # Arrange
    command_service = CommandService()
    command = "echo Hello, World!"
    
    # Act
    result = command_service.execute(command)
    
    # Assert
    assert result == 0, "The command should execute successfully with shell=True"

def test_execute_with_shell_true_injection():
    # Arrange
    command_service = CommandService()
    command = "echo Hello, World! && rm -rf /"
    
    # Act
    result = command_service.execute(command)
    
    # Assert
    assert result != 0, "The command should fail due to shell injection with shell=True"