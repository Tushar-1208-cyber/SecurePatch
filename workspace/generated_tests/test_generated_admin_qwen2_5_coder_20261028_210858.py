import pytest

from routes.admin import AdminController

def test_admin_command_execution():
    controller = AdminController()
    result = controller.execute("echo SecurePatch")
    assert result["return_code"] == 0

def test_admin_safe_command_execution():
    controller = AdminController()
    result = controller.execute_safe("echo SecurePatch")
    assert result["return_code"] == 0

def test_admin_command_with_shell_true_vulnerable():
    # This should fail if the execute method still allows shell=True
    with pytest.raises(Exception):
        controller = AdminController()
        controller.commands.execute("echo SecurePatch", shell=True)