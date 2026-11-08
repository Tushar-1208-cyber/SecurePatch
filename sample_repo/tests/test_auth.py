from routes.auth import AuthController

def test_auth_controller_login_failure():
    controller = AuthController()
    result = controller.login("missing-user", "wrong-password")
    assert result["success"] is False

def test_auth_controller_login_success():
    controller = AuthController()
    result = controller.login("demo_user", "user123")
    assert result["success"] is True
    assert result["user"]["username"] == "demo_user"
    assert result["token"]

def test_logout():
    controller = AuthController()
    result = controller.logout("demo_user")
    assert result["success"] is True

def test_password_change_rejects_wrong_password():
    controller = AuthController()
    result = controller.change_password(2, "wrong", "new-password")
    assert result["success"] is False
