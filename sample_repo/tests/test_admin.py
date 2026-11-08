from routes.admin import AdminController

def test_admin_controller_summary():
    controller = AdminController()
    summary = controller.system_summary()
    assert summary["users"] >= 3
    assert summary["documents"] >= 2

def test_admin_report():
    controller = AdminController()
    report = controller.user_report(2)
    assert report["user"]["username"] == "demo_user"

def test_safe_admin_command():
    controller = AdminController()
    result = controller.execute_safe("echo SecurePatch")
    assert result["return_code"] == 0
