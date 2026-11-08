from routes.users import UserController

def test_profile_returns_user():
    controller = UserController()
    result = controller.profile(2)
    assert result["username"] == "demo_user"

def test_profile_missing_user():
    controller = UserController()
    result = controller.profile(9999)
    assert result["error"] == "User not found"

def test_search_returns_matches():
    controller = UserController()
    results = controller.search("demo")
    assert any(user["username"] == "demo_user" for user in results)

def test_update_email():
    controller = UserController()
    result = controller.update_email(2, "updated@example.com")
    assert result["email"] == "updated@example.com"

def test_deactivate_and_reactivate():
    controller = UserController()
    assert controller.deactivate(2)["success"] is True
    assert controller.reactivate(2)["success"] is True
