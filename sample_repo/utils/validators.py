import re

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def validate_username(username):
    if not isinstance(username, str):
        raise ValueError("Username must be text")
    username = username.strip()
    if not 3 <= len(username) <= 50:
        raise ValueError("Username length is invalid")
    return username

def validate_email(email):
    if not isinstance(email, str):
        raise ValueError("Email must be text")
    if not EMAIL_PATTERN.match(email):
        raise ValueError("Invalid email")
    return email.lower()

def validate_user_id(user_id):
    if not isinstance(user_id, int) or user_id <= 0:
        raise ValueError("Invalid user id")
    return user_id

def validate_document_size(size):
    if not isinstance(size, int):
        raise ValueError("Document size must be an integer")
    if size < 0 or size > 20 * 1024 * 1024:
        raise ValueError("Document size is not allowed")
    return True

def validate_command(command):
    if not isinstance(command, str):
        raise ValueError("Command must be text")
    command = command.strip()
    if not command:
        raise ValueError("Command cannot be empty")
    return command
