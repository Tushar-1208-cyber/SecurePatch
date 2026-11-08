import pytest
from app.app import reg_customer, User, db, app
from flask import Flask, request, jsonify
import hashlib

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.app_context():
        db.create_all()
        yield app.test_client()

def test_reg_customer_normal_behavior(client):
    # Test normal behavior with valid input
    response = client.post('/register/user', json={'username': 'testuser', 'password': 'testpass'})
    assert response.status_code == 200
    assert response.json == {'Created': 'User: testuser has been created'}

def test_reg_customer_weak_hash(client):
    # Test security property: weak MD5 hash
    with pytest.raises(ValueError):
        with app.app_context():
            content = {'username': 'testuser', 'password': 'testpass'}
            username = content['username']
            password = content['password']
            hash_pass = hashlib.md5(password.encode()).hexdigest()
            new_user = User(username, hash_pass)
            db.session.add(new_user)
            db.session.commit()

def test_reg_customer_missing_password(client):
    # Test behavior with missing password
    response = client.post('/register/user', json={'username': 'testuser'})
    assert response.status_code == 404
    assert response.json == {'Error': 'Invalid Request'}

def test_reg_customer_missing_username(client):
    # Test behavior with missing username
    response = client.post('/register/user', json={'password': 'testpass'})
    assert response.status_code == 404
    assert response.json == {'Error': 'Invalid Request'}

def test_reg_customer_duplicate_username(client):
    # Test behavior with duplicate username
    client.post('/register/user', json={'username': 'testuser', 'password': 'testpass'})
    response = client.post('/register/user', json={'username': 'testuser', 'password': 'testpass'})
    assert response.status_code == 404
    assert response.json == {'Error': 'Invalid Request'}
```

This pytest code tests the `reg_customer` function for normal behavior, security property (weak MD5 hash), and various error conditions. It uses an in-memory SQLite database for testing and does not require network access or destructive system actions.