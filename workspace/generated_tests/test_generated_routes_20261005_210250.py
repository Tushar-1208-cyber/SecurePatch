import pytest
from app import create_app
from app.routes import vulnerable_products

def create_test_client():
    app = create_app(
        {
            "TESTING": True,
        }
    )
    return app.test_client()

def test_vulnerable_product_search_normal_behavior():
    client = create_test_client()
    response = client.get("/vulnerable/products?category=laptops")
    assert response.status_code == 200
    assert b"Security Laptop" in response.data
    assert b"Packet Analysis Laptop" in response.data

def test_vulnerable_product_search_sql_injection():
    client = create_test_client()
    response = client.get("/vulnerable/products", query_string={"category": "' OR '1'='1"})
    assert response.status_code == 200
    assert b"Security Laptop" in response.data
    assert b"Network Adapter" in response.data
    assert b"USB Security Key" in response.data