import pytest
from app import app

@pytest.fixture
def client():
    """Flask app test client"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_home_route(client):
    """Test home page loads"""
    response = client.get('/')
    assert response.status_code == 200

def test_signup_missing_data(client):
    """Test signup with missing email"""
    response = client.post('/api/signup', json={'password': 'test123'})
    assert response.status_code == 400
    assert 'error' in response.json

def test_login_invalid_credentials(client):
    """Test login with invalid credentials"""
    response = client.post('/api/login', json={
        'email': 'nonexistent@email.com',
        'password': 'wrongpassword'
    })
    assert response.status_code == 401

def test_protected_route_no_token(client):
    """Test protected route without token"""
    response = client.get('/api/protected')
    assert response.status_code == 401
