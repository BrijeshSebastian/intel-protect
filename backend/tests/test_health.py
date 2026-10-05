def test_health_check_endpoint(client):
    """Verify that /api/health returns a healthy status and connected database."""
    response = client.get("/api/health")
    assert response.status_code == 200
    
    payload = response.get_json()
    assert payload is not None
    assert payload["success"] is True
    assert payload["error"] is None
    assert "data" in payload
    
    data = payload["data"]
    assert data["status"] == "healthy"
    assert data["database"] == "connected"
    assert data["service"] == "Intel-Protect API"
    assert data["version"] == "1.0.0"


def test_index_route(client):
    """Verify the root index API route responds successfully."""
    response = client.get("/")
    assert response.status_code == 200
    
    payload = response.get_json()
    assert payload["success"] is True
    assert "Intel-Protect" in payload["data"]["name"]


def test_404_error_handler(client):
    """Verify that unknown endpoints return a structured 404 response."""
    response = client.get("/api/nonexistent-route")
    assert response.status_code == 404
    
    payload = response.get_json()
    assert payload["success"] is False
    assert payload["data"] is None
    assert payload["error"]["code"] == "NOT_FOUND"
