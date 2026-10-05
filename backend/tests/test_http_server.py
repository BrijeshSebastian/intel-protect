import time
import socket
import pytest
import requests
from threading import Thread
from werkzeug.serving import make_server
from backend.app import create_app


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class ServerThread(Thread):
    def __init__(self, app, port):
        super().__init__()
        self.server = make_server('127.0.0.1', port, app)

    def run(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()


def test_real_http_health_endpoint():
    """Start an actual HTTP server on a socket and test /api/health over network."""
    app = create_app(config_name="testing")
    port = find_free_port()
    server = ServerThread(app, port)
    server.start()

    time.sleep(0.5)

    try:
        url = f"http://127.0.0.1:{port}/api/health"
        res = requests.get(url, timeout=5)
        
        assert res.status_code == 200
        json_data = res.json()
        assert json_data["success"] is True
        assert json_data["data"]["status"] == "healthy"
        assert json_data["data"]["database"] == "connected"
        assert "timestamp" in json_data["meta"]
        
        # Test CORS headers on OPTIONS preflight
        options_res = requests.options(
            url,
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET"
            },
            timeout=5
        )
        assert options_res.status_code in [200, 204]
        assert "Access-Control-Allow-Origin" in options_res.headers
    finally:
        server.shutdown()
        server.join()
