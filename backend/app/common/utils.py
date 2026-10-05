from datetime import datetime, timezone
from flask import jsonify


def api_response(data=None, error=None, message=None, status_code=200):
    """
    Standardized REST API response envelope.
    Follows approved architecture specification.
    """
    is_success = error is None and status_code < 400
    
    payload = {
        "success": is_success,
        "data": data,
        "error": error,
        "meta": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    }
    
    if message:
        payload["meta"]["message"] = message

    return jsonify(payload), status_code
