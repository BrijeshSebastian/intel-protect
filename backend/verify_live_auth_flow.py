"""
Live End-to-End Verification of Phase 2 Authentication Flow.
Executes real HTTP requests against running Flask backend and PostgreSQL database.
"""
import requests
import json
import time

BASE_URL = "http://localhost:5001/api/auth"

print("=" * 80)
print("INTEL-PROTECT — LIVE AUTHENTICATION SYSTEM VERIFICATION")
print("=" * 80)

# Create a clean session with cookies support
session = requests.Session()

# 1. REGISTER
print("\n[1] Testing Registration (POST /api/auth/register)...")
test_email = f"live_analyst_{int(time.time())}@example.com"
reg_payload = {
    "email": test_email,
    "username": f"analyst_{int(time.time())}",
    "password": "SecurePassword999!",
    "full_name": "Senior Security Analyst"
}
reg_res = requests.post(f"{BASE_URL}/register", json=reg_payload)
print(f"Status Code: {reg_res.status_code}")
reg_json = reg_res.json()
print("Response:", json.dumps(reg_json, indent=2))
assert reg_res.status_code == 201
assert reg_json["success"] is True
assert "password" not in reg_json["data"]["user"]
assert "password_hash" not in reg_json["data"]["user"]
print("--> Registration SUCCESSFUL! Clean user profile returned.")

# 2. LOGIN
print("\n[2] Testing Login (POST /api/auth/login)...")
login_payload = {
    "email": test_email,
    "password": "SecurePassword999!"
}
login_res = session.post(f"{BASE_URL}/login", json=login_payload)
print(f"Status Code: {login_res.status_code}")
login_json = login_res.json()
print("Response Body:", json.dumps(login_json, indent=2))
assert login_res.status_code == 200
assert login_json["success"] is True
access_token = login_json["data"]["access_token"]
assert access_token is not None
# Confirm refresh token is NOT in body
assert "refresh_token" not in login_json["data"]
assert "refresh_token" not in login_json

# Verify HttpOnly Cookie
cookies = session.cookies.get_dict()
print("Session Cookies Received:", cookies)
assert "refresh_token" in cookies
raw_token_1 = cookies["refresh_token"]
print("--> Login SUCCESSFUL! Access token received in body, refresh token in HttpOnly cookie.")

# 3. ACCESS PROTECTED ROUTE /api/auth/me
print("\n[3] Testing Protected Route (GET /api/auth/me)...")
me_headers = {"Authorization": f"Bearer {access_token}"}
me_res = requests.get(f"{BASE_URL}/me", headers=me_headers)
print(f"Status Code: {me_res.status_code}")
me_json = me_res.json()
print("Response:", json.dumps(me_json, indent=2))
assert me_res.status_code == 200
assert me_json["data"]["user"]["email"] == test_email
print("--> Protected Route SUCCESSFUL! Identity verified from Bearer access token.")

# 4. REFRESH TOKEN ROTATION
print("\n[4] Testing Token Rotation (POST /api/auth/refresh)...")
refresh_res = session.post(f"{BASE_URL}/refresh")
print(f"Status Code: {refresh_res.status_code}")
refresh_json = refresh_res.json()
print("Response:", json.dumps(refresh_json, indent=2))
assert refresh_res.status_code == 200
new_access_token = refresh_json["data"]["access_token"]
assert new_access_token != access_token

new_cookies = session.cookies.get_dict()
raw_token_2 = new_cookies["refresh_token"]
assert raw_token_2 != raw_token_1
print(f"Old refresh token: {raw_token_1[:16]}...")
print(f"New refresh token: {raw_token_2[:16]}...")
print("--> Token Rotation SUCCESSFUL! Old token revoked, new access token and rotated cookie issued.")

# 5. REUSE DETECTION & FAMILY REVOCATION
print("\n[5] Testing Token Theft / Reuse Detection Attack Simulation...")
print("Attacker attempts to replay previously rotated token (Token 1)...")
attacker_session = requests.Session()
attacker_session.cookies.set("refresh_token", raw_token_1, path="/api/auth")

reuse_res = attacker_session.post(f"{BASE_URL}/refresh")
print(f"Status Code: {reuse_res.status_code}")
reuse_json = reuse_res.json()
print("Response:", json.dumps(reuse_json, indent=2))
assert reuse_res.status_code == 401
assert reuse_json["error"]["code"] == "TOKEN_REUSE_DETECTED"
print("--> Alert Triggered: TOKEN_REUSE_DETECTED returned.")

print("Verifying legitimate user's Token 2 was revoked due to family theft countermeasures...")
legit_res = session.post(f"{BASE_URL}/refresh")
print(f"Legitimate Token 2 Status Code: {legit_res.status_code}")
assert legit_res.status_code == 401
print("--> Entire Token Family REVOKED! Attacker and legitimate session safely terminated.")

# 6. LOGOUT
print("\n[6] Testing Fresh Login and Clean Logout...")
fresh_login = session.post(f"{BASE_URL}/login", json=login_payload)
assert fresh_login.status_code == 200
assert "refresh_token" in session.cookies.get_dict()

logout_res = session.post(f"{BASE_URL}/logout")
print(f"Logout Status Code: {logout_res.status_code}")
print("Response:", logout_res.json())
assert logout_res.status_code == 200

# Verify refresh cookie deleted or invalidated
post_logout_refresh = session.post(f"{BASE_URL}/refresh")
print(f"Post-Logout Refresh Status Code: {post_logout_refresh.status_code}")
assert post_logout_refresh.status_code == 401
print("--> Logout SUCCESSFUL! Session revoked and cookie cleared.")

print("\n" + "=" * 80)
print("ALL LIVE AUTHENTICATION FLOWS VERIFIED SUCCESSFULLY ON REAL SERVER & DATABASE!")
print("=" * 80)
