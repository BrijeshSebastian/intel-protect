# Intel-Protect — REST API Reference Manual

**API Version:** 1.0.0  
**Base URL:** `http://localhost:5000/api` (or `/api` behind Nginx reverse proxy)  
**Content-Type:** `application/json` (unless specified as `multipart/form-data`)  
**Authentication Scheme:** `Bearer <access_token>` in `Authorization` header  

---

## 1. Global API Standards

### 1.1 Response Envelope
All API endpoints return responses encapsulated in a standardized envelope:

#### Success Envelope (HTTP 200, 201)
```json
{
  "success": true,
  "data": {
    "key": "value"
  },
  "error": null,
  "meta": {
    "timestamp": "2026-10-06T01:45:00Z",
    "request_id": "b73a38a7-7b6c-4861-8ee2-dfca2d8544d6"
  }
}
```

#### Error Envelope (HTTP 400, 401, 403, 404, 429, 500)
```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "The input parameters failed schema validation.",
    "details": {
      "email": ["Invalid email address format."]
    }
  },
  "meta": {
    "timestamp": "2026-10-06T01:45:00Z",
    "request_id": "c19b8849-0cfb-4171-8eb8-4ca3f46fbb19"
  }
}
```

### 1.2 Error Codes Reference
| HTTP Status | Error Code | Description |
|---|---|---|
| `400 Bad Request` | `VALIDATION_ERROR` | Request payload failed Marshmallow schema validation. |
| `400 Bad Request` | `FILE_TOO_LARGE` | Uploaded document exceeds maximum 10 MB limit. |
| `400 Bad Request` | `UNSUPPORTED_FILE_TYPE` | File MIME magic bytes or extension not supported. |
| `401 Unauthorized` | `UNAUTHORIZED` | Bearer JWT missing, expired, or malformed. |
| `401 Unauthorized` | `INVALID_CREDENTIALS` | Invalid username/email or password provided. |
| `403 Forbidden` | `FORBIDDEN` | Access denied; user cannot access or mutate resources of another user. |
| `404 Not Found` | `NOT_FOUND` | Requested document, record, or recommendation not found. |
| `429 Too Many Requests` | `RATE_LIMITED` | Endpoint rate limit exceeded (e.g. 20 auth attempts / minute). |
| `500 Internal Error` | `SERVER_ERROR` | An unexpected internal error occurred on the server. |

---

## 2. Authentication API (`/api/auth`)

### 2.1 User Registration
Creates a new account and securely hashes the password using Argon2id.

- **Method:** `POST`
- **Endpoint:** `/api/auth/register`
- **Auth Required:** No
- **Rate Limit:** 20 requests / minute

#### Request Body
```json
{
  "email": "user@example.com",
  "username": "threat_hunter",
  "password": "SecurePassword123!#",
  "full_name": "Arjun Patel"
}
```

#### Response (HTTP 201 Created)
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "user@example.com",
      "username": "threat_hunter",
      "full_name": "Arjun Patel",
      "created_at": "2026-10-06T01:45:00Z"
    }
  },
  "error": null
}
```

---

### 2.2 User Login
Authenticates credentials, returns an in-memory access token, and sets a secure HttpOnly refresh cookie.

- **Method:** `POST`
- **Endpoint:** `/api/auth/login`
- **Auth Required:** No
- **Rate Limit:** 20 requests / minute

#### Request Body
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!#"
}
```

#### Response (HTTP 200 OK)
*Headers:* `Set-Cookie: refresh_token=...; HttpOnly; SameSite=Strict; Path=/api/auth`
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 900,
    "user": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "user@example.com",
      "username": "threat_hunter"
    }
  },
  "error": null
}
```

---

### 2.3 Rotate Refresh Token
Validates the HttpOnly cookie, rotates the token family, and issues a new access token.

- **Method:** `POST`
- **Endpoint:** `/api/auth/refresh`
- **Auth Required:** HttpOnly cookie (`refresh_token`)

#### Response (HTTP 200 OK)
*Headers:* `Set-Cookie: refresh_token=<new_token>; HttpOnly; SameSite=Strict; Path=/api/auth`
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 900
  },
  "error": null
}
```

---

### 2.4 User Logout
Revokes the refresh token family and clears the browser cookie.

- **Method:** `POST`
- **Endpoint:** `/api/auth/logout`
- **Auth Required:** Bearer JWT + HttpOnly cookie

#### Response (HTTP 200 OK)
```json
{
  "success": true,
  "data": {
    "message": "Successfully logged out and token family revoked."
  },
  "error": null
}
```

---

## 3. Document Privacy Scanner API (`/api/documents`)

### 3.1 Upload & Scan Document
Uploads a document, extracts text (native PDF or Tesseract OCR), runs deterministic PII detection, validates checksums, computes risk score, executes Model 1 ML classification, and deletes temporary files.

- **Method:** `POST`
- **Endpoint:** `/api/documents/scan`
- **Auth Required:** Bearer JWT
- **Content-Type:** `multipart/form-data`
- **Payload:** `file` (Binary stream: `.pdf`, `.png`, `.jpg`, `.txt`, max 10MB)

#### Response (HTTP 201 Created)
```json
{
  "success": true,
  "data": {
    "document": {
      "id": "7fa84001-e29b-41d4-a716-446655440001",
      "original_filename": "tax_statement_2025.pdf",
      "file_type": "pdf",
      "file_size": 245760,
      "risk_score": 78.4,
      "risk_level": "HIGH",
      "ml_classification": "HIGH",
      "ml_confidence": 0.958,
      "pii_count": 5,
      "high_risk_count": 2,
      "scanned_at": "2026-10-06T01:45:00Z",
      "score_explanation": {
        "identity_score": 40.0,
        "financial_score": 30.0,
        "contact_score": 8.4,
        "factors": [
          "Aadhaar number detected with valid Verhoeff checksum (CRITICAL)",
          "PAN number verified via structural regex (HIGH)",
          "1 Phone number and 2 Email addresses detected (MEDIUM)"
        ]
      }
    },
    "findings": [
      {
        "id": "8aa84002-e29b-41d4-a716-446655440002",
        "pii_type": "AADHAAR",
        "masked_value": "XXXX XXXX 1489",
        "confidence": 0.98,
        "severity": "CRITICAL",
        "checksum_valid": true,
        "detection_method": "regex+verhoeff",
        "context_snippet": "...Aadhaar: XXXX XXXX 1489 verified..."
      },
      {
        "id": "8bb84003-e29b-41d4-a716-446655440003",
        "pii_type": "PAN",
        "masked_value": "ABCDE****F",
        "confidence": 0.95,
        "severity": "HIGH",
        "checksum_valid": null,
        "detection_method": "regex",
        "context_snippet": "...PAN Card: ABCDE****F..."
      }
    ]
  },
  "error": null
}
```

---

### 3.2 List Scanned Documents
Returns paginated list of user's scanned document audit records.

- **Method:** `GET`
- **Endpoint:** `/api/documents?page=1&limit=10`
- **Auth Required:** Bearer JWT

#### Response (HTTP 200 OK)
```json
{
  "success": true,
  "data": {
    "documents": [
      {
        "id": "7fa84001-e29b-41d4-a716-446655440001",
        "original_filename": "tax_statement_2025.pdf",
        "file_type": "pdf",
        "risk_score": 78.4,
        "risk_level": "HIGH",
        "pii_count": 5,
        "scanned_at": "2026-10-06T01:45:00Z"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 10,
      "total": 1,
      "pages": 1
    }
  },
  "error": null
}
```

---

## 4. Exposure Footprint Monitor API (`/api/exposure`)

### 4.1 Analyze Identity Exposure
Extracts named entities from raw text or query fields, applies synergistic triad scoring, executes Model 2 classification, and evaluates anomaly likelihood via Isolation Forest.

- **Method:** `POST`
- **Endpoint:** `/api/exposure/analyze`
- **Auth Required:** Bearer JWT

#### Request Body
```json
{
  "identifiers": {
    "name": "Kavita Reddy",
    "email": "kavita.reddy@techcorp.in",
    "phone": "+91-9876543210",
    "location": "Bengaluru"
  },
  "text": "Employee record: Kavita Reddy, Email: kavita.reddy@techcorp.in, Phone: +91-9876543210, City: Bengaluru"
}
```

#### Response (HTTP 201 Created)
```json
{
  "success": true,
  "data": {
    "exposure_record": {
      "id": "9ca84004-e29b-41d4-a716-446655440004",
      "exposure_score": 43.6,
      "exposure_level": "MEDIUM",
      "sensitivity_label": "MEDIUM",
      "sensitivity_confidence": 0.972,
      "is_anomalous": false,
      "anomaly_score": 0.184,
      "total_entities": 4,
      "category_scores": {
        "identity": 15.0,
        "contact": 20.0,
        "location": 8.6,
        "financial": 0.0,
        "credential": 0.0
      },
      "masked_entities": [
        {
          "entity_type": "PERSON",
          "masked_value": "Kav*** Red***",
          "confidence": 0.92,
          "category": "identity"
        },
        {
          "entity_type": "EMAIL",
          "masked_value": "kav***@techcorp.in",
          "confidence": 0.99,
          "category": "contact"
        }
      ],
      "analyzed_at": "2026-10-06T01:45:00Z"
    }
  },
  "error": null
}
```

---

## 5. Breach Monitor API (`/api/breaches`)

### 5.1 Check Email Against Breach Catalog
Hashes the target email using SHA-256 and searches known synthetic corporate incidents.

- **Method:** `POST`
- **Endpoint:** `/api/breaches/check`
- **Auth Required:** Bearer JWT

#### Request Body
```json
{
  "email": "rahul.sharma@example.com"
}
```

#### Response (HTTP 201 Created)
```json
{
  "success": true,
  "data": {
    "query": {
      "id": "adb84005-e29b-41d4-a716-446655440005",
      "query_email_hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
      "breach_count": 2,
      "total_exposures": 6,
      "priority_label": "HIGH",
      "priority_confidence": 0.965,
      "breach_risk_score": 68.5,
      "breach_risk_level": "HIGH",
      "checked_at": "2026-10-06T01:45:00Z"
    },
    "matches": [
      {
        "name": "FinTech India Leak (Synthetic)",
        "organization": "FinTech Core Ltd",
        "breach_date": "2024-03-15",
        "affected_count": 4500000,
        "severity": "CRITICAL",
        "exposed_data_types": ["EMAIL", "PASSWORD_HASH", "PHONE", "AADHAAR"]
      },
      {
        "name": "E-Commerce MegaMart (Synthetic)",
        "organization": "MegaMart Online",
        "breach_date": "2023-11-20",
        "affected_count": 12000000,
        "severity": "HIGH",
        "exposed_data_types": ["EMAIL", "FULL_NAME", "SHIPPING_ADDRESS"]
      }
    ]
  },
  "error": null
}
```

---

### 5.2 List Known Breach Incidents Catalog
Returns public metadata for all synthetic corporate breach incidents in the catalog.

- **Method:** `GET`
- **Endpoint:** `/api/breaches/catalog`
- **Auth Required:** Bearer JWT

#### Response (HTTP 200 OK)
```json
{
  "success": true,
  "data": {
    "catalog": [
      {
        "id": "b0a84006-e29b-41d4-a716-446655440006",
        "name": "RockYou2024 (Synthetic)",
        "organization": "Global Credential Leak",
        "breach_date": "2024-01-10",
        "affected_count": 9800000,
        "severity": "HIGH",
        "exposed_data_types": ["EMAIL", "PLAINTEXT_PASSWORD"]
      }
    ]
  },
  "error": null
}
```

---

## 6. Unified Threat Cockpit API (`/api/dashboard`)

### 6.1 Get Consolidated Dashboard Cockpit
Returns composite threat index, per-module risk cards, 5-vector threat surfaces, timeline events, and active cross-module recommendations.

- **Method:** `GET`
- **Endpoint:** `/api/dashboard`
- **Auth Required:** Bearer JWT

#### Response (HTTP 200 OK)
```json
{
  "success": true,
  "data": {
    "overall_risk_score": 63.5,
    "overall_risk_level": "HIGH",
    "normalization": {
      "active_modules": ["document_scanner", "exposure_monitor", "breach_monitor"],
      "weights": {
        "document_scanner": 0.30,
        "exposure_monitor": 0.35,
        "breach_monitor": 0.35
      }
    },
    "module_scores": {
      "document_scanner": {
        "score": 78.4,
        "level": "HIGH",
        "documents_count": 1
      },
      "exposure_monitor": {
        "score": 43.6,
        "level": "MEDIUM",
        "anomalous": false
      },
      "breach_monitor": {
        "score": 68.5,
        "level": "HIGH",
        "breach_count": 2
      }
    },
    "vector_breakdown": {
      "identity": 65.0,
      "contact": 55.0,
      "financial": 45.0,
      "credential": 70.0,
      "location": 25.0
    },
    "active_recommendations_count": 3
  },
  "error": null
}
```

---

### 6.2 Dismiss Remediation Recommendation
Allows users to dismiss a recommendation across modules.

- **Method:** `PATCH`
- **Endpoint:** `/api/dashboard/recommendations/<id>/dismiss`
- **Auth Required:** Bearer JWT

#### Response (HTTP 200 OK)
```json
{
  "success": true,
  "data": {
    "message": "Recommendation dismissed successfully.",
    "recommendation_id": "c1a84007-e29b-41d4-a716-446655440007",
    "is_dismissed": true
  },
  "error": null
}
```

---

## 7. System Health API (`/api/health`)

Verifies Flask runtime and tests PostgreSQL live connectivity.

- **Method:** `GET`
- **Endpoint:** `/api/health`
- **Auth Required:** No

#### Response (HTTP 200 OK)
```json
{
  "status": "healthy",
  "database": "connected",
  "version": "1.0.0",
  "timestamp": "2026-10-06T01:45:00Z"
}
```
