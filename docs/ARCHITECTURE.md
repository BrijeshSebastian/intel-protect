# Intel-Protect — System Architecture Documentation

**Document Version:** 1.0.0  
**Project:** Intel-Protect — Hybrid Cyber Threat Intelligence Platform (MCA Major Project)  
**Classification:** Technical Architecture Specification  
**Status:** Implemented & Verified  

---

## 1. Architectural Overview

**Intel-Protect** is engineered as a privacy-preserving, local-first cyber threat intelligence platform. The architecture decomposes threat surface analysis into three independent functional assessment engines—**Document Privacy Scanner**, **Exposure Footprint Monitor**, and **Data Breach Monitor**—which converge into a centralized **Unified Threat Dashboard**.

The system strictly enforces a **Zero Raw-PII Storage Policy**: sensitive data ingested through physical or digital documents, search parameters, or breach lookups are either processed in transient memory and unlinked immediately, or transformed via mathematical checksums, cryptographic hashes (SHA-256), and centralized masking before persistence.

```mermaid
flowchart TD
    subgraph Client["Presentation Layer (React 18 + Vite + Tailwind)"]
        UI["SPA Views & Interactive Cockpit"]
        AuthCtx["Auth Context & Memory Token State"]
        API["Axios API Client (Interceptor Queue)"]
    end

    subgraph Gateway["Reverse Proxy & Perimeter Defense"]
        NGINX["Nginx (Security Headers, Gzip, SSL, SPA Fallback)"]
    end

    subgraph Application["Application Layer (Flask 3.1 Factory)"]
        BP_AUTH["Auth Blueprint (/api/auth)"]
        BP_DOCS["Document Scanner (/api/documents)"]
        BP_EXP["Exposure Monitor (/api/exposure)"]
        BP_BRCH["Breach Monitor (/api/breaches)"]
        BP_DASH["Unified Dashboard (/api/dashboard)"]
        
        SECFILT["PII-Safe Logging Filter (Root Logger)"]
        LIMITER["Flask-Limiter Throttling"]
        REGISTRY["Singleton ML Model Registry"]
        SCORING["Deterministic Risk Engine"]
    end

    subgraph Inference["Local Machine Learning Inference"]
        M1["Model 1: Doc Sensitivity (RF/LogReg)"]
        M2["Model 2: Exposure Sensitivity (TF-IDF + RF)"]
        M3["Model 3: Breach Remediation Priority (RF)"]
        M4["Anomaly Detector: Isolation Forest"]
    end

    subgraph Persistence["Data & Artifact Layer"]
        PG[(PostgreSQL 16 Relational DB)]
        ARTIFACTS["joblib Models & Scalers"]
        SYNTH_DATA["Synthetic Datasets (seed=42)"]
        FS_TEMP["Transient /temp/uploads (UUID Unlinked)"]
    end

    UI --> AuthCtx
    AuthCtx --> API
    API -->|"HTTPS / REST API"| NGINX
    NGINX --> BP_AUTH
    NGINX --> BP_DOCS
    NGINX --> BP_EXP
    NGINX --> BP_BRCH
    NGINX --> BP_DASH

    BP_AUTH --> LIMITER
    BP_DOCS --> FS_TEMP
    BP_DOCS --> SCORING
    BP_EXP --> SCORING
    BP_BRCH --> SCORING
    BP_DASH --> SCORING

    BP_DOCS --> REGISTRY
    BP_EXP --> REGISTRY
    BP_BRCH --> REGISTRY

    REGISTRY --> M1
    REGISTRY --> M2
    REGISTRY --> M3
    REGISTRY --> M4
    M1 & M2 & M3 & M4 -.-> ARTIFACTS

    BP_AUTH & BP_DOCS & BP_EXP & BP_BRCH & BP_DASH --> PG
    Application -.-> SECFILT
```

---

## 2. Subsystem Boundaries & Responsibilities

| Subsystem | Architectural Role | Core Technical Stack | Persisted Data Invariant |
|---|---|---|---|
| **Authentication & Session** | Issues short-lived access JWTs and manages HttpOnly refresh token rotation with family revocation on reuse. | Argon2id, PyJWT, Flask-Limiter | No plaintext passwords; only Argon2id hash. Refresh tokens hashed via SHA-256. |
| **Document Scanner** | Extracts text from native/scanned PDFs and images, runs deterministic PII detection, validates checksums, computes 0–100 risk score, and executes Model 1 classification. | PyMuPDF, Tesseract OCR, OpenCV, Verhoeff $D_5$, Luhn Mod-10 | Raw uploaded files deleted immediately via `try/finally`. Only masked text preview (`XXXX-1234`) and findings persisted. |
| **Exposure Monitor** | Ingests identity footprint queries, extracts named entities via custom regex NER, classifies footprint sensitivity via TF-IDF + Random Forest, and detects behavioral anomalies via Isolation Forest. | Custom NER, Scikit-learn TF-IDF, Random Forest, Isolation Forest | Query identifiers converted to SHA-256 hash. Entity values stored only as masked strings. |
| **Breach Monitor** | Queries email addresses against local synthetic corporate incident catalogs using SHA-256 hashes, classifies remediation priority via Model 3, and generates actionable advice. | Pluggable `BreachProvider` Adapter, Random Forest Classifier | Query email stored exclusively as SHA-256 hex digest. No live network scraping. |
| **Unified Dashboard** | Synthesizes scores from all 3 modules into a single 0–100 composite threat score with dynamic active-module normalization, projects risk onto 5 threat vectors, and deduplicates recommendations. | Deterministic Composite Scorer, Recharts Radar/Area/Bar | Aggregated dynamically across user-isolated tables. Zero cross-tenant data leaks. |

---

## 3. Database Architecture (Entity-Relationship Model)

The database schema is managed via **Flask-Migrate (Alembic)** and enforced with strict foreign-key cascades and unique indexes.

### 3.1 Mermaid ER Diagram

```mermaid
erDiagram
    users ||--o{ refresh_tokens : "authenticates"
    users ||--o{ documents : "uploads"
    users ||--o{ exposure_records : "analyzes"
    users ||--o{ breach_queries : "initiates"
    users ||--o{ recommendations : "receives"

    documents ||--o{ pii_findings : "contains"
    breach_queries ||--o{ breach_incidents : "matches"

    users {
        uuid id PK
        string email UK
        string username UK
        string password_hash
        string full_name
        boolean is_active
        timestamp created_at
        timestamp updated_at
        timestamp last_login
    }

    refresh_tokens {
        uuid id PK
        uuid user_id FK
        string token_hash UK
        uuid token_family
        timestamp created_at
        timestamp expires_at
        timestamp revoked_at
        uuid replaced_by FK
    }

    documents {
        uuid id PK
        uuid user_id FK
        string original_filename
        string file_type
        integer file_size
        string file_hash
        string extracted_text_preview
        integer pii_count
        integer high_risk_count
        float risk_score
        string risk_level
        string ml_classification
        float ml_confidence
        json score_explanation
        timestamp scanned_at
        timestamp created_at
    }

    pii_findings {
        uuid id PK
        uuid document_id FK
        string pii_type
        string masked_value
        float confidence
        string severity
        boolean checksum_valid
        string detection_method
        string context_snippet
        integer position_start
        integer position_end
        timestamp created_at
    }

    exposure_records {
        uuid id PK
        uuid user_id FK
        string query_type
        string query_value_hash
        integer total_entities
        integer sensitive_count
        integer financial_count
        integer credential_count
        float exposure_score
        string exposure_level
        string sensitivity_label
        float sensitivity_confidence
        boolean is_anomalous
        float anomaly_score
        json category_scores
        json entity_summary
        timestamp analyzed_at
        timestamp created_at
    }

    breach_queries {
        uuid id PK
        uuid user_id FK
        string query_email_hash
        integer breach_count
        integer total_exposures
        string priority_label
        float priority_confidence
        float breach_risk_score
        string breach_risk_level
        json exposure_summary
        timestamp checked_at
        timestamp created_at
    }

    breach_incidents {
        uuid id PK
        string name UK
        string organization
        date breach_date
        date discovered_date
        text description
        integer affected_count
        json exposed_data_types
        string severity
        boolean is_synthetic
        timestamp created_at
    }

    recommendations {
        uuid id PK
        uuid user_id FK
        uuid document_id FK "nullable"
        uuid exposure_record_id FK "nullable"
        uuid breach_query_id FK "nullable"
        string source_module
        string category
        string priority
        string title
        text description
        string action_type
        boolean is_dismissed
        timestamp created_at
    }
```

### 3.2 Relational Performance Indexes

| Table | Index Columns | Type | Purpose |
|---|---|---|---|
| `users` | `email` | UNIQUE B-Tree | O(1) login lookup |
| `users` | `username` | UNIQUE B-Tree | O(1) username availability check |
| `refresh_tokens` | `token_hash` | UNIQUE B-Tree | Fast token rotation verification |
| `refresh_tokens` | `(token_family, revoked_at)` | Composite B-Tree | Immediate token family revocation upon reuse theft |
| `documents` | `(user_id, created_at DESC)` | Composite B-Tree | Fast user-isolated document history pagination |
| `pii_findings` | `document_id` | B-Tree | Rapid retrieval of findings for a given document |
| `exposure_records` | `(user_id, created_at DESC)` | Composite B-Tree | Fast user-isolated exposure audit history pagination |
| `breach_queries` | `(user_id, created_at DESC)` | Composite B-Tree | Fast user-isolated breach query history |
| `recommendations` | `(user_id, is_dismissed, created_at DESC)` | Composite B-Tree | Instant filtering of active recommendations for dashboard |

---

## 4. Data Flow Diagrams (DFD)

### 4.1 DFD Level 0 — System Context Diagram

```mermaid
flowchart LR
    User([Authenticated User])
    System[[Intel-Protect Platform]]
    Storage[(Encrypted PostgreSQL Database)]
    Models[(Trained ML Artifacts)]

    User -->|"Upload Document / Input Query"| System
    System -->|"Masked Findings, Risk Gauges, Advice"| User
    System <-->|"Store & Query Masked Telemetry"| Storage
    System <-->|"Feature Vectors / Classification"| Models
```

### 4.2 DFD Level 1 — Decomposed Operational Flow

```mermaid
flowchart TD
    User([User])
    
    subgraph P1["Process 1: Authentication & Token Management"]
        P1_1["1.1 Hash & Verify Credentials (Argon2id)"]
        P1_2["1.2 Generate Access Token & Rotated Refresh Token"]
    end

    subgraph P2["Process 2: Document Ingestion & Verification"]
        P2_1["2.1 Validate Magic Bytes & Ingest Stream"]
        P2_2["2.2 PyMuPDF / Tesseract OCR Text Extraction"]
        P2_3["2.3 Regex & Verhoeff/Luhn Checksum Verification"]
        P2_4["2.4 Centralized Value Masking"]
        P2_5["2.5 Compute Deterministic Privacy Score & ML Sensitivity"]
    end

    subgraph P3["Process 3: Exposure Footprint & Anomaly Analysis"]
        P3_1["3.1 Hash Query & Extract Named Entities"]
        P3_2["3.2 TF-IDF Vectorization & RF Classification"]
        P3_3["3.3 Isolation Forest Behavioral Anomaly Scoring"]
    end

    subgraph P4["Process 4: Breach Catalog & Remediation"]
        P4_1["4.1 SHA-256 Hash Query Email"]
        P4_2["4.2 Query Synthetic Breach Catalog"]
        P4_3["4.3 RF Priority Classifier (Model 3)"]
        P4_4["4.4 Generate Actionable Remediation Items"]
    end

    subgraph P5["Process 5: Unified Cockpit Aggregation"]
        P5_1["5.1 Retrieve Active Module Telemetry"]
        P5_2["5.2 Compute Normalized Composite Risk Score"]
        P5_3["5.3 Deduplicate Cross-Module Recommendations"]
    end

    DB_USERS[(users / tokens)]
    DB_DOCS[(documents / findings)]
    DB_EXP[(exposure_records)]
    DB_BRCH[(breach_queries)]
    DB_REC[(recommendations)]

    User -->|"Credentials"| P1_1
    P1_1 --> P1_2
    P1_2 --> DB_USERS
    P1_2 -->|"JWT + Cookie"| User

    User -->|"File Upload"| P2_1
    P2_1 --> P2_2 --> P2_3 --> P2_4 --> P2_5
    P2_5 --> DB_DOCS
    P2_5 -->|"Masked Report"| User

    User -->|"Identity Query"| P3_1
    P3_1 --> P3_2 --> P3_3
    P3_3 --> DB_EXP
    P3_3 -->|"Exposure Radar"| User

    User -->|"Email Check"| P4_1
    P4_1 --> P4_2 --> P4_3 --> P4_4
    P4_4 --> DB_BRCH
    P4_4 --> DB_REC
    P4_4 -->|"Breach Alert"| User

    User -->|"Open Dashboard"| P5_1
    DB_DOCS & DB_EXP & DB_BRCH & DB_REC --> P5_1
    P5_1 --> P5_2 --> P5_3
    P5_3 -->|"Unified Cockpit Payload"| User
```

---

## 5. End-to-End Sequence Diagrams

### 5.1 Document Ingestion & Mathematical Checksum Verification

```mermaid
sequenceDiagram
    autonumber
    actor User as Client Browser
    participant Flask as Flask API Gateway
    participant FS as Local Filesystem (/temp/uploads)
    participant Extractor as Extraction Engine (PyMuPDF / OCR)
    participant PII as Deterministic PII Engine
    participant Checksum as Mathematical Checksum Validator
    participant Masker as Centralized Masker
    participant Scorer as Document Privacy Risk Scorer
    participant ML as ML Registry (Model 1)
    participant DB as PostgreSQL Database

    User->>Flask: POST /api/documents/scan (multipart/form-data + Bearer JWT)
    Flask->>Flask: Validate JWT & User Context
    Flask->>Flask: Verify MIME magic bytes (puremagic) & file size limit (10MB)
    Flask->>FS: Save temporary file with UUID name (<uuid>.tmp)
    
    rect rgb(240, 248, 255)
        Note over Flask,Extractor: Transient Processing (try/finally enforced)
        alt Native PDF
            Flask->>Extractor: PyMuPDF stream extract text
        else Scanned PDF / Image (PNG/JPEG)
            Flask->>Extractor: OpenCV deskew + Tesseract OCR
        else Plaintext (.txt)
            Flask->>Extractor: UTF-8 stream read
        end
        Extractor-->>Flask: Raw Extracted Text
    end

    Flask->>FS: Unlink & delete temporary file immediately
    
    Flask->>PII: Scan text for candidate patterns
    PII->>Checksum: Validate Aadhaar candidates via Verhoeff (D5 group)
    Checksum-->>PII: Checksum validity boolean
    PII->>Checksum: Validate Payment Card candidates via Luhn (Mod-10)
    Checksum-->>PII: Checksum validity boolean
    PII-->>Flask: Raw findings list with positions and confidence

    Flask->>Masker: Mask raw PII values (Aadhaar -> XXXX-XXXX-1234, etc.)
    Masker-->>Flask: Masked preview and findings

    Flask->>Scorer: Calculate deterministic score (diminishing returns formula)
    Scorer-->>Flask: Risk Score [0, 100], Level, Breakdown explanation

    Flask->>ML: Classify document sensitivity tier
    ML-->>Flask: ML Risk Label (LOW/MEDIUM/HIGH/CRITICAL), Confidence

    Flask->>DB: INSERT INTO documents & pii_findings (Masked data only)
    DB-->>Flask: Persisted UUID records

    Flask-->>User: HTTP 201 Created (Safe Masked JSON payload)
```

### 5.2 Exposure Analysis & Anomaly Detection Sequence

```mermaid
sequenceDiagram
    autonumber
    actor User as Client Browser
    participant Flask as Exposure Blueprint
    participant NER as Custom Regex NER
    participant Scorer as Synergistic Scorer
    participant Vectorizer as TF-IDF Vectorizer (Persisted)
    participant RF as Random Forest Classifier (Model 2)
    participant IF as Isolation Forest (Anomaly Detector)
    participant DB as PostgreSQL Database

    User->>Flask: POST /api/exposure/analyze (JSON identifiers + Bearer JWT)
    Flask->>Flask: Marshmallow schema validation
    Flask->>Flask: Hash primary identifier with SHA-256
    Flask->>NER: Parse text/identifiers for entities (PERSON, EMAIL, PHONE, LOCATION, etc.)
    NER-->>Flask: Extracted entities list (all values pre-masked)

    Flask->>Scorer: Compute synergistic exposure score (accounts for Identity+Contact+Financial triads)
    Scorer-->>Flask: Exposure Score [0, 100], Category scores

    Flask->>Vectorizer: Transform entity features into TF-IDF sparse matrix
    Vectorizer-->>Flask: TF-IDF feature vector
    Flask->>RF: Predict footprint sensitivity
    RF-->>Flask: Sensitivity Label, Confidence

    Flask->>IF: Evaluate behavioral anomaly score
    IF-->>Flask: Anomaly Score [0.0, 1.0], is_anomalous boolean

    Flask->>DB: INSERT INTO exposure_records (Masked entities, score, anomaly status)
    DB-->>Flask: Record created
    Flask-->>User: HTTP 201 Created (Radar metrics + Anomaly badge)
```

---

## 6. Algorithmic & Mathematical Formulations

### 6.1 Verhoeff Dihedral Group ($D_5$) Checksum Algorithm
Used to validate 12-digit Indian **Aadhaar** numbers without false-positive identification. It operates on permutations of the dihedral group $D_5$ of order 10:

$$\left(\sum_{i=1}^{n} d\left(c, p(i \bmod 8, a_i)\right)\right) = 0$$

Where:
- $d(j, k)$ is the non-commutative group operation table for $D_5$.
- $p(i, j)$ is the permutation table based on the permutation $(1 5 8 9 4 2 7 0)(3 6)$.
- $c$ is the check digit appended such that the total multiplication equals the identity element $0$.

### 6.2 Luhn Modulus 10 Algorithm
Used to validate 13–19 digit **Credit/Debit Payment Cards**:

$$\left(\sum_{i=0}^{n-1} f(c_i)\right) \equiv 0 \pmod{10}$$

Where $f(c_i)$ doubles every second digit from the rightmost digit:

$$f(c_i) = \begin{cases} c_i & \text{if position is even} \\ 2c_i & \text{if } 2c_i < 10 \\ 2c_i - 9 & \text{if } 2c_i \ge 10 \end{cases}$$

### 6.3 Deterministic Privacy Risk Monotonic Saturation Formula
Document privacy risk is computed using an exponential diminishing-returns saturation model to ensure monotonicity, transparency, and strict bounding in $[0, 100]$:

$$\text{Raw Score} = \sum_{t \in \text{findings}} w_t \times \text{confidence}_t \times \text{checksum\_mult}_t$$

$$\text{Risk Score} = 100 \times \left(1 - e^{-\frac{\text{Raw Score}}{K}}\right) \times \text{Diversity Multiplier}$$

Where:
- $w_t \in \{10, 20, 30, 40\}$ represents severity weight (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- $\text{checksum\_mult} = 1.0$ for structurally validated numbers, $0.5$ for structurally unverified.
- $K = 50$ is the saturation scaling constant.
- $\text{Diversity Multiplier} = 1.0 + 0.05 \times (\text{distinct PII types} - 1)$, capped at $1.25$.

### 6.4 Unified Composite Risk Formula with Dynamic Active Normalization
The unified cockpit combines scores across Document ($D$), Exposure ($E$), and Breach ($B$) modules using an approved design formula:

$$\text{Base Weights:} \quad W_{\text{doc}} = 0.30, \quad W_{\text{exp}} = 0.35, \quad W_{\text{brch}} = 0.35$$

$$\text{Normalized Weight for active module } m: \quad \bar{w}_m = \frac{W_m}{\sum_{k \in M_{\text{active}}} W_k}$$

$$\text{Overall Threat Score} = \begin{cases} 0.0 & \text{if } M_{\text{active}} = \emptyset \\ \sum_{m \in M_{\text{active}}} \bar{w}_m \times \text{Score}_m & \text{otherwise} \end{cases}$$

This mathematical property guarantees that new users receive a baseline $0.0$ (`LOW`) score without artificial penalty, and partial users are evaluated purely on the data they have provided.
