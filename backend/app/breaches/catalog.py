"""
Synthetic Breach Catalog & Seeding Engine.
Maintains realistic synthetic breach incidents for threat intelligence evaluation.
"""
from datetime import date, datetime, timezone
import logging
from backend.app import db
from backend.app.models.breach import Breach

logger = logging.getLogger(__name__)

SYNTHETIC_BREACH_CATALOG = [
    {
        "name": "MegaCorp Core",
        "organization": "MegaCorp Global Inc.",
        "breach_date": date(2023, 4, 12),
        "discovered_date": date(2023, 4, 15),
        "description": "Unauthorized exfiltration of corporate directory database containing hashed credentials and employee contacts.",
        "affected_count": 2500000,
        "exposed_data_types": ["EMAIL", "PASSWORD_HASH", "USERNAME", "PHONE"],
        "severity": "HIGH",
        "is_synthetic": True,
    },
    {
        "name": "FastPay Gateway",
        "organization": "FastPay Technologies Ltd.",
        "breach_date": date(2024, 1, 20),
        "discovered_date": date(2024, 1, 24),
        "description": "SQL injection vulnerability exposed encrypted payment records, partial card numbers, and linked bank accounts.",
        "affected_count": 1800000,
        "exposed_data_types": ["EMAIL", "CARD", "FINANCIAL", "BANK_ACCOUNT", "PASSWORD_HASH"],
        "severity": "CRITICAL",
        "is_synthetic": True,
    },
    {
        "name": "HealthPlus Portal",
        "organization": "HealthPlus Healthcare Systems",
        "breach_date": date(2023, 9, 5),
        "discovered_date": date(2023, 9, 10),
        "description": "Misconfigured cloud storage bucket exposed patient KYC records containing Aadhaar identifiers and personal phone numbers.",
        "affected_count": 3200000,
        "exposed_data_types": ["EMAIL", "AADHAAR", "IDENTITY", "PHONE", "ADDRESS", "DOB"],
        "severity": "CRITICAL",
        "is_synthetic": True,
    },
    {
        "name": "ShopEasy Direct",
        "organization": "ShopEasy E-Commerce Ltd.",
        "breach_date": date(2022, 11, 15),
        "discovered_date": date(2022, 11, 20),
        "description": "Exposed customer shipping database containing delivery addresses, names, and contact phone numbers.",
        "affected_count": 850000,
        "exposed_data_types": ["EMAIL", "PHONE", "ADDRESS", "USERNAME"],
        "severity": "MEDIUM",
        "is_synthetic": True,
    },
    {
        "name": "CloudDev Forge",
        "organization": "CloudDev Systems Inc.",
        "breach_date": date(2024, 6, 18),
        "discovered_date": date(2024, 6, 21),
        "description": "Compromised CI/CD server exposed developer authentication tokens, API secrets, and repository passwords.",
        "affected_count": 420000,
        "exposed_data_types": ["EMAIL", "API_SECRET", "CREDENTIAL", "PASSWORD_HASH", "USERNAME"],
        "severity": "CRITICAL",
        "is_synthetic": True,
    },
    {
        "name": "AeroFly Booking",
        "organization": "AeroFly Airlines",
        "breach_date": date(2022, 5, 30),
        "discovered_date": date(2022, 6, 5),
        "description": "Booking reservation system breach leaking passenger travel itineraries and identity documents.",
        "affected_count": 1200000,
        "exposed_data_types": ["EMAIL", "PASSPORT", "NAME", "PHONE"],
        "severity": "MEDIUM",
        "is_synthetic": True,
    },
    {
        "name": "EduLearn Academy",
        "organization": "EduLearn Online Education Inc.",
        "breach_date": date(2021, 8, 10),
        "discovered_date": date(2021, 8, 18),
        "description": "Forum database scrape containing public user profiles, display handles, and registration emails.",
        "affected_count": 350000,
        "exposed_data_types": ["EMAIL", "USERNAME"],
        "severity": "LOW",
        "is_synthetic": True,
    },
    {
        "name": "FinSecure Ledger",
        "organization": "FinSecure Banking Solutions",
        "breach_date": date(2024, 8, 1),
        "discovered_date": date(2024, 8, 4),
        "description": "Ransomware exfiltration incident impacting loan applicants' PAN numbers and direct deposit accounts.",
        "affected_count": 950000,
        "exposed_data_types": ["EMAIL", "PAN", "BANK_ACCOUNT", "PHONE", "PASSWORD_HASH"],
        "severity": "CRITICAL",
        "is_synthetic": True,
    },
    {
        "name": "SocialPulse Connect",
        "organization": "SocialPulse Media Corp.",
        "breach_date": date(2023, 2, 14),
        "discovered_date": date(2023, 2, 18),
        "description": "API scraping event exposing user contact directories and geographic login IP records.",
        "affected_count": 5400000,
        "exposed_data_types": ["EMAIL", "PHONE", "USERNAME", "IP"],
        "severity": "MEDIUM",
        "is_synthetic": True,
    },
    {
        "name": "GameZone Arena",
        "organization": "GameZone Interactive Studios",
        "breach_date": date(2022, 7, 22),
        "discovered_date": date(2022, 7, 28),
        "description": "Legacy gaming forum vulnerability leaking gamertags, emails, and birthdays.",
        "affected_count": 670000,
        "exposed_data_types": ["EMAIL", "USERNAME", "DOB"],
        "severity": "LOW",
        "is_synthetic": True,
    },
]


def seed_synthetic_breaches():
    """
    Populates the breaches table with synthetic catalog records if not already present.
    """
    created_count = 0
    for b_data in SYNTHETIC_BREACH_CATALOG:
        existing = Breach.query.filter_by(name=b_data["name"]).first()
        if not existing:
            breach = Breach(
                name=b_data["name"],
                organization=b_data["organization"],
                breach_date=b_data["breach_date"],
                discovered_date=b_data["discovered_date"],
                description=b_data["description"],
                affected_count=b_data["affected_count"],
                exposed_data_types=b_data["exposed_data_types"],
                severity=b_data["severity"],
                is_synthetic=b_data["is_synthetic"],
                created_at=datetime.now(timezone.utc)
            )
            db.session.add(breach)
            created_count += 1

    if created_count > 0:
        db.session.commit()
        logger.info(f"Seeded {created_count} synthetic breach records into the database.")
