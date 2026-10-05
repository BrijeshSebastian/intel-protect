"""
Breach Provider Architecture (Adapter Pattern).
Defines the abstract BreachProvider interface and the default LocalBreachProvider.
"""
from abc import ABC, abstractmethod
import hashlib
import logging
from backend.app.models.breach import Breach
from backend.app.breaches.catalog import seed_synthetic_breaches

logger = logging.getLogger(__name__)


class BreachProvider(ABC):
    """Abstract interface for checking email addresses against breach repositories."""

    @abstractmethod
    def search_breaches(self, email: str) -> list[Breach]:
        """Returns list of Breach records matched for the provided email."""
        pass


class LocalBreachProvider(BreachProvider):
    """
    Default provider that matches synthetic breach records deterministically
    from the local catalog database without querying external networks.
    """

    def __init__(self):
        # Ensure database is seeded with synthetic catalog
        seed_synthetic_breaches()

    def search_breaches(self, email: str) -> list[Breach]:
        """
        Deterministically evaluates breach occurrences for an email address.
        """
        email_clean = email.strip().lower()
        all_breaches = Breach.query.order_by(Breach.name.asc()).all()
        if not all_breaches:
            return []

        # 1. Deterministic keyword overrides for testing
        if any(term in email_clean for term in ("clean", "safe", "unbreached", "zero")):
            return []

        if any(term in email_clean for term in ("critical", "victim", "triad", "hacked", "pwned")):
            # Match 3-4 critical breaches
            critical_names = {"FastPay Gateway", "HealthPlus Portal", "CloudDev Forge", "FinSecure Ledger"}
            return [b for b in all_breaches if b.name in critical_names]

        if any(term in email_clean for term in ("medium", "moderate")):
            # Match 1-2 medium breaches
            medium_names = {"ShopEasy Direct", "SocialPulse Connect"}
            return [b for b in all_breaches if b.name in medium_names]

        # 2. General Deterministic Hash-Bucket Resolution
        # Uses first 8 hex characters of SHA-256 for consistent deterministic mapping
        digest = hashlib.sha256(email_clean.encode("utf-8")).hexdigest()
        bucket = int(digest[:8], 16) % 10

        if bucket in (0, 1, 2):
            # 30% clean / unbreached
            return []
        elif bucket in (3, 4, 5):
            # 30% single low-to-medium breach
            idx = int(digest[8:12], 16) % len(all_breaches)
            return [all_breaches[idx]]
        elif bucket in (6, 7, 8):
            # 30% 2 breaches
            idx1 = int(digest[8:12], 16) % len(all_breaches)
            idx2 = (idx1 + 1 + (int(digest[12:16], 16) % (len(all_breaches) - 1))) % len(all_breaches)
            return [all_breaches[idx1], all_breaches[idx2]]
        else:
            # 10% severe (3 breaches)
            idx1 = int(digest[8:12], 16) % len(all_breaches)
            idx2 = (idx1 + 2) % len(all_breaches)
            idx3 = (idx1 + 4) % len(all_breaches)
            return [all_breaches[idx1], all_breaches[idx2], all_breaches[idx3]]


# Global default provider instance
_default_provider = None

def get_breach_provider() -> BreachProvider:
    """Factory retrieving the configured BreachProvider."""
    global _default_provider
    if _default_provider is None:
        _default_provider = LocalBreachProvider()
    return _default_provider
