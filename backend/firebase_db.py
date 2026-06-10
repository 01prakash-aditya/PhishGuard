import firebase_admin
from firebase_admin import credentials, firestore, db as rtdb
import logging
import os
from pathlib import Path
from datetime import datetime
import base64

logger = logging.getLogger(__name__)

# Singleton database reference
db = None
db_kind = None


def _resolve_credentials_path() -> Path | None:
    """Resolve Firebase credentials from env vars or known fallback locations."""
    candidate_paths = [
        os.getenv("FIREBASE_CREDENTIALS_PATH"),
        os.getenv("GOOGLE_APPLICATION_CREDENTIALS"),
        str(Path(__file__).parent / "firebase-adminsdk.json"),
        str(Path(__file__).resolve().parent.parent / "firebase-credentials.json"),
    ]

    for candidate in candidate_paths:
        if not candidate:
            continue
        path = Path(candidate).expanduser()
        if path.exists():
            return path
    return None


def _bind_database_client():
    """Attach the active database client after Firebase app initialization."""
    global db, db_kind

    database_url = os.getenv("FIREBASE_DATABASE_URL")
    if database_url:
        db = rtdb.reference("reported_urls")
        db_kind = "rtdb"
        logger.info("Community intel bound to Firebase Realtime Database.")
        return True

    try:
        db = firestore.client()
        db_kind = "firestore"
        logger.info("Community intel bound to Firebase Firestore.")
        return True
    except Exception as e:
        logger.error(f"Failed to bind Firebase database client: {e}")
        db = None
        db_kind = None
        return False

def init_firebase():
    """Initialize the Firebase Admin SDK."""
    global db
    try:
        cred_path = _resolve_credentials_path()
        if not cred_path:
            logger.error("Firebase credentials not found. Checked env vars and fallback paths.")
            return False

        if not firebase_admin._apps:
            init_kwargs = {}
            database_url = os.getenv("FIREBASE_DATABASE_URL")
            if database_url:
                init_kwargs["databaseURL"] = database_url
            cred = credentials.Certificate(str(cred_path))
            firebase_admin.initialize_app(cred, init_kwargs if init_kwargs else None)

        return _bind_database_client()
    except Exception as e:
        logger.error(f"Failed to initialize Firebase: {e}")
        db = None
        return False

def get_url_doc_id(url: str) -> str:
    """Safely encode a URL to be used as a Firestore document ID."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

def report_malicious_url(url: str, reason: str = ""):
    """Report a malicious URL, incrementing count and logging reasons."""
    if not db:
        logger.warning("Firebase not initialized. Cannot record report.")
        return False

    doc_id = get_url_doc_id(url)
    timestamp = datetime.utcnow()
    
    try:
        if db_kind == "rtdb":
            doc_ref = db.child(doc_id)
            existing = doc_ref.get()
            if existing:
                reasons = existing.get("reasons", []) or []
                if reason and reason not in reasons:
                    reasons.append(reason)

                doc_ref.update({
                    "report_count": int(existing.get("report_count", 0)) + 1,
                    "last_reported": timestamp.isoformat(),
                    "reasons": reasons,
                })
            else:
                doc_ref.set({
                    "url": url,
                    "report_count": 1,
                    "first_reported": timestamp.isoformat(),
                    "last_reported": timestamp.isoformat(),
                    "reasons": [reason] if reason else [],
                    "verdict": "PENDING"
                })
        else:
            doc_ref = db.collection("reported_urls").document(doc_id)
            doc = doc_ref.get()

            if doc.exists:
                data = doc.to_dict()
                reasons = data.get("reasons", [])
                # Append reason uniquely
                if reason and reason not in reasons:
                    reasons.append(reason)

                doc_ref.update({
                    "report_count": firestore.Increment(1),
                    "last_reported": timestamp,
                    "reasons": reasons
                })
            else:
                doc_ref.set({
                    "url": url,
                    "report_count": 1,
                    "first_reported": timestamp,
                    "last_reported": timestamp,
                    "reasons": [reason] if reason else [],
                    "verdict": "PENDING"
                })
        return True
    except Exception as e:
        logger.error(f"Failed to upsert report for {url}: {e}")
        return False

def get_community_trust(url: str) -> dict:
    """Fetch the community trust intelligence for a specific URL."""
    if not db:
        return {"found": False, "report_count": 0, "error": "DB_NOT_INITIALIZED"}
        
    try:
        doc_id = get_url_doc_id(url)
        if db_kind == "rtdb":
            data = db.child(doc_id).get()
            if data:
                return {
                    "found": True,
                    "report_count": data.get("report_count", 0),
                    "reasons": data.get("reasons", []),
                    "verdict": data.get("verdict", "PENDING")
                }
        else:
            doc = db.collection("reported_urls").document(doc_id).get()
            
            if doc.exists:
                data = doc.to_dict()
                return {
                    "found": True,
                    "report_count": data.get("report_count", 0),
                    "reasons": data.get("reasons", []),
                    "verdict": data.get("verdict", "PENDING")
                }
        
        return {
            "found": False,
            "report_count": 0
        }
    except Exception as e:
        logger.error(f"Failed to fetch community trust for {url}: {e}")
        return {"found": False, "report_count": 0, "error": str(e)}
