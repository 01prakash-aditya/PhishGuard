"""
PhishGuard++ — Dataset Builder
Merges all 5 data sources into a unified corpus for model training.

Datasets:
  1. Kaggle UCI           — Pre-computed features + label (Result column)
  2. PhiUSIIL             — URLs + 50+ features + label
  3. PhishTank            — Verified phishing URLs (all label=1)
  4. Tranco Top 1M        — Legitimate domains (all label=0)
  5. Mendeley Phishing    — URLs + HTML files + labels from SQL

Output:
  datasets/unified_urls.csv     — url, label, source
  datasets/unified_features.csv — url, 40 engineered features, label
"""

import os
import re
import pandas as pd
import numpy as np
from pathlib import Path
from tqdm import tqdm
import logging
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

#  Paths 
BASE_DIR   = Path(__file__).resolve().parent.parent.parent
DATA_DIR   = BASE_DIR / "datasets"
OUTPUT_DIR = DATA_DIR / "processed"

CURATED_LEGITIMATE_URLS = [
    # Government and public services
    "https://www.irs.gov/payments/your-online-account",
    "https://www.usa.gov/",
    "https://secure.login.gov/",
    "https://www.ssa.gov/myaccount/",
    "https://www.va.gov/sign-in/",
    "https://www.cdc.gov/",
    "https://www.nih.gov/",
    "https://home.treasury.gov/",
    "https://www.cms.gov/",
    "https://www.india.gov.in/my-government",
    "https://www.incometax.gov.in/iec/foportal/",
    "https://uidai.gov.in/",
    "https://www.gst.gov.in/",
    "https://www.passportindia.gov.in/",
    "https://www.epfindia.gov.in/site_en/index.php",
    "https://www.digilocker.gov.in/",
    "https://www.mygov.in/",
    # Enterprise and financial login/account flows
    "https://accounts.google.com/",
    "https://login.microsoftonline.com/",
    "https://account.microsoft.com/",
    "https://appleid.apple.com/",
    "https://www.amazon.com/ap/signin",
    "https://www.paypal.com/signin",
    "https://github.com/login",
    "https://www.linkedin.com/login",
    "https://www.netflix.com/login",
    "https://account.adobe.com/",
    "https://onlinesbi.sbi/",
    "https://www.hdfcbank.com/personal/login",
    "https://www.icicibank.com/personal-banking/insta-banking/internet-banking",
    "https://www.irctc.co.in/nget/train-search",
    "https://www.chase.com/",
    "https://www.wellsfargo.com/",
    "https://www.bankofamerica.com/",
    "https://www.citi.com/",
    "https://www.fedex.com/",
    "https://www.dhl.com/",
    "https://www.ups.com/",
    "https://www.usps.com/",
]

BENIGN_AUTH_PATHS = [
    "", "/login", "/signin", "/account", "/my-account", "/secure",
    "/verify", "/payments", "/support", "/contact", "/help",
]

IMPERSONATED_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "netflix", "linkedin", "adobe", "sbi", "hdfc", "icici", "irctc",
    "irs", "uidai", "gst",
]

PHISH_TLDS = ["xyz", "top", "info", "site", "online", "click", "live", "shop"]


def normalize_url(value: str) -> str:
    """Normalize domains/paths from mixed CSV feeds into parseable HTTPS URLs."""
    raw = str(value or "").strip()
    if not raw or raw.lower() == "nan":
        return ""
    if raw.startswith("//"):
        return f"https:{raw}"
    if "://" not in raw:
        return f"https://{raw.lstrip('/')}"
    return raw


def _base_origin(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    if not parsed.netloc:
        return normalize_url(url).rstrip("/")
    return f"{parsed.scheme or 'https'}://{parsed.netloc}"


def build_curated_legitimate() -> pd.DataFrame:
    """Hard negatives: legitimate government/company URLs with auth-like paths."""
    records = []
    seen = set()
    for url in CURATED_LEGITIMATE_URLS:
        normalized = normalize_url(url)
        origin = _base_origin(normalized)
        candidates = [normalized] + [f"{origin}{path}" for path in BENIGN_AUTH_PATHS if path]
        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            records.append({
                "url": candidate,
                "label": 0,
                "source": "curated_legit_hard_negative",
            })
    return pd.DataFrame(records)


def build_curated_phishing() -> pd.DataFrame:
    """Hard positives: brand/government impersonation across deceptive domains."""
    records = []
    for idx, brand in enumerate(IMPERSONATED_BRANDS):
        for tld in PHISH_TLDS:
            records.extend([
                {
                    "url": f"https://{brand}-secure-login.{tld}/account/verify?id={1000 + idx}",
                    "label": 1,
                    "source": "curated_phish_impersonation",
                },
                {
                    "url": f"https://secure-{brand}.customer-verify.{tld}/signin",
                    "label": 1,
                    "source": "curated_phish_impersonation",
                },
                {
                    "url": f"https://account-update.{tld}/{brand}/validate/password",
                    "label": 1,
                    "source": "curated_phish_impersonation",
                },
            ])
    records.extend([
        {"url": "https://irs.gov.secure-tax-refund.example.com/login", "label": 1, "source": "curated_phish_impersonation"},
        {"url": "https://login.gov.verify-account.example.net/secure", "label": 1, "source": "curated_phish_impersonation"},
        {"url": "https://uidai.gov.in.kyc-update.example.org/otp", "label": 1, "source": "curated_phish_impersonation"},
    ])
    return pd.DataFrame(records)


def balance_binary_corpus(df: pd.DataFrame, majority_ratio: float = 1.25) -> pd.DataFrame:
    """Keep class balance tight so the model does not learn a phish-biased prior."""
    counts = df["label"].value_counts()
    if len(counts) < 2:
        return df

    minority_label = counts.idxmin()
    majority_label = counts.idxmax()
    minority_count = counts[minority_label]
    max_majority = int(minority_count * majority_ratio)

    majority_df = df[df["label"] == majority_label]
    minority_df = df[df["label"] == minority_label]
    if len(majority_df) > max_majority:
        majority_df = majority_df.sample(n=max_majority, random_state=42)

    balanced = pd.concat([minority_df, majority_df], ignore_index=True)
    return balanced.sample(frac=1.0, random_state=42).reset_index(drop=True)


def load_kaggle_uci() -> pd.DataFrame:
    """Load Kaggle UCI phishing dataset.
    Columns are pre-computed binary features + 'Result' label (-1=phishing, 1=legit).
    We keep only the label; features are re-extracted from URLs in PhiUSIIL.
    """
    path = DATA_DIR / "Kaggle_UCI.csv"
    logger.info(f"Loading Kaggle UCI from {path}")
    df = pd.read_csv(path)

    # The 'Result' column: -1 = phishing, 1 = legitimate
    # We don't have raw URLs here, so we skip this for URL merging
    # but keep it for the ablation baseline (pre-computed features)
    df["label"] = df["Result"].map({-1: 1, 1: 0})  # 1=phishing, 0=legit
    df["source"] = "kaggle_uci"
    logger.info(f"  → {len(df)} rows ({df['label'].sum()} phishing, {(df['label']==0).sum()} legit)")
    return df


def load_phiusiil() -> pd.DataFrame:
    """Load PhiUSIIL dataset — has URLs + 50+ pre-computed features + label."""
    path = DATA_DIR / "PhiUSIIL_Phishing_URL_Dataset.csv"
    logger.info(f"Loading PhiUSIIL from {path}")
    df = pd.read_csv(path)

    # 'label' column: 1 = phishing, 0 = legitimate
    df["source"] = "phiusiil"
    logger.info(f"  → {len(df)} rows ({df['label'].sum()} phishing, {(df['label']==0).sum()} legit)")
    return df


def load_phishtank() -> pd.DataFrame:
    """Load PhishTank — all verified phishing URLs."""
    path = DATA_DIR / "PhishTank.csv"
    logger.info(f"Loading PhishTank from {path}")
    df = pd.read_csv(path)

    if "verified" in df.columns:
        df = df[df["verified"].astype(str).str.lower().eq("yes")]
    if "online" in df.columns:
        online_df = df[df["online"].astype(str).str.lower().eq("yes")]
        if len(online_df) > 0:
            df = online_df

    # Keep only essential columns
    df = df[["url"]].copy()
    df["url"] = df["url"].apply(normalize_url)
    df = df[df["url"] != ""]
    df["label"] = 1  # All phishing
    df["source"] = "phishtank"
    df = df.drop_duplicates(subset=["url"])
    logger.info(f"  → {len(df)} phishing URLs")
    return df


def load_tranco() -> pd.DataFrame:
    """Load Tranco Top 1M — popular legitimate domains.
    Format: rank,domain (no header in some versions).
    """
    path = DATA_DIR / "Tranco_top_1m.csv"
    logger.info(f"Loading Tranco from {path}")

    # Try to detect if there's a header
    df = pd.read_csv(path, header=None, names=["rank", "domain"])

    # Convert mixed domain/path rows to full URLs for feature extraction
    df["url"] = df["domain"].apply(normalize_url)
    df = df[df["url"] != ""]
    df["label"] = 0  # All legitimate
    df["source"] = "tranco"
    df = df[["url", "label", "source"]].copy()
    logger.info(f"  → {len(df)} legitimate domains")
    return df


def load_mendeley_sql() -> pd.DataFrame:
    """Parse the Mendeley SQL dump to extract URL → label → HTML filename mapping."""
    sql_path = DATA_DIR / "Mendeley phishing dataset" / "index.sql"
    logger.info(f"Loading Mendeley SQL from {sql_path}")

    with open(sql_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # Parse INSERT statements
    # Pattern: (rec_id, 'url', 'filename', label, 'timestamp')
    pattern = r"\((\d+),\s*'([^']*)',\s*'([^']*)',\s*(\d+),\s*'([^']*)'\)"
    matches = re.findall(pattern, content)

    records = []
    for match in matches:
        rec_id, url, filename, label, timestamp = match
        records.append({
            "rec_id": int(rec_id),
            "url": url,
            "html_filename": filename,
            "label": int(label),  # 0=legit, 1=phishing
            "timestamp": timestamp,
        })

    df = pd.DataFrame(records)
    df["source"] = "mendeley"

    # Verify HTML files exist
    html_dir = DATA_DIR / "Mendeley phishing dataset"
    df["html_exists"] = df["html_filename"].apply(
        lambda f: (html_dir / f).exists()
    )

    existing = df["html_exists"].sum()
    logger.info(f"  → {len(df)} rows ({df['label'].sum()} phishing, {(df['label']==0).sum()} legit)")
    logger.info(f"  → {existing}/{len(df)} HTML files found on disk")
    return df


def build_unified_url_corpus(
    max_tranco: int | None = None,
    max_phishtank: int | None = None,
    balance: bool = True,
) -> pd.DataFrame:
    """
    Build unified URL corpus from all sources.

    Returns DataFrame with columns: url, label, source
    """
    logger.info("=" * 60)
    logger.info("Building unified URL corpus")
    logger.info("=" * 60)

    frames = []

    # 1. PhiUSIIL — has both URLs and labels
    try:
        phiusiil = load_phiusiil()
        phiusiil = phiusiil[["URL", "label", "source"]].rename(columns={"URL": "url"})
        phiusiil["url"] = phiusiil["url"].apply(normalize_url)
        phiusiil = phiusiil[phiusiil["url"] != ""]
        frames.append(phiusiil)
    except Exception as e:
        logger.warning(f"Skipping PhiUSIIL: {e}")

    # 2. PhishTank — all phishing
    try:
        phishtank = load_phishtank()
        if max_phishtank is not None and len(phishtank) > max_phishtank:
            phishtank = phishtank.sample(n=max_phishtank, random_state=42)
        frames.append(phishtank[["url", "label", "source"]])
    except Exception as e:
        logger.warning(f"Skipping PhishTank: {e}")

    # 3. Tranco — all legitimate
    try:
        tranco = load_tranco()
        if max_tranco is not None and len(tranco) > max_tranco:
            tranco = tranco.head(max_tranco)  # Top-ranked domains are most legitimate
        frames.append(tranco[["url", "label", "source"]])
    except Exception as e:
        logger.warning(f"Skipping Tranco: {e}")

    # 4. Mendeley — has URLs and labels
    try:
        mendeley = load_mendeley_sql()
        frames.append(mendeley[["url", "label", "source"]])
    except Exception as e:
        logger.warning(f"Skipping Mendeley: {e}")

    try:
        curated_legit = build_curated_legitimate()
        frames.append(curated_legit)
        logger.info(f"Added {len(curated_legit)} curated legitimate hard negatives")
    except Exception as e:
        logger.warning(f"Skipping curated legitimate hard negatives: {e}")

    try:
        curated_phish = build_curated_phishing()
        frames.append(curated_phish)
        logger.info(f"Added {len(curated_phish)} curated phishing hard positives")
    except Exception as e:
        logger.warning(f"Skipping curated phishing hard positives: {e}")

    if not frames:
        logger.error("No datasets could be loaded!")
        raise ValueError("No datasets available.")

    # Merge
    unified = pd.concat(frames, ignore_index=True)

    # Deduplicate by URL (keep first occurrence)
    before = len(unified)
    unified = unified.drop_duplicates(subset=["url"], keep="first")
    logger.info(f"Deduplication: {before} → {len(unified)} ({before - len(unified)} duplicates removed)")

    # Stats
    logger.info("\n Unified Corpus Stats ")
    logger.info(f"Total samples:  {len(unified)}")
    logger.info(f"Phishing (1):   {(unified['label']==1).sum()}")
    logger.info(f"Legitimate (0): {(unified['label']==0).sum()}")
    logger.info(f"Balance ratio:  {(unified['label']==1).sum() / len(unified):.2%}")
    logger.info(f"\nSources:\n{unified['source'].value_counts().to_string()}")

    return unified


def create_train_val_test_split(
    df: pd.DataFrame,
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    test_ratio: float = 0.1,
    random_state: int = 42,
) -> dict:
    """Stratified train/val/test split."""
    from sklearn.model_selection import train_test_split

    assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-6

    # First split: train vs (val + test)
    train_df, temp_df = train_test_split(
        df, test_size=(val_ratio + test_ratio),
        stratify=df["label"], random_state=random_state,
    )

    # Second split: val vs test
    relative_test = test_ratio / (val_ratio + test_ratio)
    val_df, test_df = train_test_split(
        temp_df, test_size=relative_test,
        stratify=temp_df["label"], random_state=random_state,
    )

    logger.info(f"\nSplit sizes:")
    logger.info(f"  Train: {len(train_df)} ({len(train_df)/len(df):.1%})")
    logger.info(f"  Val:   {len(val_df)} ({len(val_df)/len(df):.1%})")
    logger.info(f"  Test:  {len(test_df)} ({len(test_df)/len(df):.1%})")

    return {"train": train_df, "val": val_df, "test": test_df}


def main():
    """Build and save the unified dataset."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Build unified URL corpus
    unified = build_unified_url_corpus()

    # Save full corpus
    out_path = OUTPUT_DIR / "unified_urls.csv"
    unified.to_csv(out_path, index=False)
    logger.info(f"\nSaved unified corpus to {out_path}")

    # Create splits
    splits = create_train_val_test_split(unified)
    for split_name, split_df in splits.items():
        split_path = OUTPUT_DIR / f"{split_name}_urls.csv"
        split_df.to_csv(split_path, index=False)
        logger.info(f"Saved {split_name} to {split_path}")

    # Save Mendeley metadata separately (for HTML feature extraction)
    try:
        mendeley = load_mendeley_sql()
        mendeley_path = OUTPUT_DIR / "mendeley_metadata.csv"
        mendeley.to_csv(mendeley_path, index=False)
        logger.info(f"Saved Mendeley metadata to {mendeley_path}")
    except Exception as e:
        logger.warning(f"Could not generate mendeley_metadata.csv: {e}")
        pd.DataFrame(columns=["rec_id","url","html_filename","label","timestamp","source","html_exists"]).to_csv(OUTPUT_DIR / "mendeley_metadata.csv", index=False)

    logger.info("\n Dataset building complete!")


if __name__ == "__main__":
    main()
