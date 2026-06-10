"""
PhishGuard++ — Cloud Backend (FastAPI)
Tier 2 (Cloud Classifier) & Tier 3 (Gemini Multi-modal) Orchestration
"""

import logging
import os
import asyncio
import httpx
import pandas as pd
from typing import Optional, Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google import genai
from dotenv import load_dotenv

# Absolute imports
from src.explainability.shap_pipeline import get_phish_explanation, FEATURE_ORDER
from src.features.url_features import extract_url_features, URL_FEATURE_NAMES
from src.features.html_features import HTML_FEATURE_NAMES
from src.models.gemini_llm import run_tier3_gemini

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="PhishGuard++ Cloud Backend")

# Allow Chrome extension and localhost to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalysisRequest(BaseModel):
    url: str
    htmlExcerpt: str
    screenshotBase64: Optional[str] = None
    features: Optional[Any] = None

class AnalysisResponse(BaseModel):
    verdict: str
    score: float
    tier: int
    reason: str

class ReportRequest(BaseModel):
    url: str
    reason: Optional[str] = ""
    
class TrustCheckResponse(BaseModel):
    found: bool
    report_count: int
    reasons: list
    verdict: str

#  Tier 2: Safe Browsing 
async def check_safe_browsing(url: str):
    """Hits Google Safe Browsing API to check for blacklisted URLs."""
    api_key = os.getenv("SAFE_BROWSING_API_KEY")
    if not api_key:
        return False, "API Key Missing"
    
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "phishguard-plus", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(endpoint, json=payload, timeout=2.0)
            data = resp.json()
            if "matches" in data and len(data["matches"]) > 0:
                threat_type = data["matches"][0].get("threatType", "MALICIOUS")
                return True, f"Google Safe Browsing: {threat_type}"
            return False, "Clean"
    except Exception as e:
        logger.warning(f"Safe Browsing API failed: {e}")
        return False, "API Timeout/Error"

#  Tier 2: Cloud Classifier 
async def run_tier2_analysis(features: dict):
    """Uses the Stage 1 LightGBM model for cloud-side inference."""
    from src.explainability.shap_pipeline import explainer
    
    if not explainer.model:
        return 0.5  # Fallback
        
    try:
        # Run in a thread to avoid blocking the async loop if the model is large
        def _predict():
            df = pd.DataFrame([features], columns=FEATURE_ORDER)
            # Ensure model returns probability
            if hasattr(explainer.model, "predict_proba"):
                return explainer.model.predict_proba(df)[0][1]
            return explainer.model.predict(df)[0]
            
        score = await asyncio.to_thread(_predict)
        return float(score)
    except Exception as e:
        logger.error(f"Tier 2 Inference failed: {e}")
        return 0.5


def build_feature_vector(url: str, html_features: Optional[Any] = None) -> dict:
    """Combine URL lexical features with HTML structural features."""
    url_feature_values = extract_url_features(url)

    if isinstance(html_features, dict):
        html_values = [float(html_features.get(name, 0.0)) for name in HTML_FEATURE_NAMES]
    else:
        html_values = list(html_features or [])[: len(HTML_FEATURE_NAMES)]
        if len(html_values) < len(HTML_FEATURE_NAMES):
            html_values.extend([0.0] * (len(HTML_FEATURE_NAMES) - len(html_values)))

    combined = {name: float(url_feature_values.get(name, 0.0)) for name in URL_FEATURE_NAMES}
    combined.update({name: float(value) for name, value in zip(HTML_FEATURE_NAMES, html_values)})
    return combined

#  Tier 4: Gemini Analysis 
# Gemini logic has been moved to src/models/gemini_llm.py


@app.post("/analyze/cloud", response_model=AnalysisResponse)
async def analyze_cloud(request: AnalysisRequest):
    from src.models.inference_pipeline import orchestrator
    import urllib.parse
    
    logger.info(f"Analyzing Cloud Tiers for: {request.url}")

    # --- Tranco & Custom Allowlist Check ---
    try:
        parsed_url = urllib.parse.urlparse(request.url)
        hostname = parsed_url.hostname.lower() if parsed_url.hostname else ""
        if hostname.startswith("www."):
            hostname = hostname[4:]
            
        parts = hostname.split('.')
        # Simple extraction of base domain (last two parts) 
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
        
        if hostname in TRANCO_DOMAINS or base_domain in TRANCO_DOMAINS or hostname in CUSTOM_ALLOWLIST or base_domain in CUSTOM_ALLOWLIST:
            logger.info(f"Domain {hostname} matches allowlist. Bypassing ML.")
            return AnalysisResponse(verdict="SAFE", score=0.01, tier=2, reason="Verified against trusted domains list.")
    except Exception as e:
        logger.warning(f"Error checking allowlists: {e}")

    combined_features = build_feature_vector(request.url, request.features)
    
    # 1. Run Tier 2 (Safe Browsing and LightGBM Tabular) in PARALLEL
    sb_task = check_safe_browsing(request.url)
    
    if combined_features:
        lgbm_task = run_tier2_analysis(combined_features)
        sb_result, t2_score = await asyncio.gather(sb_task, lgbm_task)
    else:
        sb_result, _ = await asyncio.gather(sb_task, asyncio.sleep(0))
        t2_score = 0.5

    is_blacklisted, sb_reason = sb_result

    # 2. Threshold check for Tier 2 Safe Browsing (CRITICAL Hit)
    if is_blacklisted:
        return AnalysisResponse(verdict="PHISH", score=1.0, tier=2, reason=f"CRITICAL: {sb_reason}")

    # 3. Generate SHAP Explanation
    explanation = ""
    if combined_features and t2_score >= 0.5:
        try:
            explanation = get_phish_explanation(combined_features)
        except Exception:
            explanation = "Structural anomalies detected."

    # 4. Multimodal Fusion (Tabular + URL + HTML + Vision)
    fusion_data = await orchestrator.fuse_predictions(
        tabular_score=t2_score,
        url=request.url,
        html=request.htmlExcerpt,
        screenshot=request.screenshotBase64
    )
    
    fused_score = fusion_data["fused_score"]
    
    # 5. Fast-Path for highly confident local models
    if fused_score > 0.8:
        return AnalysisResponse(
            verdict="PHISH", 
            score=fused_score, 
            tier=2, 
            reason=f"Fusion Confidence [{fused_score:.2f}]: {explanation or 'High Multimodal Risk.'}"
        )
    elif fused_score < 0.2:
        return AnalysisResponse(
            verdict="SAFE", 
            score=fused_score, 
            tier=2, 
            reason="Multi-tier signals appear safe."
        )
        
    # 6. Escalate to Tier 4 (Gemini) if local models are ambiguous
    logger.info(f"Fusion score ambiguous ({fused_score:.2f}), escalating to Gemini Tier 3...")
    # Run the blocking Gemini call off the event loop to avoid blocking the server
    verdict, g_score, vision_reason = await asyncio.to_thread(
        run_tier3_gemini, request.url, request.htmlExcerpt, request.screenshotBase64
    )
    final_reason = f"{vision_reason}\n\nTechnical Signals:\n{explanation}" if explanation else vision_reason
    return AnalysisResponse(verdict=verdict, score=g_score, tier=3, reason=final_reason)

TRANCO_DOMAINS = set()
CUSTOM_ALLOWLIST = {"deshawindia.com", "deshaw.com"}

@app.on_event("startup")
def startup_event():
    # We dynamically import so it doesn't break if run from root.
    from . import firebase_db
    firebase_db.init_firebase()
    
    # Load Tranco list
    tranco_path = os.path.join("src", "data", "tranco_top_1m.txt")
    if os.path.exists(tranco_path):
        with open(tranco_path, "r", encoding="utf-8") as f:
            for line in f:
                TRANCO_DOMAINS.add(line.strip().lower())
        logger.info(f"Loaded {len(TRANCO_DOMAINS)} domains from Tranco allowlist.")
    else:
        logger.warning("Tranco allowlist not found. Bypassing global allowlist check.")

@app.post("/community/report")
async def report_url(request: ReportRequest):
    from . import firebase_db
    success = firebase_db.report_malicious_url(request.url, request.reason)
    if success:
        return {"status": "success", "message": "Report logged."}
    else:
        raise HTTPException(status_code=500, detail="Failed to log report to DB.")

@app.get("/community/check", response_model=TrustCheckResponse)
async def check_url(url: str):
    from . import firebase_db
    result = firebase_db.get_community_trust(url)
    
    if "error" in result:
        # Return graceful failure instead of 500 so extension keeps working
        return TrustCheckResponse(found=False, report_count=0, reasons=[], verdict="ERROR")
        
    return TrustCheckResponse(
        found=result.get("found", False),
        report_count=result.get("report_count", 0),
        reasons=result.get("reasons", []),
        verdict=result.get("verdict", "PENDING")
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
