import logging
import os
import json
import base64
from typing import Optional, Tuple
from google import genai
from google.genai import types as genai_types

logger = logging.getLogger(__name__)

class GeminiTier3:
    """
    Tier 3 Cascade: Multi-modal LLM Arbiter
    Uses Gemini 2.5 Flash to act as the final decision maker for ambiguous signals.
    """
    def __init__(self):
        # We initialize the client when the method is called to allow for late .env loading
        self.model_id = "gemini-2.5-flash"
        self._client = None

    @property
    def client(self):
        if not self._client:
            api_key = os.getenv("GEMINI_API_KEY")
            if not api_key:
                logger.error("GEMINI_API_KEY environment variable is not set.")
                raise ValueError("GEMINI_API_KEY is missing.")
            self._client = genai.Client(api_key=api_key)
        return self._client

    def run_inference(self, url: str, html_excerpt: str, screenshot_base64: Optional[str] = None) -> Tuple[str, float, str]:
        """
        Escalates to Tier 4 Gemini Analysis for highly sophisticated phishing checks.
        Returns: verdict (str), score (float), reason (str)
        """
        logger.info(f"Escalating to Gemini Tier 3 for {url}...")
        
        prompt = f"""Analyze the following URL and HTML excerpt for phishing indicators.
URL: {url}
HTML Excerpt:
{html_excerpt[:2000]}

Verify:
1. Brand impersonation (e.g., 'g00gle.com').
2. Credential harvesting forms (password/PII inputs to suspicious actions).
3. Urgency/threatening language.
4. If a screenshot image is provided, check if the logo/design matches the claimed brand.

Output ONLY valid JSON:
{{
  "verdict": "PHISH" or "SAFE",
  "score": 0.0 to 1.0,
  "reason": "Clear explanation."
}}"""
        
        parts = [genai_types.Part.from_text(text=prompt)]
        
        if screenshot_base64:
            raw_b64 = screenshot_base64.split(",")[1] if "," in screenshot_base64 else screenshot_base64
            parts.append(genai_types.Part.from_bytes(
                data=base64.b64decode(raw_b64),
                mime_type="image/jpeg"
            ))
        
        try:
            response = self.client.models.generate_content(
                model=self.model_id,
                contents=parts,
                config=genai_types.GenerateContentConfig(
                    response_mime_type="application/json",
                )
            )
            data = json.loads(response.text)
            return data.get("verdict", "SAFE").upper(), float(data.get("score", 0.1)), data.get("reason", "No reason.")
        except json.JSONDecodeError as e:
            logger.error(f"Gemini JSON Parse Error: {e}")
            return "ERROR", 0.5, "Tier 3 JSON parsing failed."
        except Exception as e:
            logger.error(f"Gemini Tier 3 failed: {e}")
            return "ERROR", 0.5, f"Tier 3 Gemini API error: {str(e)}"

# Singleton instance
gemini_model = GeminiTier3()

def run_tier3_gemini(url: str, html_excerpt: str, screenshot_base64: Optional[str] = None) -> Tuple[str, float, str]:
    return gemini_model.run_inference(url, html_excerpt, screenshot_base64)
