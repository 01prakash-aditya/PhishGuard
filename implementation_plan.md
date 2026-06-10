PhishGuard++ — Fix All Tier Inconsistencies & Improve Accuracy
Based on the deep research report, this plan addresses every identified bug, naming inconsistency, and accuracy concern to get the full 3-tier cascade working correctly end-to-end.

User Review Required
IMPORTANT

The Gemini module currently calls itself "Tier 4" in code but returns tier=3 in API responses. This plan standardises everything to Tier 3 (since Tier 0 is the allowlist, Tier 1 is Edge/ONNX, Tier 2 is Cloud ML + Fusion, Tier 3 is Gemini LLM). If you intended a different numbering scheme, please flag it before I begin.

WARNING

Your .env file contains plaintext API keys (Gemini, Safe Browsing, W&B, Firebase). While .env is already in .gitignore, the backend/firebase-adminsdk.json file (2.4 KB) is committed to the repo. This plan does NOT remove it (that would break your deployment), but be aware it's in git history.

Proposed Changes
1. Backend — Tier Naming & Async Fix
[MODIFY] 
main.py
Line	Issue	Fix
3	Docstring says "Tier 3 (Gemini)"	Change to "Tier 3 (Gemini LLM Arbiter)"
23	from src.models.gemini_llm import run_tier4_gemini	→ run_tier3_gemini
132	Comment says "Tier 4: Gemini Analysis"	→ "Tier 3: Gemini Analysis"
195	Log says "escalating to Gemini Tier 3" but calls run_tier4_gemini	Fix function name
196	run_tier4_gemini(...) called synchronously inside async — blocks event loop	Wrap in await asyncio.to_thread(...)
2. Gemini Module — Rename Tier 4 → Tier 3
[MODIFY] 
gemini_llm.py
Line	Issue	Fix
11	class GeminiTier4	→ class GeminiTier3
13-14	Docstring says "Tier 4 Cascade"	→ "Tier 3 Cascade"
33	"Escalates to Tier 4 Gemini Analysis"	→ "Tier 3"
36	Log "Gemini Tier 4"	→ "Gemini Tier 3"
77	Error msg "Tier 4 JSON"	→ "Tier 3 JSON"
79-80	Error msg "Gemini Tier 4"	→ "Gemini Tier 3"
83	gemini_model = GeminiTier4()	→ GeminiTier3()
85	def run_tier4_gemini(...)	→ def run_tier3_gemini(...)
3. Extension — Expand Trusted Domains for Fewer False Positives
[MODIFY] 
background.js
The hardcoded allowlist of 5 domains misses dozens of legitimate domains that the backend and feature extractor already trust. This causes unnecessary Tier 1 escalations for banks, social media, shipping, and government sites, wasting cloud resources and increasing false-positive risk.

Fix: Expand to match the backend's TRUSTED_REGISTRABLE_DOMAINS set (~50 domains) and add .gov / .mil suffix checks.

4. Attention Fusion — Remove Dead Softmax Layer
[MODIFY] 
attention_fusion.py
The self.attention Sequential has 4 layers (Linear → ReLU → Linear → Softmax), but forward() never uses the Softmax (it manually calls torch.softmax() after masking on line 60). The dead Softmax wastes memory and creates confusion.

Fix: Remove the nn.Softmax(dim=-1) from the Sequential and update slicing from self.attention[:3] to self.attention (all 3 remaining layers).

NOTE

This changes the module's state_dict keys, so the existing attention_fusion.pth checkpoint will fail to load. However, since the Softmax layer had no learnable parameters, the remaining weights are identical. I will add a strict=False load or remap the keys.

5. ONNX Export — Remove Hardcoded Feature Count
[MODIFY] 
onnx_export.py
Line 33 hardcodes n_features = 40. If the feature set ever changes, the export silently produces a broken model.

Fix: Derive from model.n_features_ with 40 as fallback.

6. Inference Pipeline — Improve Fusion Fallback for Better Accuracy
[MODIFY] 
inference_pipeline.py
When the fusion model isn't available, the fallback is a simple average of active scores. This treats all branches equally, but tabular (LightGBM) is always present and has the highest standalone accuracy. PhishBERT on a fine-tuned DistilBERT has been shown to be reliable too.

Fix: Replace simple average with a weighted fallback:

Tabular (LightGBM): weight 0.45
PhishBERT: weight 0.30
CodeBERT: weight 0.15
EfficientNet: weight 0.10
Inactive branches redistribute their weight proportionally to active ones.

7. Fusion Data Generator — Fix Eager Module-Level Import
[MODIFY] 
fusion_data_generator.py
Line 16 from src.models.inference_pipeline import orchestrator loads ALL ML models at import time. This is only needed when actually generating data, not when the module is accidentally imported.

Fix: Move to lazy import inside generate_fusion_data().

8. Popup — Fix Tier Name Array (Index 4 is unreachable)
[MODIFY] 
popup_v2.js
Line 202: getTierName() returns ['', 'On-Device', 'Cloud ML', 'Gemini Vision', 'Community'][tier]. Index 4 ("Community") is unreachable since the backend only returns tiers 1–3. More importantly, Tier 3 should say "Gemini AI" not "Gemini Vision" since it's a full multimodal LLM analysis (not just vision).

Fix: Change to ['', 'On-Device', 'Cloud ML', 'Gemini AI'][tier].

Summary of Accuracy Improvements
Change	Impact
Expand trusted domains (5 → ~50)	Eliminates false positives on legitimate banks, gov sites, social media
Weighted fusion fallback	Properly weights the most reliable model (LightGBM) when fusion layer is absent
Async Gemini call	Prevents event-loop blocking — faster, more reliable Tier 3 responses
Remove dead Softmax	Cleaner model architecture, prevents potential numerical confusion
Fix tier numbering	Consistent escalation ensures proper cascade logic
Verification Plan
Automated Tests
python test_backend.py — Existing backend tests
python -c "from src.models.gemini_llm import run_tier3_gemini; print('OK')" — Import check
python -c "from src.models.inference_pipeline import FusionOrchestrator; print('OK')" — Import check
python -c "from src.models.attention_fusion import AttentionFusion; print('OK')" — Import check
Manual Verification
Load the extension in Chrome, verify popup shows correct tier labels
Test a known safe site (google.com) → should return SAFE at Tier 1
Test a suspicious URL → should escalate through tiers correctly