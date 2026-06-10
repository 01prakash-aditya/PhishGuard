import os
import shutil
from pathlib import Path
import lightgbm as lgb
import numpy as np
import joblib
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR / "models"
EXT_MODELS_DIR = BASE_DIR / "extension" / "models"

def main():
    logger.info("Setting up dummy models since datasets are not present...")
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    EXT_MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Train a dummy LightGBM model
    # The pipeline expects 40 features
    X_dummy = np.random.rand(100, 40)
    y_dummy = np.random.randint(0, 2, 100)

    model = lgb.LGBMClassifier(n_estimators=10, max_depth=3)
    model.fit(X_dummy, y_dummy)

    # Save backend tabular model
    backend_model_path = MODELS_DIR / "lightgbm_stage1.pkl"
    joblib.dump(model, backend_model_path)
    logger.info(f"Saved dummy backend model to {backend_model_path}")

    # Save edge model (baseline_race.py also saves lightgbm_edge.pkl)
    edge_model_path = MODELS_DIR / "lightgbm_edge.pkl"
    joblib.dump(model, edge_model_path)
    logger.info(f"Saved dummy edge model to {edge_model_path}")

    # 2. Export to ONNX using existing script
    import sys
    sys.path.append(str(BASE_DIR))
    from src.models.onnx_export import export_lgb_to_onnx

    onnx_path = export_lgb_to_onnx(edge_model_path, "phishguard_edge.onnx")
    
    # 3. Copy ONNX to extension folder
    ext_onnx_path = EXT_MODELS_DIR / "phishguard_edge.onnx"
    shutil.copy(onnx_path, ext_onnx_path)
    logger.info(f"Copied ONNX model to extension folder: {ext_onnx_path}")
    
    # 4. Create empty dummy paths for other models so the backend doesn't complain
    # We just create dummy empty files or let the backend's graceful fallback handle it.
    # The backend already handles missing transformers gracefully.
    
    logger.info(" Setup complete! The extension should now load the ONNX model successfully.")

if __name__ == "__main__":
    main()
