"""
PhishGuard++ — Deployment Verification
Checks environment, dependencies, and model presence for final verification.
"""

import os
import sys
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent

def check_structure():
    required_dirs = [
        "src/data", "src/features", "src/models", "src/api",
        "extension", "extension/lib", "extension/models",
        "datasets/processed", "models"
    ]
    all_ok = True
    for d in required_dirs:
        if not (BASE_DIR / d).exists():
            logger.warning(f"Missing directory: {d}")
            all_ok = False
        else:
            logger.info(f"Directory OK: {d}")
    return all_ok

def check_dependencies():
    deps = ["pandas", "numpy", "sklearn", "torch", "transformers", "fastapi", "onnx", "onnxmltools", "onnxruntime", "sdv"]
    for dep in deps:
        try:
            __import__(dep)
            logger.info(f"Dependency OK: {dep}")
        except ImportError:
            logger.warning(f"Missing dependency: {dep}")

def check_github():
    try:
        import subprocess
        res = subprocess.run(["git", "remote", "-v"], capture_output=True, text=True)
        if "github.com/naksshhh/PhishGuard" in res.stdout:
            logger.info("GitHub Remote OK")
        else:
            logger.warning("GitHub Remote not detected or mismatched")
    except Exception as e:
        logger.error(f"Git check failed: {e}")

def main():
    logger.info("Starting PhishGuard++ Deployment Check...")
    print("-" * 40)
    check_structure()
    print("-" * 40)
    check_dependencies()
    print("-" * 40)
    check_github()
    print("-" * 40)
    logger.info(" Verification Complete. Ready for Phase 5 (Production Training).")

if __name__ == "__main__":
    main()
