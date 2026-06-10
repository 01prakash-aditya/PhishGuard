import os
import subprocess
from pathlib import Path
import logging
import urllib.request
import zipfile

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "datasets"

def run_cmd(cmd):
    logger.info(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        logger.error(f"Command failed: {result.stderr}")
    else:
        logger.info("Success.")

def download_file(url, dest):
    logger.info(f"Downloading {url} to {dest}...")
    try:
        urllib.request.urlretrieve(url, dest)
        logger.info("Download complete.")
    except Exception as e:
        logger.error(f"Failed to download {url}: {e}")

def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    # 1. Tranco Top 1M
    tranco_path = DATA_DIR / "Tranco_top_1m.csv"
    if not tranco_path.exists():
        download_file("https://tranco-list.eu/top-1m.csv", tranco_path)
    else:
        logger.info("Tranco dataset already exists.")

    # 2. PhishTank
    phishtank_path = DATA_DIR / "PhishTank.csv"
    if not phishtank_path.exists():
        # PhishTank's direct link is sometimes rate-limited, but we try it.
        download_file("http://data.phishtank.com/data/online-valid.csv", phishtank_path)
    else:
        logger.info("PhishTank dataset already exists.")

    # 3. Kaggle Datasets (Requires Kaggle API Key)
    # PhiUSIIL Phishing URL Dataset
    phiusiil_zip = DATA_DIR / "phishing-url-dataset.zip"
    phiusiil_csv = DATA_DIR / "PhiUSIIL_Phishing_URL_Dataset.csv"
    if not phiusiil_csv.exists():
        logger.info("Downloading PhiUSIIL dataset via Kaggle...")
        run_cmd(f"kaggle datasets download shashwatwork/phishing-url-dataset -p {DATA_DIR}")
        if phiusiil_zip.exists():
            with zipfile.ZipFile(phiusiil_zip, 'r') as zip_ref:
                zip_ref.extractall(DATA_DIR)
            os.remove(phiusiil_zip)
    
    # UCI Dataset
    uci_zip = DATA_DIR / "phishing-website-dataset.zip"
    uci_csv = DATA_DIR / "Kaggle_UCI.csv" # The script expects Kaggle_UCI.csv
    if not uci_csv.exists():
        logger.info("Downloading UCI dataset via Kaggle...")
        run_cmd(f"kaggle datasets download akashkr/phishing-website-dataset -p {DATA_DIR}")
        if uci_zip.exists():
            with zipfile.ZipFile(uci_zip, 'r') as zip_ref:
                zip_ref.extractall(DATA_DIR)
            os.remove(uci_zip)
            # Rename if necessary to match dataset_builder expectations
            for file in DATA_DIR.glob("*.csv"):
                if "dataset" in file.name.lower():
                    file.rename(uci_csv)

    logger.info(" Dataset download process finished! Please check for any errors.")

if __name__ == "__main__":
    main()
