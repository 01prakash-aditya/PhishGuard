import subprocess
import sys
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

commands = [
    ("Building Dataset", "python -m src.data.dataset_builder"),
    ("Extracting Features", "python -m src.features.extract_all"),
    ("Baseline Race", "python -m src.models.baseline_race"),
    ("Export ONNX", "python -m src.models.onnx_export"),
    ("Train PhishBERT", "python -m src.models.bert_finetune --model phishbert"),
    ("Train CodeBERT", "python -m src.models.bert_finetune --model codebert"),
    ("Train Visual Model", "python -m src.models.efficientnet_visual"),
    ("Generate Fusion Data", "python -m src.models.fusion_data_generator"),
    ("Train Fusion Layer", "python -m src.models.attention_fusion")
]

def main():
    logger.info("Starting Reasonable Training Pipeline...")
    for name, cmd in commands:
        logger.info(f"\n======================================")
        logger.info(f"STEP: {name}")
        logger.info(f"======================================")
        res = subprocess.run(cmd, shell=True)
        if res.returncode != 0:
            logger.error(f"ERROR: {name} failed with code {res.returncode}")
            # We don't exit to let subsequent independent models train if one fails 
            # (e.g., visual model failing due to no screenshots shouldn't block fusion data generation)
        else:
            logger.info(f"SUCCESS: {name}")
            
    logger.info("\nPipeline Execution Completed!")

if __name__ == "__main__":
    main()
