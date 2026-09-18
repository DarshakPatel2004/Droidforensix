"""
Batch run pipeline on all 310 malware samples.
Output: Individual pipeline_result.json for each sample + aggregated CSV.
"""

import json
import csv
import logging
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.pipeline import run_pipeline
from backend.config import settings

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(name)s | %(levelname)s | %(message)s',
    handlers=[
        logging.FileHandler('analysis/ground_truth_phase1/logs/batch_run.log'),
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger(__name__)

def batch_analyze():
    """Run pipeline on all malware samples in samples/malware/"""

    malware_dir = Path(settings.SAMPLES_DIR) / "malware"
    output_dir = Path("analysis/ground_truth_phase1/pipeline_outputs")
    output_dir.mkdir(parents=True, exist_ok=True)

    apk_files = list(malware_dir.glob("**/*.apk"))
    logger.info(f"Found {len(apk_files)} APK files")

    if not apk_files:
        logger.error(f"No APKs found in {malware_dir}")
        return

    results_summary = []
    failed_samples = []

    for idx, apk_path in enumerate(apk_files, 1):
        sample_id = apk_path.stem
        logger.info(f"[{idx}/{len(apk_files)}] Analyzing {sample_id}")

        try:
            result = run_pipeline(
                apk_path=str(apk_path),
                work_dir=str(output_dir / sample_id),
                event_emitter=None,
            )

            metadata = result.get("metadata", {})
            c2_list = result.get("c2_infrastructure", [])
            obf = result.get("obfuscation_analysis", {})

            summary = {
                "sample_id": result.get("sample_id", sample_id),
                "package_name": metadata.get("package_name", "unknown"),
                "file_size": metadata.get("file_size_bytes", 0),
                "c2_count": len(c2_list),
                "c2_domains": [c.get("domain") for c in c2_list[:5]],
                "c2_ips": [c.get("ip") for c in c2_list[:5]],
                "risk_score": result.get("llm_assessment", {}).get("risk_score", 0),
                "obfuscation_score": obf.get("obfuscation_score", 0),
                "obfuscation_level": obf.get("obfuscation_level", "unknown"),
                "status": "success",
            }

            results_summary.append(summary)
            logger.info(f"  + {summary['c2_count']} C2 indicators extracted")

        except Exception as e:
            logger.error(f"  x Failed: {e}")
            failed_samples.append({
                "sample_id": sample_id,
                "error": str(e),
            })
            results_summary.append({
                "sample_id": sample_id,
                "status": "failed",
                "error": str(e),
            })

    csv_path = Path("analysis/ground_truth_phase1/310_pipeline_output.csv")
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(results_summary[0].keys()))
        writer.writeheader()
        writer.writerows(results_summary)

    logger.info(f"\n=== BATCH RUN COMPLETE ===")
    logger.info(f"Successful: {len(apk_files) - len(failed_samples)}/{len(apk_files)}")
    logger.info(f"Failed: {len(failed_samples)}")
    logger.info(f"Output: {csv_path}")
    logger.info(f"Logs: analysis/ground_truth_phase1/logs/batch_run.log")

    if failed_samples:
        logger.warning(f"\nFailed samples:")
        for sample in failed_samples:
            logger.warning(f"  - {sample['sample_id']}: {sample['error']}")

if __name__ == "__main__":
    batch_analyze()
