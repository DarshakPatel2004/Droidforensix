"""Run the family KB miner on the LAMDA kb group only, writing to a separate file.

The miner's paths are module constants, so they are overridden here instead of
editing analysis/mine_family_knowledge.py or touching the shipped KB.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import analysis.mine_family_knowledge as miner  # noqa: E402

HERE = Path(__file__).resolve().parent

if __name__ == "__main__":
    miner.CACHE_PATH = HERE / "kb_features.json"
    miner.GT_CHECK = HERE / "kb_gt.csv"
    miner.OUT_PATH = HERE / "kb_knowledge_base.json"
    miner.main()
