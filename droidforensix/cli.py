"""Command-line interface for DroidForensix.

Run from the repo root with `python -m droidforensix` (or `droidforensix`
after `pip install .`).
"""

import argparse
import subprocess
import sys
from pathlib import Path

from droidforensix import __version__

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _cmd_analyze(args: argparse.Namespace) -> int:
    try:
        from analysis.pipeline import run_pipeline
    except ImportError as e:
        print(f"error: could not import analysis.pipeline: {e}", file=sys.stderr)
        return 2

    result = run_pipeline(args.apk, work_dir=args.workdir)
    sample_id = result.get("sample_id") or Path(args.apk).stem
    work_dir = Path(args.workdir) if args.workdir else Path("analysis") / "work"
    report = work_dir / sample_id / "pipeline_result.json"
    print(f"sample_id: {sample_id}")
    if report.exists():
        print(f"report: {report}")
    if args.json:
        import json

        print(json.dumps(result, indent=2, default=str))
    return 0


def _cmd_classify(args: argparse.Namespace) -> int:
    try:
        from analysis.classify_fast import classify_malware_fast
    except ImportError as e:
        print(f"error: could not import analysis.classify_fast: {e}", file=sys.stderr)
        return 2

    verdict, confidence = classify_malware_fast(args.apk, pipeline_timeout=args.timeout)
    print(f"{'MALWARE' if verdict else 'BENIGN'}  confidence={confidence:.3f}")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError as e:
        print(f"error: uvicorn not available (pip install -r requirements.txt): {e}", file=sys.stderr)
        return 2
    uvicorn.run(
        "backend.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )
    return 0


def _cmd_unpack(args: argparse.Namespace) -> int:
    unpack_py = PROJECT_ROOT / "scripts" / "unpack.py"
    if not unpack_py.exists():
        print(f"error: {unpack_py} not found", file=sys.stderr)
        return 2
    cmd = [sys.executable, str(unpack_py), args.apk]
    if args.workdir:
        cmd.append("--workdir")
        cmd.append(args.workdir)
    if args.out:
        cmd.append("--out")
        cmd.append(args.out)
    return subprocess.call(cmd)


def _cmd_version(args: argparse.Namespace) -> int:
    print(f"droidforensix {__version__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="droidforensix",
        description="Offline Android malware analysis and unpacking.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("analyze", help="run the full offline pipeline on an APK")
    p.add_argument("apk", help="path to the APK")
    p.add_argument("--workdir", default=None, help="analysis work directory (default: analysis/work)")
    p.add_argument("--json", action="store_true", help="also print the full report as JSON")
    p.set_defaults(func=_cmd_analyze)

    p = sub.add_parser("classify", help="quick malware/benign classification")
    p.add_argument("apk", help="path to the APK")
    p.add_argument("--timeout", type=int, default=600, help="pipeline timeout in seconds")
    p.set_defaults(func=_cmd_classify)

    p = sub.add_parser("serve", help="start the FastAPI backend")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--reload", action="store_true")
    p.set_defaults(func=_cmd_serve)

    p = sub.add_parser("unpack", help="packer-aware unpack dispatcher")
    p.add_argument("apk", help="path to the APK")
    p.add_argument("--workdir", default=None, help="unpack work directory")
    p.add_argument("--out", default=None, help="path for the unpack report JSON")
    p.set_defaults(func=_cmd_unpack)

    p = sub.add_parser("version", help="print version")
    p.set_defaults(func=_cmd_version)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())