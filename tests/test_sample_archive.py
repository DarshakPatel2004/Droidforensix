"""R2/R3: placing a downloaded sample must never rename or delete another sample."""
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from sample_archive import place_sample  # noqa: E402

SHA = "ab" * 32


def _extract(archive, staging):
    with zipfile.ZipFile(archive) as z:
        z.extractall(staging)


def _zip(path, member, payload=b"PK\x03\x04data"):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(member, payload)
    return path


def test_places_matching_entry_and_leaves_neighbours(tmp_path):
    neighbour = tmp_path / ("cd" * 32 + ".apk")
    neighbour.write_bytes(b"PK\x03\x04old sample")
    archive = _zip(tmp_path / "x.zip", f"{SHA}.apk")
    dest = tmp_path / f"fam_{SHA}.apk"

    assert place_sample(archive, dest, SHA, _extract) is True
    assert dest.read_bytes() == b"PK\x03\x04data"
    assert neighbour.read_bytes() == b"PK\x03\x04old sample"


def test_no_matching_entry_moves_nothing(tmp_path):
    neighbour = tmp_path / "old.apk"
    neighbour.write_bytes(b"PK\x03\x04old")
    archive = _zip(tmp_path / "x.zip", "other.bin")
    # Two entries, neither matching: nothing may be picked.
    with zipfile.ZipFile(archive, "a") as z:
        z.writestr("another.bin", b"x")
    dest = tmp_path / f"fam_{SHA}.apk"

    assert place_sample(archive, dest, SHA, _extract) is False
    assert not dest.exists()
    assert neighbour.read_bytes() == b"PK\x03\x04old"
    assert not any(p.name.startswith(".staging-") for p in tmp_path.iterdir())
