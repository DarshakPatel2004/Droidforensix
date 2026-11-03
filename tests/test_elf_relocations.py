"""Regression: ELF relocation symbol names resolve via the linked symbol table."""
import logging
from pathlib import Path

import pytest

from backend.elf_analyzer import HAS_PYELFFLTOOLS, ELFBreaker

SAMPLE_SO = Path(__file__).resolve().parents[1] / "analysis" / "work" / (
    "85cafe005c7f893cae65fa0a5ebf1c103eca579529ebd5d531c672408acdb9d0"
    "/apktool/lib/armeabi/libvadgo.so"
)


@pytest.mark.skipif(not HAS_PYELFFLTOOLS, reason="pyelftools not installed")
@pytest.mark.skipif(not SAMPLE_SO.exists(), reason="sample .so not present in analysis/work")
def test_relocations_resolve_symbol_names(caplog):
    breaker = ELFBreaker(SAMPLE_SO.name, SAMPLE_SO.read_bytes())
    assert breaker._parse()

    with caplog.at_level(logging.WARNING, logger="backend.elf_analyzer"):
        relocs = breaker._extract_relocations()

    assert not any("_extract_relocations" in r.getMessage() for r in caplog.records)
    assert relocs, "expected at least one relocation in the sample"
    assert all({"offset", "type", "symbol"} <= set(r) for r in relocs)
    assert any(r["symbol"] for r in relocs), "no relocation resolved to a symbol name"
