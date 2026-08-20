import os
import sys
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Platform-aware tool path resolution
# ---------------------------------------------------------------------------
# The tools/ directory ships both Windows (.bat) and Linux (no-extension)
# binaries for apktool. apktool ships as a .bat wrapper (Windows) or is invoked
# directly via java -jar (Linux). die is Windows-only; on Linux we fall back
# to the system `die` binary on PATH (if available).

_IS_WINDOWS = sys.platform.startswith("win")

# apktool: on Windows use the bundled .bat wrapper; on Linux invoke via java -jar.
# The java invocation is built in tools.py — here we expose the jar path so
# tools.py can construct the correct command without duplicating path logic.
_APKTOOL_BAT = ROOT_DIR / "tools" / "apktool" / "apktool.bat"
_APKTOOL_JAR = ROOT_DIR / "tools" / "apktool" / "apktool.jar"

# die (Detect-It-Easy): Windows-only bundled binary.
# On Linux, fall back to "diec" on PATH (user must install separately).
_DIE_BIN = ROOT_DIR / "tools" / "die" / "die" / "diec.exe" if _IS_WINDOWS else Path("diec")

# 7-Zip: Windows-only bundled install. On Linux, use system p7zip ("7z").
_SEVEN_ZIP_BIN = Path(r"C:\Program Files\7-Zip\7z.exe") if _IS_WINDOWS else Path("7z")


class Settings(BaseSettings):
    """Centralized cross-platform DroidForensix configuration."""

    model_config = SettingsConfigDict(
        env_file=ROOT_DIR / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # File system paths (computed from project root)
    WORK_DIR: Path = ROOT_DIR / "analysis" / "work"
    REPORTS_DIR: Path = ROOT_DIR / "reports"
    SAMPLES_DIR: Path = ROOT_DIR / "samples"
    UPLOADS_DIR: Path = ROOT_DIR / "uploads"

    # Analysis tools — override via .env or environment variables if needed.
    # On Windows: uses bundled .bat wrappers and .exe binaries.
    # On Linux: apktool via java -jar; die/7z from PATH.
    APKTOOL_PATH: str = str(_APKTOOL_BAT if _IS_WINDOWS else _APKTOOL_JAR)
    DIE_PATH: str = str(_DIE_BIN)
    GEOIP_PATH: Path = ROOT_DIR / "data" / "GeoLite2-City.mmdb"
    YARA_RULES_PATH: str = str(ROOT_DIR / "analysis" / "yara_rules.yar")
    SEVEN_ZIP_PATH: str = str(_SEVEN_ZIP_BIN)

    # Ollama / LLM inference
    OLLAMA_HOST: str = "http://localhost:11434"
    # Default model; override via OLLAMA_MODEL in .env or environment.
    OLLAMA_MODEL: str = "mistral:3b"
    OLLAMA_TIMEOUT: int = 120

    # NVIDIA NIM (optional, for future expansion)
    NIM_ENABLED: bool = False
    NIM_HOST: Optional[str] = None
    NIM_MODEL: Optional[str] = None
    NIM_API_KEY: Optional[str] = None

    # OpenRouter (optional, OpenAI-compatible, supports many models)
    OPENROUTER_HOST: str = "https://openrouter.ai/api/v1"
    OPENROUTER_MODEL: str = "google/gemma-4-31b-it:free"

    # LLM provider selection: "auto" (default), "nvidia", "openrouter", or "ollama".
    # "auto" prefers NVIDIA NIM > OpenRouter > Ollama, depending on which API keys are set.
    LLM_PROVIDER: str = "auto"

    # Pipeline settings
    STEP_TIMEOUT: int = 300  # seconds per step
    MAX_UPLOAD_SIZE_MB: int = 100
    ENABLE_LOGGING: bool = True
    LOG_LEVEL: str = "INFO"
    # Extraction mode: Androguard only (fast, ~5s); DEX data feeds all
    # downstream steps. No external decompiler is required.

    # Web server
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000
    FRONTEND_URL: str = "http://localhost:5173"
    # Allow both localhost and 127.0.0.1: browsers treat them as distinct
    # origins, and the Vite dev server may be reached via either host.
    # Include the configured FRONTEND_URL plus common Vite dev/preview ports.
    CORS_ORIGINS: list = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:4173",
        "http://localhost:8443",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:4173",
        "http://127.0.0.1:8443",
    ]

    @property
    def cors_origins(self) -> list:
        env_val = os.environ.get("CORS_ORIGINS")
        if env_val:
            return [o.strip() for o in env_val.split(",") if o.strip()]
        return self.CORS_ORIGINS


settings = Settings()

# Ensure directories exist
for dir_path in [settings.WORK_DIR, settings.REPORTS_DIR, settings.SAMPLES_DIR, settings.UPLOADS_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)
