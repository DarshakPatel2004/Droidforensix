import os
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Centralized Windows-native DroidForensix configuration."""

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

    # Analysis tools (relative to project root)
    JADX_PATH: str = str(ROOT_DIR / "tools" / "jadx" / "bin" / "jadx.bat")
    APKTOOL_PATH: str = str(ROOT_DIR / "tools" / "apktool" / "apktool.bat")
    DIE_PATH: str = str(ROOT_DIR / "tools" / "die" / "die" / "diec.exe")
    GEOIP_PATH: Path = ROOT_DIR / "data" / "GeoLite2-City.mmdb"
    YARA_RULES_PATH: str = str(ROOT_DIR / "analysis" / "yara_rules.yar")
    SEVEN_ZIP_PATH: str = r"C:\Program Files\7-Zip\7z.exe"

    # Ollama / LLM inference (local Windows service)
    OLLAMA_HOST: str = "http://localhost:11434"
    # Default model; override via the OLLAMA_MODEL environment variable or .env
    OLLAMA_MODEL: str = "qwen2.5:3b-instruct-q4_K_M"
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
    # Extraction mode: "auto" uses Androguard (fast, ~5s), JADX runs only when
    # Androguard fails. Set True to always run JADX (decompiled Java for analysis).
    USE_JADX: bool = False

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
