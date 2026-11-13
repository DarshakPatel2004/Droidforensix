"""Keys in .env must be visible to the LLM callers, not only to os.environ."""
from analysis import step7_llm_assessment as step7


def test_api_key_falls_back_to_dotenv(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("OPENROUTER_API_KEY=  test-key-123  \n", encoding="utf-8")
    monkeypatch.setattr(step7, "ROOT_DIR", tmp_path)
    assert step7._api_key("OPENROUTER_API_KEY") == "test-key-123"


def test_api_key_prefers_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENROUTER_API_KEY", "from-env")
    (tmp_path / ".env").write_text("OPENROUTER_API_KEY=from-file\n", encoding="utf-8")
    monkeypatch.setattr(step7, "ROOT_DIR", tmp_path)
    assert step7._api_key("OPENROUTER_API_KEY") == "from-env"
