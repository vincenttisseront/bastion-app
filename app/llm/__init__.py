"""Optional local LLM assistant (Ollama, e.g. Qwen3-14B).

Golden rule: nothing in the portal depends on this package. Disabled by
default (env ``LLM_ENABLED`` + admin toggle); every entry point returns
``None`` / "unavailable" instead of raising, and none is called from the
authentication, proxy, WAF or ban critical paths.
"""

from app.llm.service import generate_json, llm_enabled, llm_public_status

__all__ = ["generate_json", "llm_enabled", "llm_public_status"]
