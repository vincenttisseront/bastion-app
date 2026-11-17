"""The ten optional LLM features. Each one degrades to today's behaviour.

Every entry point returns ``None`` (or an empty result) when the assistant is
disabled or unavailable; callers keep their non-LLM path unchanged.
"""
