"""User-Agent summarization for sessions diagnostics."""

from app.user_agent_label import summarize_user_agent


def test_firefox_windows():
    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) "
        "Gecko/20100101 Firefox/152.0"
    )
    assert summarize_user_agent(ua) == "Firefox 152 / Windows"


def test_chrome_macos():
    ua = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    )
    assert summarize_user_agent(ua) == "Chrome 126 / macOS"


def test_empty():
    assert summarize_user_agent("") == "—"
    assert summarize_user_agent(None) == "—"
