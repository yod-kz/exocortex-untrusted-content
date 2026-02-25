import base64

from untrusted_content_tool.models import SanitizerConfig
from untrusted_content_tool.sanitizer import Sanitizer


def test_sanitizer_strips_invisible_comments_and_base64() -> None:
    raw_blob = base64.b64encode(b"x" * 600).decode("ascii")
    content = f"hello\u200b world <!-- hidden --> data:text/plain;base64,{raw_blob}"

    sanitizer = Sanitizer(SanitizerConfig(max_base64_blob_size=256))
    result = sanitizer.sanitize(content)

    assert "\u200b" not in result.content
    assert "<!--" not in result.content
    assert "[stripped-data-uri]" in result.content or "[stripped-base64-blob]" in result.content
    assert "stripped_invisible_chars" in result.actions
    assert "stripped_html_comments" in result.actions


def test_sanitizer_strips_large_base64_blob_without_data_uri() -> None:
    blob = base64.b64encode(b"y" * 700).decode("ascii")
    content = f"prefix {blob} suffix"

    sanitizer = Sanitizer(SanitizerConfig(max_base64_blob_size=128))
    result = sanitizer.sanitize(content)

    assert "[stripped-base64-blob]" in result.content
    assert "stripped_base64_blob" in result.actions


def test_sanitizer_truncates_near_boundary() -> None:
    sentence = "alpha beta gamma. " * 200
    sanitizer = Sanitizer(SanitizerConfig(max_length=120))

    result = sanitizer.sanitize(sentence)

    assert len(result.content) <= 120
    assert result.truncated is True
    assert "truncated_length" in result.actions
