from __future__ import annotations

import base64
import re
import unicodedata

from .models import SanitizerConfig, SanitizerResult


_ZERO_WIDTH_AND_BIDI_RE = re.compile(r"[\u200B-\u200F\u2060\uFEFF\u00AD\u202A-\u202E\u2066-\u2069]")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_DATA_URI_RE = re.compile(r"data:[^\s]{0,128};base64,[A-Za-z0-9+/=\s]{120,}", re.IGNORECASE)


class Sanitizer:
    def __init__(self, config: SanitizerConfig):
        self.config = config

    def sanitize(self, content: str) -> SanitizerResult:
        text = content
        actions: list[str] = []

        if self.config.normalize_unicode:
            normalized = unicodedata.normalize("NFC", text)
            if normalized != text:
                actions.append("normalized_unicode_nfc")
                text = normalized

        if text.startswith("\ufeff"):
            text = text.lstrip("\ufeff")
            actions.append("stripped_bom")

        normalized_line_endings = text.replace("\r\n", "\n").replace("\r", "\n")
        if normalized_line_endings != text:
            actions.append("normalized_line_endings")
            text = normalized_line_endings

        if self.config.strip_invisible:
            updated = _ZERO_WIDTH_AND_BIDI_RE.sub("", text)
            if updated != text:
                actions.append("stripped_invisible_chars")
                text = updated

            updated = _CONTROL_RE.sub("", text)
            if updated != text:
                actions.append("stripped_control_chars")
                text = updated

        if self.config.strip_html_comments:
            updated = _HTML_COMMENT_RE.sub("", text)
            if updated != text:
                actions.append("stripped_html_comments")
                text = updated

        if self.config.strip_binary:
            updated = _DATA_URI_RE.sub("[stripped-data-uri]", text)
            if updated != text:
                actions.append("stripped_data_uri")
                text = updated

            updated = self._strip_large_base64_blobs(text, self.config.max_base64_blob_size)
            if updated != text:
                actions.append("stripped_base64_blob")
                text = updated

        if not self.config.preserve_markdown:
            updated = self._strip_markdown_formatting(text)
            if updated != text:
                actions.append("stripped_markdown_formatting")
                text = updated

        if self.config.collapse_whitespace:
            updated = re.sub(r"[ \t]{2,}", " ", text)
            updated = re.sub(r"\n{3,}", "\n\n", updated)
            if updated != text:
                actions.append("collapsed_whitespace")
                text = updated

        truncated = False
        if len(text) > self.config.max_length:
            text = _truncate_near_boundary(text, self.config.max_length)
            actions.append("truncated_length")
            truncated = True

        return SanitizerResult(content=text, actions=actions, truncated=truncated)

    @staticmethod
    def _strip_large_base64_blobs(text: str, max_blob_size: int) -> str:
        min_chars = max(64, int(max_blob_size * 1.35))
        pattern = re.compile(
            rf"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{{{min_chars},}}={{0,2}})(?![A-Za-z0-9+/=])"
        )

        def replacer(match: re.Match[str]) -> str:
            blob = match.group(1)
            if len(blob) % 4 != 0:
                return blob
            try:
                decoded = base64.b64decode(blob, validate=True)
            except Exception:
                return blob
            if len(decoded) > max_blob_size:
                return "[stripped-base64-blob]"
            return blob

        return pattern.sub(replacer, text)

    @staticmethod
    def _strip_markdown_formatting(text: str) -> str:
        text = re.sub(r"`{1,3}", "", text)
        text = re.sub(r"\*{1,2}([^*]+)\*{1,2}", r"\1", text)
        text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", text)
        return text


def _truncate_near_boundary(text: str, max_length: int) -> str:
    if len(text) <= max_length:
        return text

    candidate = text[:max_length]
    search_start = max(0, max_length - 500)
    boundary = max(
        candidate.rfind("\n\n", search_start),
        candidate.rfind(". ", search_start),
        candidate.rfind("! ", search_start),
        candidate.rfind("? ", search_start),
    )

    if boundary == -1:
        return candidate

    if candidate[boundary : boundary + 2] in {"\n\n", ". ", "! ", "? "}:
        boundary += 1
    return candidate[: boundary + 1].rstrip()
