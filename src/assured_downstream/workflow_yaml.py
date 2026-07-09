from __future__ import annotations

import textwrap
from dataclasses import dataclass
from typing import Any


class WorkflowYamlError(ValueError):
    """Raised when a workflow YAML file is outside the supported subset."""


@dataclass(frozen=True)
class _Line:
    indent: int
    content: str
    raw: str
    number: int


def parse_workflow_yaml(text: str) -> dict[str, Any]:
    """Parse the GitHub Actions YAML subset used by recon.

    The project intentionally has no YAML runtime dependency today. This parser
    is narrow by design: it supports the mapping, list, scalar, flow-list, and
    block-string shapes common in workflow files, and fails closed for malformed
    structure so recon can report that condition explicitly.
    """

    parser = _WorkflowYamlParser(text)
    value = parser.parse()
    if not isinstance(value, dict):
        raise WorkflowYamlError("workflow YAML root must be a mapping")
    return value


class _WorkflowYamlParser:
    def __init__(self, text: str) -> None:
        self.lines = textwrap.dedent(text).splitlines()
        self.index = 0

    def parse(self) -> Any:
        line = self._peek()
        if line is None:
            return {}

        value = self._parse_block(line.indent)
        extra = self._peek()
        if extra is not None:
            raise WorkflowYamlError(f"unexpected content at line {extra.number}")
        return value

    def _parse_block(self, indent: int) -> Any:
        line = self._peek()
        if line is None:
            return {}
        if line.indent < indent:
            return {}
        if line.indent > indent:
            raise WorkflowYamlError(f"unexpected indentation at line {line.number}")
        if _is_sequence_item(line.content):
            return self._parse_sequence(indent)
        return self._parse_mapping(indent)

    def _parse_mapping(self, indent: int) -> dict[str, Any]:
        mapping: dict[str, Any] = {}
        while True:
            line = self._peek()
            if line is None or line.indent < indent:
                break
            if line.indent > indent:
                raise WorkflowYamlError(f"unexpected indentation at line {line.number}")
            if _is_sequence_item(line.content):
                break

            key, value_text = _split_key_value(line.content, line.number)
            self.index += 1
            mapping[_parse_key(key)] = self._parse_value_after_key(
                value_text,
                parent_indent=line.indent,
            )
        return mapping

    def _parse_sequence(self, indent: int) -> list[Any]:
        items: list[Any] = []
        while True:
            line = self._peek()
            if line is None or line.indent < indent:
                break
            if line.indent > indent:
                raise WorkflowYamlError(f"unexpected indentation at line {line.number}")
            if not _is_sequence_item(line.content):
                break

            item_text = line.content[1:].strip()
            self.index += 1

            if not item_text:
                item = self._parse_nested_value(parent_indent=indent)
            elif _has_key_value_separator(item_text):
                key, value_text = _split_key_value(item_text, line.number)
                item = {
                    _parse_key(key): self._parse_value_after_key(
                        value_text,
                        parent_indent=indent,
                    )
                }
                continuation = self._parse_sequence_item_continuation(indent)
                if isinstance(item, dict) and isinstance(continuation, dict):
                    item.update(continuation)
                elif continuation not in (None, {}, []):
                    item = [item, continuation]
            else:
                item = _parse_scalar(item_text, line.number)
                continuation = self._parse_sequence_item_continuation(indent)
                if continuation not in (None, {}, []):
                    item = [item, continuation]

            items.append(item)
        return items

    def _parse_sequence_item_continuation(self, sequence_indent: int) -> Any:
        next_line = self._peek()
        if next_line is None or next_line.indent <= sequence_indent:
            return None
        return self._parse_block(next_line.indent)

    def _parse_value_after_key(self, value_text: str, *, parent_indent: int) -> Any:
        cleaned = _strip_yaml_metadata(value_text)
        if not cleaned:
            return self._parse_nested_value(parent_indent=parent_indent)
        if cleaned[0] in {"|", ">"}:
            return self._parse_block_scalar(parent_indent, folded=cleaned[0] == ">")
        return _parse_scalar(cleaned, self.index)

    def _parse_nested_value(self, *, parent_indent: int) -> Any:
        next_line = self._peek()
        if next_line is None or next_line.indent <= parent_indent:
            return {}
        return self._parse_block(next_line.indent)

    def _parse_block_scalar(self, parent_indent: int, *, folded: bool) -> str:
        lines: list[str] = []
        content_indent: int | None = None
        while self.index < len(self.lines):
            raw = self.lines[self.index].rstrip("\r")
            if not raw.strip():
                lines.append("")
                self.index += 1
                continue

            indent = _count_indent(raw, self.index + 1)
            if indent <= parent_indent:
                break
            if content_indent is not None and indent < content_indent:
                break
            if content_indent is None:
                content_indent = indent

            lines.append(raw[min(indent, content_indent):])
            self.index += 1

        if folded:
            return " ".join(line.strip() for line in lines if line.strip())
        return "\n".join(lines).rstrip("\n")

    def _peek(self) -> _Line | None:
        while self.index < len(self.lines):
            raw = self.lines[self.index].rstrip("\r")
            indent = _count_indent(raw, self.index + 1)
            content = _strip_inline_comment(raw[indent:]).rstrip()
            if content.strip() and content.strip() not in {"---", "..."}:
                return _Line(indent, content.strip(), raw, self.index + 1)
            self.index += 1
        return None


def _count_indent(raw: str, line_number: int) -> int:
    indent = len(raw) - len(raw.lstrip(" "))
    if "\t" in raw[:indent]:
        raise WorkflowYamlError(f"tabs are not supported for indentation at line {line_number}")
    return indent


def _is_sequence_item(content: str) -> bool:
    return content == "-" or content.startswith("- ")


def _has_key_value_separator(text: str) -> bool:
    return _find_unquoted_colon(text) is not None


def _split_key_value(text: str, line_number: int) -> tuple[str, str]:
    separator = _find_unquoted_colon(text)
    if separator is None:
        raise WorkflowYamlError(f"expected key/value mapping at line {line_number}")
    key = text[:separator].strip()
    if not key:
        raise WorkflowYamlError(f"empty mapping key at line {line_number}")
    return key, text[separator + 1:].strip()


def _find_unquoted_colon(text: str) -> int | None:
    quote: str | None = None
    escape = False
    depth = 0
    for index, char in enumerate(text):
        if quote:
            if quote == '"' and char == "\\" and not escape:
                escape = True
                continue
            if char == quote and not escape:
                quote = None
            escape = False
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char in "[{(":
            depth += 1
            continue
        if char in "]})":
            depth = max(depth - 1, 0)
            continue
        if char == ":" and depth == 0:
            return index
    return None


def _parse_key(value: str) -> str:
    parsed = _parse_scalar(value, line_number=0)
    return parsed if isinstance(parsed, str) else str(parsed)


def _parse_scalar(value: str, line_number: int) -> Any:
    value = _strip_yaml_metadata(value.strip())
    if not value:
        return ""

    if value.startswith("["):
        if not value.endswith("]"):
            raise WorkflowYamlError(f"unterminated flow sequence near line {line_number}")
        return [_parse_scalar(item, line_number) for item in _split_flow_items(value[1:-1])]
    if value.startswith("{"):
        if not value.endswith("}"):
            raise WorkflowYamlError(f"unterminated flow mapping near line {line_number}")
        mapping: dict[str, Any] = {}
        for item in _split_flow_items(value[1:-1]):
            if not item:
                continue
            key, item_value = _split_key_value(item, line_number)
            mapping[_parse_key(key)] = _parse_scalar(item_value, line_number)
        return mapping

    if len(value) >= 2 and value[0] == value[-1] == "'":
        return value[1:-1].replace("''", "'")
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return _unquote_double(value)

    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if lowered in {"null", "~"}:
        return None
    return value


def _strip_yaml_metadata(value: str) -> str:
    parts = value.split()
    while parts and (parts[0].startswith("&") or parts[0].startswith("!")):
        parts.pop(0)
    return " ".join(parts)


def _unquote_double(value: str) -> str:
    chars: list[str] = []
    escape = False
    escapes = {
        "0": "\0",
        '"': '"',
        "\\": "\\",
        "n": "\n",
        "r": "\r",
        "t": "\t",
    }
    for char in value[1:-1]:
        if escape:
            chars.append(escapes.get(char, char))
            escape = False
        elif char == "\\":
            escape = True
        else:
            chars.append(char)
    if escape:
        chars.append("\\")
    return "".join(chars)


def _split_flow_items(value: str) -> list[str]:
    items: list[str] = []
    start = 0
    quote: str | None = None
    escape = False
    depth = 0
    for index, char in enumerate(value):
        if quote:
            if quote == '"' and char == "\\" and not escape:
                escape = True
                continue
            if char == quote and not escape:
                quote = None
            escape = False
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char in "[{(":
            depth += 1
            continue
        if char in "]})":
            depth = max(depth - 1, 0)
            continue
        if char == "," and depth == 0:
            items.append(value[start:index].strip())
            start = index + 1
    tail = value[start:].strip()
    if tail:
        items.append(tail)
    return items


def _strip_inline_comment(value: str) -> str:
    quote: str | None = None
    escape = False
    for index, char in enumerate(value):
        if quote:
            if quote == '"' and char == "\\" and not escape:
                escape = True
                continue
            if char == quote and not escape:
                quote = None
            escape = False
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
    return value
