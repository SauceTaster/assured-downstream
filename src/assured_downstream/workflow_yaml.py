from __future__ import annotations

import re
from typing import Any

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode


MAX_WORKFLOW_BYTES = 1 * 1024 * 1024
MAX_WORKFLOW_NODES = 100_000
BOOL_TAG = "tag:yaml.org,2002:bool"
TIMESTAMP_TAG = "tag:yaml.org,2002:timestamp"


class WorkflowYamlError(ValueError):
    """Raised when workflow YAML is malformed or outside safe parser limits."""


class WorkflowLoader(yaml.SafeLoader):
    pass


# GitHub treats `on` and `off` as strings. PyYAML's YAML 1.1 resolver does not.
WorkflowLoader.yaml_implicit_resolvers = {
    key: [
        (tag, pattern)
        for tag, pattern in resolvers
        if tag not in {BOOL_TAG, TIMESTAMP_TAG}
    ]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
WorkflowLoader.add_implicit_resolver(
    BOOL_TAG,
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)


def parse_workflow_yaml(text: str) -> dict[str, Any]:
    """Parse a bounded GitHub Actions workflow without constructing code."""

    if len(text.encode("utf-8")) > MAX_WORKFLOW_BYTES:
        raise WorkflowYamlError(
            f"workflow YAML exceeds the {MAX_WORKFLOW_BYTES}-byte parser limit"
        )
    try:
        value = yaml.load(text, Loader=WorkflowLoader)
    except yaml.YAMLError as exc:
        raise WorkflowYamlError(yaml_error_message(exc)) from exc
    except RecursionError as exc:
        raise WorkflowYamlError("workflow YAML nesting is too deep") from exc
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise WorkflowYamlError("workflow YAML root must be a mapping")
    try:
        validate_graph(value)
    except RecursionError as exc:
        raise WorkflowYamlError("workflow YAML nesting is too deep") from exc
    return value


def construct_unique_mapping(
    loader: WorkflowLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


WorkflowLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)


def validate_graph(root: Any) -> None:
    node_count = 0
    active: set[int] = set()

    def visit(value: Any) -> None:
        nonlocal node_count
        node_count += 1
        if node_count > MAX_WORKFLOW_NODES:
            raise WorkflowYamlError(
                f"workflow YAML exceeds the {MAX_WORKFLOW_NODES}-node parser limit"
            )
        if isinstance(value, dict):
            identity = id(value)
            if identity in active:
                raise WorkflowYamlError("workflow YAML contains a recursive mapping")
            active.add(identity)
            for key, child in value.items():
                if not isinstance(key, str):
                    raise WorkflowYamlError("workflow YAML mapping keys must be strings")
                visit(child)
            active.remove(identity)
        elif isinstance(value, list):
            identity = id(value)
            if identity in active:
                raise WorkflowYamlError("workflow YAML contains a recursive sequence")
            active.add(identity)
            for child in value:
                visit(child)
            active.remove(identity)
        elif not isinstance(value, (str, int, float, bool, type(None))):
            raise WorkflowYamlError(
                f"workflow YAML contains unsupported value type {type(value).__name__}"
            )

    visit(root)


def yaml_error_message(error: yaml.YAMLError) -> str:
    problem = getattr(error, "problem", None)
    mark = getattr(error, "problem_mark", None)
    if problem and mark is not None:
        return f"{problem} at line {mark.line + 1}, column {mark.column + 1}"
    return str(error).strip() or "workflow YAML could not be parsed"
