#!/usr/bin/env python3
"""Fail-closed lexical/structural inventory for Rust proof scripts.

This is intentionally not a Rust compiler.  It provides the small, auditable
subset needed by the Store qualification guards:

* comments and literal contents never participate in code searches;
* every delimiter is paired or scanning refuses;
* function items, their impl owner, visibility, attributes, and body are
  identified structurally;
* direct call expressions and public re-exports are inventoried; and
* all Cargo production targets and feature/dependency surfaces are discoverable.

Macro expansion and dynamic dispatch are not guessed.  Guards using this
module must explicitly refuse those alternate surfaces for protected symbols.
"""

from __future__ import annotations

import bisect
import dataclasses
import re
import tomllib
from pathlib import Path
from typing import Iterable, Iterator, Sequence


class ScanError(AssertionError):
    """The source cannot be classified without ambiguity."""


@dataclasses.dataclass(frozen=True)
class Token:
    kind: str
    value: str
    start: int
    end: int
    line: int
    column: int


@dataclasses.dataclass(frozen=True)
class Call:
    name: str
    path: str
    kind: str
    receiver: str | None
    start: int
    line: int


@dataclasses.dataclass(frozen=True)
class ImplScope:
    owner: str
    trait_name: str | None
    start_token: int
    open_token: int
    close_token: int
    attributes: tuple[str, ...]
    cfg_test: bool


@dataclasses.dataclass(frozen=True)
class Function:
    source: "RustSource"
    name: str
    owner: str | None
    trait_owner: str | None
    visibility: str
    attributes: tuple[str, ...]
    cfg_test: bool
    declaration_only: bool
    start_token: int
    fn_token: int
    name_token: int
    body_open_token: int | None
    body_close_token: int | None
    end_token: int

    @property
    def line(self) -> int:
        return self.source.tokens[self.fn_token].line

    @property
    def location(self) -> str:
        return f"{self.source.path}:{self.line}"

    @property
    def qualified_name(self) -> str:
        if self.owner:
            return f"{self.owner}::{self.name}"
        return self.name

    @property
    def raw(self) -> str:
        first = self.source.tokens[self.start_token].start
        last = self.source.tokens[self.end_token].end
        return self.source.text[first:last]

    @property
    def code(self) -> str:
        """Whitespace-normalized code tokens, with literal contents absent."""
        return token_text(self.item_tokens, include_literals=False)

    @property
    def signature_code(self) -> str:
        end = (
            self.body_open_token
            if self.body_open_token is not None
            else self.end_token + 1
        )
        return token_text(
            self.source.tokens[self.start_token : end], include_literals=False
        )

    @property
    def item_tokens(self) -> Sequence[Token]:
        return self.source.tokens[self.start_token : self.end_token + 1]

    @property
    def body_tokens(self) -> Sequence[Token]:
        if self.body_open_token is None or self.body_close_token is None:
            return ()
        return self.source.tokens[self.body_open_token + 1 : self.body_close_token]

    @property
    def string_literals(self) -> tuple[str, ...]:
        return tuple(
            token.value for token in self.item_tokens if token.kind == "literal"
        )

    def calls(self, name: str | None = None) -> list[Call]:
        found = calls_in_tokens(self.body_tokens)
        return found if name is None else [call for call in found if call.name == name]

    def code_identifiers(self, value: str | None = None) -> list[Token]:
        found = [token for token in self.item_tokens if token.kind == "ident"]
        return (
            found
            if value is None
            else [token for token in found if token.value == value]
        )


@dataclasses.dataclass(frozen=True)
class ReExport:
    source: "RustSource"
    visibility: str
    path: str
    names: tuple[str, ...]
    start_token: int
    end_token: int

    @property
    def line(self) -> int:
        return self.source.tokens[self.start_token].line

    @property
    def location(self) -> str:
        return f"{self.source.path}:{self.line}"


@dataclasses.dataclass(frozen=True)
class CargoPackage:
    name: str
    root: Path
    manifest: dict
    production_sources: tuple[Path, ...]

    @property
    def features(self) -> dict[str, list[str]]:
        return self.manifest.get("features", {})

    def dependency_tables(
        self, *, include_dev: bool = False
    ) -> Iterator[tuple[str, dict]]:
        names = {"dependencies", "build-dependencies"}
        if include_dev:
            names.add("dev-dependencies")
        for name in sorted(names):
            table = self.manifest.get(name)
            if isinstance(table, dict):
                yield name, table
        target = self.manifest.get("target", {})
        if isinstance(target, dict):
            for target_name, target_table in sorted(target.items()):
                if not isinstance(target_table, dict):
                    continue
                for name in sorted(names):
                    table = target_table.get(name)
                    if isinstance(table, dict):
                        yield f"target.{target_name}.{name}", table


def _line_column(text: str, starts: Sequence[int], offset: int) -> tuple[int, int]:
    line_index = bisect.bisect_right(starts, offset) - 1
    return line_index + 1, offset - starts[line_index] + 1


def _literal_end(text: str, start: int) -> int | None:
    """Return one-past-end for a Rust string/byte/raw/char literal."""
    length = len(text)
    index = start
    prefix = ""
    if text.startswith("br", index) or text.startswith("rb", index):
        prefix = text[index : index + 2]
        index += 2
    elif index < length and text[index] in "bcr":
        prefix = text[index]
        index += 1

    if "r" in prefix:
        hashes = 0
        while index < length and text[index] == "#":
            hashes += 1
            index += 1
        if index >= length or text[index] != '"':
            return None
        marker = '"' + ("#" * hashes)
        ending = text.find(marker, index + 1)
        if ending < 0:
            raise ScanError(f"unterminated raw literal at byte {start}")
        return ending + len(marker)

    if index >= length or text[index] not in "\"'":
        return None
    quote = text[index]
    # A lifetime such as 'store is not a character literal.
    if quote == "'" and index + 1 < length and re.match(r"[A-Za-z_]", text[index + 1]):
        possible = index + 2
        while possible < length and re.match(r"[A-Za-z0-9_]", text[possible]):
            possible += 1
        if possible >= length or text[possible] != "'":
            return None
    index += 1
    escaped = False
    while index < length:
        character = text[index]
        if character == "\n" and quote == "'":
            raise ScanError(f"unterminated character literal at byte {start}")
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == quote:
            return index + 1
        index += 1
    raise ScanError(f"unterminated literal at byte {start}")


def lex_rust(
    text: str, *, label: str = "<memory>"
) -> tuple[list[Token], dict[int, int]]:
    """Lex source while omitting comments and retaining literals as opaque tokens."""
    starts = [0]
    starts.extend(match.end() for match in re.finditer("\n", text))
    tokens: list[Token] = []
    index = 0
    length = len(text)

    def emit(kind: str, value: str, start: int, end: int) -> None:
        line, column = _line_column(text, starts, start)
        tokens.append(Token(kind, value, start, end, line, column))

    while index < length:
        character = text[index]
        if character.isspace():
            index += 1
            continue
        if text.startswith("//", index):
            ending = text.find("\n", index + 2)
            index = length if ending < 0 else ending + 1
            continue
        if text.startswith("/*", index):
            start = index
            depth = 1
            index += 2
            while index < length and depth:
                if text.startswith("/*", index):
                    depth += 1
                    index += 2
                elif text.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            if depth:
                line, column = _line_column(text, starts, start)
                raise ScanError(f"{label}:{line}:{column}: unterminated block comment")
            continue

        literal_end = _literal_end(text, index)
        if literal_end is not None:
            emit("literal", text[index:literal_end], index, literal_end)
            index = literal_end
            continue

        if re.match(r"[A-Za-z_]", character):
            ending = index + 1
            while ending < length and re.match(r"[A-Za-z0-9_]", text[ending]):
                ending += 1
            emit("ident", text[index:ending], index, ending)
            index = ending
            continue
        if character.isdigit():
            ending = index + 1
            while ending < length and re.match(r"[A-Za-z0-9_.]", text[ending]):
                ending += 1
            emit("number", text[index:ending], index, ending)
            index = ending
            continue

        # Multi-character punctuation is useful when normalizing signatures.
        punctuation = next(
            (
                candidate
                for candidate in (
                    "::",
                    "->",
                    "=>",
                    "..=",
                    "...",
                    "..",
                    "&&",
                    "||",
                    "==",
                    "!=",
                    "<=",
                    ">=",
                    "+=",
                    "-=",
                    "*=",
                    "/=",
                )
                if text.startswith(candidate, index)
            ),
            character,
        )
        emit("punct", punctuation, index, index + len(punctuation))
        index += len(punctuation)

    pairs: dict[int, int] = {}
    stack: list[tuple[str, int]] = []
    matching = {")": "(", "]": "[", "}": "{"}
    for token_index, token in enumerate(tokens):
        if token.value in "([{":
            stack.append((token.value, token_index))
        elif token.value in ")]}":
            if not stack or stack[-1][0] != matching[token.value]:
                raise ScanError(
                    f"{label}:{token.line}:{token.column}: unmatched delimiter {token.value}"
                )
            _, opening = stack.pop()
            pairs[opening] = token_index
            pairs[token_index] = opening
    if stack:
        value, token_index = stack[-1]
        token = tokens[token_index]
        raise ScanError(
            f"{label}:{token.line}:{token.column}: unclosed delimiter {value}"
        )
    return tokens, pairs


def token_text(tokens: Sequence[Token], *, include_literals: bool = False) -> str:
    values = []
    for token in tokens:
        if token.kind == "literal" and not include_literals:
            values.append("<literal>")
        else:
            values.append(token.value)
    return " ".join(values)


def compact_tokens(tokens: Sequence[Token], *, include_literals: bool = False) -> str:
    return "".join(
        token.value if include_literals or token.kind != "literal" else "<literal>"
        for token in tokens
    )


def _attributes(
    tokens: Sequence[Token], pairs: dict[int, int], start: int, end: int
) -> tuple[str, ...]:
    attributes: list[str] = []
    index = start
    while index < end:
        if (
            tokens[index].value == "#"
            and index + 1 < end
            and tokens[index + 1].value == "["
        ):
            closing = pairs[index + 1]
            if closing >= end:
                break
            attributes.append(
                compact_tokens(tokens[index + 2 : closing], include_literals=True)
            )
            index = closing + 1
        else:
            index += 1
    return tuple(attributes)


def cfg_is_test_only(attributes: Iterable[str]) -> bool:
    """True only when an attribute unconditionally requires Cargo's test cfg.

    `cfg(any(test, feature = "test-support"))` is deliberately *not* test-only:
    the feature arm is a product compilation surface and must be scanned.
    """
    for attribute in attributes:
        compact = attribute.replace(" ", "")
        if compact == "cfg(test)" or re.match(r"^cfg\(all\(test(?:,|\))", compact):
            return True
    return False


def _brace_depths(tokens: Sequence[Token]) -> list[int]:
    depths: list[int] = []
    depth = 0
    for token in tokens:
        depths.append(depth)
        if token.value == "{":
            depth += 1
        elif token.value == "}":
            depth -= 1
    if depth != 0:
        raise ScanError("internal brace-depth mismatch")
    return depths


def _item_prefix_start(
    tokens: Sequence[Token], depths: Sequence[int], item_index: int
) -> int:
    depth = depths[item_index]
    index = item_index - 1
    while index >= 0:
        value = tokens[index].value
        if depths[index] == depth and value == ";":
            return index + 1
        # A closing brace is recorded at the depth *inside* the block.
        if depths[index] == depth + 1 and value == "}":
            return index + 1
        if value == "{" and depths[index] == depth - 1:
            return index + 1
        index -= 1
    return 0


def _visibility(
    tokens: Sequence[Token], pairs: dict[int, int], start: int, fn_index: int
) -> str:
    index = start
    while index < fn_index:
        if tokens[index].value == "pub":
            if index + 1 < fn_index and tokens[index + 1].value == "(":
                closing = pairs[tokens.index(tokens[index + 1])]
                return f"pub({compact_tokens(tokens[index + 2 : closing])})"
            return "pub"
        index += 1
    return "private"


def _visibility_by_index(
    tokens: Sequence[Token], pairs: dict[int, int], start: int, end: int
) -> str:
    for index in range(start, end):
        if tokens[index].value != "pub":
            continue
        if index + 1 < end and tokens[index + 1].value == "(":
            closing = pairs[index + 1]
            return f"pub({compact_tokens(tokens[index + 2 : closing])})"
        return "pub"
    return "private"


def _impl_owner(header: Sequence[Token]) -> tuple[str, str | None]:
    values = [token.value for token in header]
    # Drop impl generics.
    index = 1
    if index < len(values) and values[index] == "<":
        depth = 0
        while index < len(values):
            if values[index] == "<":
                depth += 1
            elif values[index] == ">":
                depth -= 1
                if depth == 0:
                    index += 1
                    break
            index += 1
        if depth:
            raise ScanError("unterminated impl generic parameter list")
    remainder = header[index:]
    for_position = next(
        (i for i, token in enumerate(remainder) if token.value == "for"), None
    )
    trait_tokens = remainder[:for_position] if for_position is not None else ()
    owner_tokens = (
        remainder[for_position + 1 :] if for_position is not None else remainder
    )
    where_position = next(
        (i for i, token in enumerate(owner_tokens) if token.value == "where"),
        len(owner_tokens),
    )
    owner_tokens = owner_tokens[:where_position]

    def outer_type_name(candidates: Sequence[Token]) -> str | None:
        angle_depth = 0
        names: list[str] = []
        for candidate in candidates:
            if candidate.value == "<":
                angle_depth += 1
            elif candidate.value == ">" and angle_depth:
                angle_depth -= 1
            elif (
                angle_depth == 0
                and candidate.kind == "ident"
                and candidate.value not in ("const", "unsafe")
            ):
                names.append(candidate.value)
        return names[-1] if names else None

    owner = outer_type_name(owner_tokens)
    if owner is None:
        raise ScanError(f"cannot identify impl owner in {token_text(header)}")
    trait_name = outer_type_name(trait_tokens)
    return owner, trait_name


def _find_impl_scopes(
    tokens: Sequence[Token], pairs: dict[int, int], depths: Sequence[int]
) -> list[ImplScope]:
    scopes: list[ImplScope] = []
    for index, token in enumerate(tokens):
        if token.value != "impl":
            continue
        # `impl Trait` in a return type cannot start an item.
        prefix_start = _item_prefix_start(tokens, depths, index)
        prefix_values = {candidate.value for candidate in tokens[prefix_start:index]}
        if "->" in prefix_values or "=" in prefix_values or ":" in prefix_values:
            continue
        opening = None
        cursor = index + 1
        while cursor < len(tokens):
            if depths[cursor] < depths[index]:
                break
            if depths[cursor] == depths[index] and tokens[cursor].value in (";", "="):
                break
            if depths[cursor] == depths[index] and tokens[cursor].value == "{":
                opening = cursor
                break
            cursor += 1
        if opening is None:
            continue
        owner, trait_name = _impl_owner(tokens[index:opening])
        attributes = _attributes(tokens, pairs, prefix_start, index)
        scopes.append(
            ImplScope(
                owner=owner,
                trait_name=trait_name,
                start_token=prefix_start,
                open_token=opening,
                close_token=pairs[opening],
                attributes=attributes,
                cfg_test=cfg_is_test_only(attributes),
            )
        )
    return scopes


def _cfg_item_scopes(
    tokens: Sequence[Token], pairs: dict[int, int], depths: Sequence[int]
) -> list[tuple[int, int]]:
    scopes: list[tuple[int, int]] = []
    for index, token in enumerate(tokens):
        if token.value not in ("mod", "impl", "trait"):
            continue
        prefix_start = _item_prefix_start(tokens, depths, index)
        attributes = _attributes(tokens, pairs, prefix_start, index)
        if not cfg_is_test_only(attributes):
            continue
        cursor = index + 1
        while cursor < len(tokens) and depths[cursor] >= depths[index]:
            if depths[cursor] == depths[index] and tokens[cursor].value == "{":
                scopes.append((cursor, pairs[cursor]))
                break
            if depths[cursor] == depths[index] and tokens[cursor].value == ";":
                break
            cursor += 1
    return scopes


class RustSource:
    """One structurally scanned Rust source file."""

    def __init__(
        self, path: Path, *, root: Path | None = None, text: str | None = None
    ):
        self.path = path if root is None else path.relative_to(root)
        self.absolute_path = path
        self.text = path.read_text(encoding="utf-8") if text is None else text
        self.tokens, self.pairs = lex_rust(self.text, label=str(self.path))
        self.depths = _brace_depths(self.tokens)
        self.impl_scopes = _find_impl_scopes(self.tokens, self.pairs, self.depths)
        self._cfg_scopes = _cfg_item_scopes(self.tokens, self.pairs, self.depths)
        self.functions = self._find_functions()
        self.reexports = self._find_reexports()

    @classmethod
    def from_text(cls, text: str, label: str = "fixture.rs") -> "RustSource":
        return cls(Path(label), text=text)

    def _find_functions(self) -> list[Function]:
        functions: list[Function] = []
        for index, token in enumerate(self.tokens):
            if token.value != "fn" or index + 1 >= len(self.tokens):
                continue
            name_token = self.tokens[index + 1]
            if name_token.kind != "ident":
                continue  # bare function-pointer type
            start = _item_prefix_start(self.tokens, self.depths, index)
            attributes = _attributes(self.tokens, self.pairs, start, index)
            cursor = index + 2
            body_open = None
            declaration_end = None
            base_depth = self.depths[index]
            while cursor < len(self.tokens):
                if self.depths[cursor] < base_depth:
                    break
                if (
                    self.depths[cursor] == base_depth
                    and self.tokens[cursor].value == "{"
                ):
                    body_open = cursor
                    break
                if (
                    self.depths[cursor] == base_depth
                    and self.tokens[cursor].value == ";"
                ):
                    declaration_end = cursor
                    break
                cursor += 1
            if body_open is None and declaration_end is None:
                raise ScanError(
                    f"{self.path}:{token.line}: function {name_token.value} has no body or semicolon"
                )
            body_close = self.pairs[body_open] if body_open is not None else None
            end = body_close if body_close is not None else declaration_end
            assert end is not None
            enclosing = [
                scope
                for scope in self.impl_scopes
                if scope.open_token < index < scope.close_token
            ]
            owner_scope = (
                min(enclosing, key=lambda scope: scope.close_token - scope.open_token)
                if enclosing
                else None
            )
            inherited_cfg = any(
                opening < index < closing for opening, closing in self._cfg_scopes
            )
            functions.append(
                Function(
                    source=self,
                    name=name_token.value,
                    owner=owner_scope.owner if owner_scope else None,
                    trait_owner=owner_scope.trait_name if owner_scope else None,
                    visibility=_visibility_by_index(
                        self.tokens, self.pairs, start, index
                    ),
                    attributes=attributes,
                    cfg_test=cfg_is_test_only(attributes)
                    or inherited_cfg
                    or bool(owner_scope and owner_scope.cfg_test),
                    declaration_only=body_open is None,
                    start_token=start,
                    fn_token=index,
                    name_token=index + 1,
                    body_open_token=body_open,
                    body_close_token=body_close,
                    end_token=end,
                )
            )
        return functions

    def _find_reexports(self) -> list[ReExport]:
        found: list[ReExport] = []
        for index, token in enumerate(self.tokens):
            if token.value != "use":
                continue
            start = _item_prefix_start(self.tokens, self.depths, index)
            visibility = _visibility_by_index(self.tokens, self.pairs, start, index)
            if not visibility.startswith("pub"):
                continue
            end = index + 1
            while end < len(self.tokens):
                if (
                    self.depths[end] == self.depths[index]
                    and self.tokens[end].value == ";"
                ):
                    break
                end += 1
            if end >= len(self.tokens):
                raise ScanError(f"{self.path}:{token.line}: public use lacks semicolon")
            use_tokens = self.tokens[index + 1 : end]
            names = tuple(
                candidate.value
                for candidate in use_tokens
                if candidate.kind == "ident"
                and candidate.value not in ("as", "self", "super", "crate")
            )
            found.append(
                ReExport(
                    source=self,
                    visibility=visibility,
                    path=compact_tokens(use_tokens, include_literals=False),
                    names=names,
                    start_token=start,
                    end_token=end,
                )
            )
        return found

    def find_functions(
        self,
        name: str | None = None,
        *,
        owner: str | None = None,
        production_only: bool = False,
    ) -> list[Function]:
        result = self.functions
        if name is not None:
            result = [function for function in result if function.name == name]
        if owner is not None:
            result = [function for function in result if function.owner == owner]
        if production_only:
            result = [function for function in result if not function.cfg_test]
        return result

    def require_function(
        self,
        name: str,
        *,
        owner: str | None = None,
        production_only: bool = False,
    ) -> Function:
        result = self.find_functions(name, owner=owner, production_only=production_only)
        qualifier = f"{owner}::{name}" if owner else name
        if len(result) != 1:
            locations = ", ".join(function.location for function in result) or "none"
            raise ScanError(
                f"{self.path}: expected exactly one {qualifier}; found {len(result)} ({locations})"
            )
        return result[0]

    def identifier_occurrences(self, name: str) -> list[Token]:
        return [
            token
            for token in self.tokens
            if token.kind == "ident" and token.value == name
        ]

    def item_attributes(self, token_index: int) -> tuple[str, ...]:
        """Return attributes attached to the item keyword at `token_index`."""
        if not 0 <= token_index < len(self.tokens):
            raise ScanError(
                f"{self.path}: item token index is out of bounds: {token_index}"
            )
        start = _item_prefix_start(self.tokens, self.depths, token_index)
        return _attributes(self.tokens, self.pairs, start, token_index)


def calls_in_tokens(tokens: Sequence[Token]) -> list[Call]:
    calls: list[Call] = []
    excluded = {
        "as",
        "break",
        "const",
        "continue",
        "else",
        "enum",
        "extern",
        "fn",
        "for",
        "if",
        "impl",
        "in",
        "let",
        "loop",
        "match",
        "mod",
        "move",
        "return",
        "static",
        "struct",
        "trait",
        "type",
        "unsafe",
        "use",
        "where",
        "while",
    }
    for index, token in enumerate(tokens):
        if token.value != "(" or index == 0:
            continue
        previous = index - 1
        # Direct calls may carry a turbofish: `function::<T, U>(...)`.
        if tokens[previous].value == ">":
            angle_depth = 1
            cursor = previous - 1
            while cursor >= 0 and angle_depth:
                if tokens[cursor].value == ">":
                    angle_depth += 1
                elif tokens[cursor].value == "<":
                    angle_depth -= 1
                cursor -= 1
            if angle_depth or cursor < 1 or tokens[cursor].value != "::":
                continue
            previous = cursor - 1
        if tokens[previous].kind != "ident":
            continue
        name = tokens[previous].value
        if name in excluded or (
            previous > 0 and tokens[previous - 1].value in ("fn", "!")
        ):
            continue
        start = previous
        while (
            start >= 2
            and tokens[start - 1].value == "::"
            and tokens[start - 2].kind == "ident"
        ):
            start -= 2
        path = compact_tokens(tokens[start : previous + 1])
        kind = (
            "method"
            if previous > 0 and tokens[previous - 1].value == "."
            else ("path" if "::" in path else "free")
        )
        receiver = None
        if kind == "method" and previous >= 2 and tokens[previous - 2].kind == "ident":
            receiver_start = previous - 2
            while (
                receiver_start >= 2
                and tokens[receiver_start - 1].value == "."
                and tokens[receiver_start - 2].kind == "ident"
            ):
                receiver_start -= 2
            receiver = compact_tokens(tokens[receiver_start : previous - 1])
        calls.append(
            Call(
                name=name,
                path=path,
                kind=kind,
                receiver=receiver,
                start=token.start,
                line=token.line,
            )
        )
    return calls


def _manifest_source_paths(package_root: Path, manifest: dict) -> set[Path]:
    sources: set[Path] = set()
    package = manifest.get("package", {})
    build = package.get("build") if isinstance(package, dict) else None
    if build is not False:
        build_path = package_root / (build if isinstance(build, str) else "build.rs")
        if build_path.is_file():
            sources.add(build_path)

    src = package_root / "src"
    if src.is_dir():
        sources.update(src.rglob("*.rs"))
    examples = package_root / "examples"
    if examples.is_dir():
        sources.update(examples.rglob("*.rs"))
    for table_name in ("lib", "bin", "example"):
        entries = manifest.get(table_name, [])
        if isinstance(entries, dict):
            entries = [entries]
        for entry in entries:
            if isinstance(entry, dict) and isinstance(entry.get("path"), str):
                path = package_root / entry["path"]
                if not path.is_file():
                    raise ScanError(f"Cargo target path is absent: {path}")
                sources.add(path)
    return sources


def workspace_packages(root: Path) -> tuple[CargoPackage, ...]:
    workspace_manifest_path = root / "Cargo.toml"
    with workspace_manifest_path.open("rb") as handle:
        workspace_manifest = tomllib.load(handle)
    members = workspace_manifest.get("workspace", {}).get("members")
    if not isinstance(members, list) or not all(
        isinstance(member, str) for member in members
    ):
        raise ScanError("workspace.members must be an explicit string list")
    packages: list[CargoPackage] = []
    for member in members:
        if any(character in member for character in "*?["):
            raise ScanError(f"workspace member globs are not proof-auditable: {member}")
        package_root = root / member
        manifest_path = package_root / "Cargo.toml"
        if not manifest_path.is_file():
            raise ScanError(f"workspace member manifest is absent: {manifest_path}")
        with manifest_path.open("rb") as handle:
            manifest = tomllib.load(handle)
        name = manifest.get("package", {}).get("name")
        if not isinstance(name, str):
            raise ScanError(f"package name is absent: {manifest_path}")
        packages.append(
            CargoPackage(
                name=name,
                root=package_root,
                manifest=manifest,
                production_sources=tuple(
                    sorted(_manifest_source_paths(package_root, manifest))
                ),
            )
        )
    names = [package.name for package in packages]
    if len(names) != len(set(names)):
        raise ScanError("workspace package names are not unique")
    return tuple(packages)


def production_sources(root: Path) -> tuple[RustSource, ...]:
    paths = sorted(
        {
            path
            for package in workspace_packages(root)
            for path in package.production_sources
        }
    )
    return tuple(RustSource(path, root=root) for path in paths)


def compile_confined_module_paths(sources: Sequence[RustSource]) -> set[str]:
    """Resolve external modules whose declaration is gated by `cfg(test)`."""
    known = {
        source.absolute_path.resolve(): source.path.as_posix() for source in sources
    }
    confined: set[str] = set()
    for source in sources:
        for index, token in enumerate(source.tokens[:-2]):
            if token.value != "mod" or source.tokens[index + 1].kind != "ident":
                continue
            cursor = index + 2
            while (
                cursor < len(source.tokens)
                and source.depths[cursor] >= source.depths[index]
            ):
                if source.depths[cursor] == source.depths[index] and source.tokens[
                    cursor
                ].value in (";", "{"):
                    break
                cursor += 1
            if cursor >= len(source.tokens) or source.tokens[cursor].value != ";":
                continue
            attributes = source.item_attributes(index)
            if not cfg_is_test_only(attributes):
                continue
            explicit_path = next(
                (
                    attribute
                    for attribute in attributes
                    if attribute.startswith("path=")
                ),
                None,
            )
            candidates: list[Path]
            if explicit_path is not None:
                match = re.fullmatch(r'path="([^"\\]+)"', explicit_path)
                if match is None:
                    raise ScanError(
                        f"{source.path}:{token.line}: cfg(test) module has unsupported path attribute {explicit_path}"
                    )
                candidates = [source.absolute_path.parent / match.group(1)]
            else:
                module_name = source.tokens[index + 1].value
                if source.absolute_path.stem in ("lib", "main", "mod"):
                    base = source.absolute_path.parent
                else:
                    base = source.absolute_path.parent / source.absolute_path.stem
                candidates = [base / f"{module_name}.rs", base / module_name / "mod.rs"]
            matches = [
                candidate.resolve()
                for candidate in candidates
                if candidate.resolve() in known
            ]
            if len(matches) != 1:
                raise ScanError(
                    f"{source.path}:{token.line}: cfg(test) external module resolves ambiguously or is absent: "
                    + ", ".join(str(candidate) for candidate in candidates)
                )
            confined.add(known[matches[0]])
    return confined


def cargo_test_sources(
    root: Path, packages: Sequence[CargoPackage] | None = None
) -> tuple[RustSource, ...]:
    """Scan explicit Cargo test/bench targets, which are compile-confined."""
    packages = workspace_packages(root) if packages is None else packages
    paths: set[Path] = set()
    for package in packages:
        for directory_name in ("tests", "benches"):
            directory = package.root / directory_name
            if directory.is_dir():
                paths.update(directory.rglob("*.rs"))
        for table_name in ("test", "bench"):
            entries = package.manifest.get(table_name, [])
            if isinstance(entries, dict):
                entries = [entries]
            for entry in entries:
                if isinstance(entry, dict) and isinstance(entry.get("path"), str):
                    path = package.root / entry["path"]
                    if not path.is_file():
                        raise ScanError(
                            f"Cargo {table_name} target path is absent: {path}"
                        )
                    paths.add(path)
    return tuple(RustSource(path, root=root) for path in sorted(paths))


def production_functions(
    sources: Iterable[RustSource], *, compile_confined_paths: set[str] | None = None
) -> list[Function]:
    compile_confined_paths = (
        set() if compile_confined_paths is None else compile_confined_paths
    )
    return [
        function
        for source in sources
        for function in source.functions
        if not function.cfg_test
        and source.path.as_posix() not in compile_confined_paths
    ]


def require_unique_function(
    functions: Iterable[Function],
    *,
    name: str,
    owner: str | None = None,
    path: str | None = None,
) -> Function:
    matches = [function for function in functions if function.name == name]
    if owner is not None:
        matches = [function for function in matches if function.owner == owner]
    if path is not None:
        matches = [
            function for function in matches if function.source.path.as_posix() == path
        ]
    selector = "/".join(value for value in (path, owner, name) if value)
    if len(matches) != 1:
        locations = ", ".join(function.location for function in matches) or "none"
        raise ScanError(
            f"expected exactly one function {selector}; found {len(matches)} ({locations})"
        )
    return matches[0]


def reachable_callers(
    functions: Sequence[Function], target_names: set[str]
) -> tuple[set[Function], dict[Function, set[str]]]:
    """Conservative reverse reachability by unqualified call name.

    Name ambiguity broadens the graph rather than selecting a convenient
    definition.  This makes reachability checks conservative and fail closed.
    """
    callers_by_name: dict[str, set[Function]] = {}
    for function in functions:
        for call in function.calls():
            callers_by_name.setdefault(call.name, set()).add(function)
    reached: set[Function] = set()
    reasons: dict[Function, set[str]] = {}
    frontier = set(target_names)
    while frontier:
        target = frontier.pop()
        for caller in callers_by_name.get(target, set()):
            reasons.setdefault(caller, set()).add(target)
            if caller not in reached:
                reached.add(caller)
                frontier.add(caller.name)
    return reached, reasons


def _self_test() -> None:
    fixture = r"""
// fn decoy() { bare_helper(); }
#[cfg(test)]
mod tests {
    pub(super) fn fixture() { bare_helper("literal bare_helper()"); }
}
#[cfg(any(test, feature = "test-support"))]
fn feature_surface() { alternate(); }
struct Store;
impl Store {
    pub(crate) fn bare_helper(&mut self) { /* bare_helper(); */ sink(); }
}
impl<'a> Session<'a> {
    pub fn typed(&mut self) { self.check()?; self.store.bare_helper(); generic::<u8>(); }
}
pub use private::Surface;
"""
    source = RustSource.from_text(fixture)
    assert source.require_function("fixture").cfg_test
    assert not source.require_function("feature_surface").cfg_test
    helper = source.require_function("bare_helper", owner="Store")
    assert [call.name for call in helper.calls()] == ["sink"]
    typed = source.require_function("typed", owner="Session")
    assert [call.name for call in typed.calls()] == ["check", "bare_helper", "generic"]
    assert typed.visibility == "pub"
    assert len(source.reexports) == 1 and "Surface" in source.reexports[0].names
    try:
        RustSource.from_text("fn broken() {", "broken.rs")
    except ScanError:
        pass
    else:
        raise AssertionError("unterminated fixture did not refuse")
    print("Rust source scanner self-test: PASS")


if __name__ == "__main__":
    _self_test()
