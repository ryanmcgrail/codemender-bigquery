# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Small YAML helpers that need no third-party packages.

Terraform's yamldecode() is the source of truth for repos.yaml and
deployment.yaml (see validate.py). This module only:

*   scans block-style YAML line by line, for lints that Terraform cannot do
    (duplicate keys, unquoted values that yamldecode() does not read as
    text), and
*   writes scalars that every YAML reader reads back unchanged.
"""

import dataclasses
import json
import re
from typing import Dict, Iterator, List, Optional, Tuple

_KEY_RE = re.compile(
    r"""^(?P<indent>[ ]*)(?P<dash>-[ ]+)?(?P<key>"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s#'"][^:#]*?)[ ]*:(?:[ ]+(?P<value>.*?))?[ ]*$"""
)
_BLOCK_SCALAR_RE = re.compile(r"^[|>][+-]?[0-9]?[+-]?(\s+#.*)?$")


@dataclasses.dataclass(frozen=True)
class Entry:
  """One `key: value` line of a block-style YAML document."""

  path: Tuple[str, ...]  # keys of the enclosing mappings, outermost first
  key: str
  raw_value: str  # text after the colon, comment removed; "" for a parent
  line: int  # 1-based


def _unquote_key(key: str) -> str:
  if len(key) >= 2 and key[0] == key[-1] == '"':
    try:
      return json.loads(key)
    except ValueError:
      return key[1:-1]
  if len(key) >= 2 and key[0] == key[-1] == "'":
    return key[1:-1].replace("''", "'")
  return key.strip()


def strip_comment(value: str) -> str:
  """Removes a trailing ` # comment` that is outside quotes."""
  in_single = in_double = False
  prev = " "
  for i, ch in enumerate(value):
    if ch == "'" and not in_double:
      in_single = not in_single
    elif ch == '"' and not in_single and prev != "\\":
      in_double = not in_double
    elif ch == "#" and not in_single and not in_double and prev in " \t":
      return value[:i].rstrip()
    prev = ch
  return value.rstrip()


def scan(text: str) -> Iterator[Entry]:
  """Yields the `key: value` lines of block-style YAML with their paths.

  Flow collections, anchors and multi-document files are not interpreted;
  block scalars (| and >) are skipped. Good enough for lints, never for
  reading values that matter.
  """
  stack: List[Tuple[int, str]] = []  # (indent, key) of open parent mappings
  items: Dict[Tuple[Tuple[str, ...], int], int] = {}  # sequence item counters
  block_indent: Optional[int] = None
  for lineno, line in enumerate(text.splitlines(), start=1):
    stripped = line.strip()
    indent = len(line) - len(line.lstrip(" "))
    if block_indent is not None:
      if not stripped or indent > block_indent:
        continue
      block_indent = None
    if not stripped or stripped.startswith("#") or stripped in ("---", "..."):
      continue
    m = _KEY_RE.match(line)
    if not m:
      continue
    key_indent = len(m.group("indent"))
    if m.group("dash"):
      # `- key: value` starts a new mapping inside a sequence. Give each item
      # its own path element ([0], [1], ...) so items never collide.
      dash_indent = key_indent
      while stack and (stack[-1][0] > dash_indent or
                       (stack[-1][0] == dash_indent and stack[-1][1].startswith("["))):
        stack.pop()
      parent = tuple(k for _, k in stack)
      index = items.get((parent, dash_indent), 0)
      items[(parent, dash_indent)] = index + 1
      stack.append((dash_indent, f"[{index}]"))
      key_indent += len(m.group("dash"))
    while stack and stack[-1][0] >= key_indent:
      stack.pop()
    key = _unquote_key(m.group("key"))
    value = strip_comment(m.group("value") or "")
    yield Entry(tuple(k for _, k in stack), key, value, lineno)
    if value == "":
      stack.append((key_indent, key))
    elif _BLOCK_SCALAR_RE.match(value):
      block_indent = key_indent


def duplicate_keys(text: str) -> List[str]:
  """Returns `path.key (lines a, b)` for every key repeated in one mapping."""
  seen: Dict[Tuple[Tuple[str, ...], str], List[int]] = {}
  for entry in scan(text):
    seen.setdefault((entry.path, entry.key), []).append(entry.line)
  out = []
  for (path, key), lines in seen.items():
    if len(lines) > 1:
      name = ".".join(path + (key,))
      out.append(f"{name} (lines {', '.join(str(n) for n in lines)})")
  return out


def top_level_scalars(text: str) -> Dict[str, str]:
  """Returns the unquoted top-level scalar settings (best effort)."""
  out: Dict[str, str] = {}
  for entry in scan(text):
    if not entry.path and entry.raw_value:
      out[entry.key] = plain_value(entry.raw_value)
  return out


def plain_value(raw: str) -> str:
  """Unquotes a scalar the way YAML would, for simple cases."""
  raw = raw.strip()
  if len(raw) >= 2 and raw[0] == raw[-1] == '"':
    try:
      return json.loads(raw)
    except ValueError:
      return raw[1:-1]
  if len(raw) >= 2 and raw[0] == raw[-1] == "'":
    return raw[1:-1].replace("''", "'")
  return raw


def is_quoted(raw: str) -> bool:
  raw = raw.strip()
  return len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'"


# Plain scalars that Terraform's yamldecode() (YAML 1.1 rules) reads as
# booleans, so `scan_target: on` or `model: no` would not be text.
_YAML11_TRUE = {"y", "Y", "yes", "Yes", "YES", "on", "On", "ON"}
_YAML11_FALSE = {"n", "N", "no", "No", "NO", "off", "Off", "OFF"}
_LEADING_ZERO_RE = re.compile(r"^[-+]?0[0-9]+$")


def coercion_warning(raw: str) -> Optional[str]:
  """Explains how Terraform reads a surprising unquoted value, or None."""
  if not raw or is_quoted(raw) or raw[0] in "[{&*!|>":
    return None
  if raw in _YAML11_TRUE or raw in _YAML11_FALSE:
    value = "true" if raw in _YAML11_TRUE else "false"
    return f"{raw} is read as the boolean {value}; write {value}, or quote it if you mean the text"
  if _LEADING_ZERO_RE.match(raw):
    return f"{raw} is read as the number {int(raw)}; quote it to keep the leading zero"
  return None


def scalar(value) -> str:
  """Formats a Python value as a YAML scalar every reader reads back as is.

  Strings are always double-quoted (JSON string syntax is valid YAML), so
  values such as "on" or "0123" stay strings.
  """
  if value is None:
    return "null"
  if isinstance(value, bool):
    return "true" if value else "false"
  if isinstance(value, int):
    return str(value)
  return json.dumps(str(value), ensure_ascii=False)


def hcl_string(value: str) -> str:
  """Formats a string as an HCL literal: JSON escaping plus ${ and %{ escapes."""
  return json.dumps(value, ensure_ascii=False).replace("${", "$${").replace("%{", "%%{")
