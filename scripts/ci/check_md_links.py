#!/usr/bin/env python3
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
"""Checks that relative links in Markdown files resolve.

Every relative link or image in a Markdown file must point at a file or
directory inside the checked tree, and a `#fragment` on a link to a Markdown
file must match one of its headings (GitHub's anchor rules). External links
(any URL with a scheme, such as https: or mailto:) are not checked.

Usage:
  check_md_links.py [--root DIR] [FILE ...]

Without FILE arguments, every *.md file under DIR is checked (the files git
tracks, when DIR is a git work tree). Exits 1 if any link is broken.
"""

import argparse
import dataclasses
import os
import re
import subprocess
import sys
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Set, Tuple

_FENCE_RE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")
_INLINE_CODE_RE = re.compile(r"(`+)(?:(?!\1).)+?\1")
# [text](target "title") and ![alt](target). The text may wrap over several
# lines (but not a blank line) and contain one level of nested brackets, as in
# [![badge](img)](link).
_INLINE_LINK_RE = re.compile(
    r"!?\[(?:[^\[\]\n]|\n(?![ \t]*\n)|\[[^\[\]]*\])*\]"
    r"\(\s*(?P<target><[^<>\n]*>|[^\s()]+)(?:\s+(?:\"[^\"]*\"|'[^']*'))?\s*\)"
)
_REF_DEF_RE = re.compile(r"^[ \t]{0,3}\[[^\]\n]+\]:[ \t]*(?P<target><[^<>\n]*>|\S+)", re.MULTILINE)
_HTML_ATTR_RE = re.compile(r"""\b(?:href|src)\s*=\s*(?P<q>["'])(?P<target>[^"'\n]*)(?P=q)""", re.IGNORECASE)
_HTML_ANCHOR_RE = re.compile(r"""<a\s[^>]*\b(?:name|id)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(?P<text>.*?)\s*#*\s*$")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_MD_LINK_TEXT_RE = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")

_SKIP_DIRS = {".git", ".terraform", "node_modules", "__pycache__", ".venv", "venv"}


@dataclasses.dataclass(frozen=True)
class Link:
  """A link target found in a Markdown file."""

  line: int  # 1-based line number of the target
  target: str  # the target as written, without angle brackets
  start: int  # offset of the target in the document
  end: int


@dataclasses.dataclass(frozen=True)
class LinkError:
  path: str  # file containing the link, relative to the root
  line: int
  target: str
  reason: str

  def __str__(self) -> str:
    return f"{self.path}:{self.line}: {self.target}: {self.reason}"


def _mask(text: str, pattern: re.Pattern) -> str:
  """Replaces every match of pattern with spaces, keeping offsets."""
  return pattern.sub(lambda m: " " * len(m.group(0)), text)


def iter_lines_outside_code(text: str) -> Iterator[Tuple[int, str, str]]:
  """Yields (line_number, masked_line, line) for lines outside code fences.

  In masked_line, inline code spans are blanked out (same length), so that
  offsets into it match the original line.
  """
  fence: Optional[str] = None
  for number, line in enumerate(text.splitlines(), start=1):
    match = _FENCE_RE.match(line)
    if fence is None:
      if match:
        fence = match.group(1)
        continue
      yield number, _mask(line, _INLINE_CODE_RE), line
    elif match and match.group(1)[0] == fence[0] and len(match.group(1)) >= len(fence):
      fence = None


def mask_code(text: str) -> str:
  """Returns text with fenced code blocks and inline code blanked out.

  The result has the same length and line breaks, so offsets and line numbers
  still match the original.
  """
  out = []
  fence: Optional[str] = None
  for line in text.splitlines(keepends=True):
    body = line.rstrip("\r\n")
    ending = line[len(body):]
    match = _FENCE_RE.match(body)
    if fence is None and not match:
      out.append(_mask(body, _INLINE_CODE_RE) + ending)
      continue
    if fence is None:
      fence = match.group(1)
    elif match and match.group(1)[0] == fence[0] and len(match.group(1)) >= len(fence):
      fence = None
    out.append(" " * len(body) + ending)
  return "".join(out)


def iter_links(text: str) -> Iterator[Link]:
  """Yields every link and image target outside code, in document order."""
  masked = mask_code(text)
  found = []
  for regex in (_INLINE_LINK_RE, _REF_DEF_RE, _HTML_ATTR_RE):
    for match in regex.finditer(masked):
      start, end = match.start("target"), match.end("target")
      raw = text[start:end]
      if raw.startswith("<") and raw.endswith(">"):
        raw, start, end = raw[1:-1], start + 1, end - 1
      found.append(Link(line=text.count("\n", 0, start) + 1, target=raw, start=start, end=end))
  return iter(sorted(found, key=lambda link: link.start))


def is_external(target: str) -> bool:
  return bool(_SCHEME_RE.match(target)) or target.startswith("//")


def github_slug(heading: str) -> str:
  """Returns the anchor GitHub generates for a heading's text."""
  text = _MD_LINK_TEXT_RE.sub(r"\1", heading)
  text = re.sub(r"<[^>]+>", "", text)
  text = text.replace("`", "").replace("*", "")
  text = text.strip().lower()
  text = re.sub(r"[^\w\- ]", "", text)
  return text.replace(" ", "-")


def anchors(text: str) -> Set[str]:
  """Returns the anchors a Markdown document defines."""
  result: Set[str] = set()
  counts: Dict[str, int] = {}
  for _, masked, line in iter_lines_outside_code(text):
    for match in _HTML_ANCHOR_RE.finditer(masked):
      result.add(match.group(1))
    heading = _HEADING_RE.match(line)
    if not heading:
      continue
    slug = github_slug(heading.group("text"))
    if slug in counts:
      counts[slug] += 1
      result.add(f"{slug}-{counts[slug]}")
    else:
      counts[slug] = 0
      result.add(slug)
  return result


def split_target(target: str) -> Tuple[str, str]:
  """Splits a link target into (path, fragment)."""
  path, _, fragment = target.partition("#")
  path = path.split("?", 1)[0]
  return path, fragment


def check_file(
    root: str,
    rel_path: str,
    read: Callable[[str], str],
    anchor_cache: Dict[str, Set[str]],
) -> List[LinkError]:
  """Checks the links in one Markdown file (rel_path is relative to root)."""
  errors: List[LinkError] = []
  root = os.path.realpath(root)
  text = read(os.path.join(root, rel_path))
  base_dir = os.path.dirname(os.path.join(root, rel_path))
  for link in iter_links(text):
    target = link.target.strip()
    if not target or is_external(target):
      continue
    path_part, fragment = split_target(target)
    if path_part:
      if path_part.startswith("/"):
        errors.append(LinkError(rel_path, link.line, target, "absolute path; use a relative link"))
        continue
      resolved = os.path.normpath(os.path.join(base_dir, path_part))
      if os.path.commonpath([resolved, root]) != root:
        errors.append(LinkError(rel_path, link.line, target, "points outside the tree"))
        continue
      if not os.path.exists(resolved):
        errors.append(LinkError(rel_path, link.line, target, "target does not exist"))
        continue
    else:
      resolved = os.path.join(root, rel_path)
    if fragment and resolved.endswith(".md") and os.path.isfile(resolved):
      if resolved not in anchor_cache:
        anchor_cache[resolved] = anchors(read(resolved))
      if fragment not in anchor_cache[resolved]:
        errors.append(LinkError(rel_path, link.line, target, f"no heading for #{fragment}"))
  return errors


def _read(path: str) -> str:
  with open(path, encoding="utf-8") as f:
    return f.read()


def find_markdown_files(root: str) -> List[str]:
  """Lists *.md files under root, relative to it (git-tracked if possible)."""
  try:
    out = subprocess.run(
        ["git", "-C", root, "ls-files", "-z", "--", "*.md"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    inside = subprocess.run(
        ["git", "-C", root, "rev-parse", "--show-prefix"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if inside == "":
      return sorted(p for p in out.split("\0") if p)
  except (OSError, subprocess.CalledProcessError):
    pass
  found = []
  for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
    for name in filenames:
      if name.endswith(".md"):
        found.append(os.path.relpath(os.path.join(dirpath, name), root))
  return sorted(found)


def check_tree(root: str, files: Optional[Sequence[str]] = None) -> List[LinkError]:
  """Checks every Markdown file under root (or only the given files)."""
  files = list(files) if files else find_markdown_files(root)
  cache: Dict[str, Set[str]] = {}
  errors: List[LinkError] = []
  for rel in files:
    errors.extend(check_file(root, rel, _read, cache))
  return errors


def main(argv: Optional[Sequence[str]] = None) -> int:
  parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
  parser.add_argument("--root", default=".", help="tree to check (default: current directory)")
  parser.add_argument("files", nargs="*", help="Markdown files relative to --root (default: all)")
  args = parser.parse_args(argv)
  files = args.files or find_markdown_files(args.root)
  errors = check_tree(args.root, files)
  for error in errors:
    print(error, file=sys.stderr)
  print(f"Checked {len(files)} Markdown file(s): {len(errors)} broken link(s).")
  return 1 if errors else 0


if __name__ == "__main__":
  sys.exit(main())
