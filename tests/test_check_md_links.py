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
"""Tests for scripts/ci/check_md_links.py."""

import importlib.util
import os
import tempfile
import unittest

_SCRIPT = os.path.join(os.path.dirname(__file__), "..", "scripts", "ci", "check_md_links.py")
_spec = importlib.util.spec_from_file_location("check_md_links", _SCRIPT)
check_md_links = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_md_links)


class GithubSlugTest(unittest.TestCase):

  def test_punctuation_and_code_are_dropped(self):
    self.assertEqual(
        check_md_links.github_slug("Step 1.1: Build & Publish the `codemender-runner` Image (GHCR)"),
        "step-11-build--publish-the-codemender-runner-image-ghcr",
    )

  def test_link_text_is_kept(self):
    self.assertEqual(check_md_links.github_slug("See [the guide](x.md) now"), "see-the-guide-now")

  def test_duplicate_headings_are_numbered(self):
    self.assertEqual(
        check_md_links.anchors("# Setup\n## Setup\n### Setup\n"),
        {"setup", "setup-1", "setup-2"},
    )

  def test_headings_in_code_fences_are_ignored(self):
    self.assertEqual(check_md_links.anchors("```\n# Not a heading\n```\n# Real\n"), {"real"})


class IterLinksTest(unittest.TestCase):

  def targets(self, text):
    return [link.target for link in check_md_links.iter_links(text)]

  def test_finds_inline_image_reference_and_html_links(self):
    text = (
        "See [a](a.md) and ![img](img/x.png \"title\").\n"
        "[ref]: <docs/b c.md>\n"
        '<a href="c.md#top">c</a>\n'
    )
    self.assertEqual(self.targets(text), ["a.md", "img/x.png", "docs/b c.md", "c.md#top"])

  def test_skips_code(self):
    text = "`[a](inline.md)`\n```\n[b](fenced.md)\n```\n[c](real.md)\n"
    self.assertEqual(self.targets(text), ["real.md"])

  def test_offsets_point_at_the_target(self):
    line = "x [a](target.md) y"
    link = next(check_md_links.iter_links(line))
    self.assertEqual(line[link.start:link.end], "target.md")

  def test_link_text_wrapped_over_lines(self):
    text = "intro\nsee [the\nguide](guide.md#setup), done\n\n[not\n\na link](x.md)\n"
    links = list(check_md_links.iter_links(text))
    self.assertEqual([(l.target, l.line) for l in links], [("guide.md#setup", 3)])
    self.assertEqual(text[links[0].start:links[0].end], "guide.md#setup")


class CheckTreeTest(unittest.TestCase):

  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.root = self._tmp.name
    self.addCleanup(self._tmp.cleanup)

  def write(self, rel, text):
    path = os.path.join(self.root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
      f.write(text)

  def errors(self):
    return [(e.path, e.target, e.reason) for e in check_md_links.check_tree(self.root)]

  def test_valid_links_pass(self):
    self.write("README.md", "[doc](docs/a.md#usage) [dir](docs/) [self](#intro) [web](https://example.com)\n# Intro\n")
    self.write("docs/a.md", "## Usage\n[back](../README.md)\n")
    self.assertEqual(self.errors(), [])

  def test_missing_file_is_reported(self):
    self.write("README.md", "[gone](docs/missing.md)\n")
    self.assertEqual(self.errors(), [("README.md", "docs/missing.md", "target does not exist")])

  def test_missing_anchor_is_reported(self):
    self.write("README.md", "[a](a.md#nope) [self](#also-nope)\n")
    self.write("a.md", "# Yes\n")
    self.assertEqual(
        self.errors(),
        [
            ("README.md", "a.md#nope", "no heading for #nope"),
            ("README.md", "#also-nope", "no heading for #also-nope"),
        ],
    )

  def test_links_outside_the_tree_and_absolute_links_fail(self):
    self.write("README.md", "[up](../elsewhere.md) [abs](/etc/passwd)\n")
    reasons = [reason for _, _, reason in self.errors()]
    self.assertEqual(reasons, ["points outside the tree", "absolute path; use a relative link"])

  def test_main_exit_code(self):
    self.write("README.md", "[gone](missing.md)\n")
    self.assertEqual(check_md_links.main(["--root", self.root]), 1)
    self.write("README.md", "fine\n")
    self.assertEqual(check_md_links.main(["--root", self.root]), 0)


if __name__ == "__main__":
  unittest.main()
