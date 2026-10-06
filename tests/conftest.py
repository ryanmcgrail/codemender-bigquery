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

"""Shared pytest configuration for the unit test suite."""

import os

import pytest

# Environment variables injected by CI runners (for example GitHub Actions)
# that the orchestrator reads to auto-detect its runtime. When the suite runs
# inside such a runner they leak into every test, switching storage to the
# Actions transit adapter and overriding mocked commit SHAs and PR metadata.
_CI_ENV_PREFIXES = ("GITHUB_", "RUNNER_")
_CI_ENV_NAMES = ("CI",)


@pytest.fixture(autouse=True)
def _isolate_from_ci_runner_env(monkeypatch):
  """Removes CI runner variables so tests behave the same locally and in CI.

  Tests that need a specific value still set it themselves (for example with
  `mock.patch.dict(os.environ, ...)`), which runs after this fixture.
  """
  for name in list(os.environ):
    if name.startswith(_CI_ENV_PREFIXES) or name in _CI_ENV_NAMES:
      monkeypatch.delenv(name, raising=False)
