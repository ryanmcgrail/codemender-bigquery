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

"""Unit tests for codemender_agent.utils module."""

import subprocess
import unittest
from unittest.mock import MagicMock, patch

from codemender_agent.utils import (
    extract_json_from_output,
    free_port,
    retry_on_exception,
    run_command,
)


class TestUtils(unittest.TestCase):

  def test_extract_json_from_output_dict(self):
    """Test extracting JSON dict with trailing logs."""
    raw = """
{
  "version": "2.1.0",
  "runs": [{"tool": {"driver": {"name": "CodeMender"}}}]
}
2026-08-28T16:35:50Z [INFO] 📄 Session log: /github/home/.codemender/logs/20260828T163550Z_pending.log
"""
    data = extract_json_from_output(raw)
    self.assertIsInstance(data, dict)
    self.assertEqual(data["version"], "2.1.0")

  def test_extract_json_from_output_list(self):
    """Test extracting JSON list with leading text and trailing logs."""
    raw = """
Some banner info
[
  {"FindingID": "fid-1", "Title": "SQLi"},
  {"FindingID": "fid-2", "Title": "XSS"}
]
2026-08-28T16:35:49Z [INFO] 📄 Session log: /github/home/log.log
"""
    data = extract_json_from_output(raw)
    self.assertIsInstance(data, list)
    self.assertEqual(len(data), 2)
    self.assertEqual(data[0]["FindingID"], "fid-1")

  def test_extract_json_from_output_invalid(self):
    """Test extracting JSON from invalid strings returns None."""
    self.assertIsNone(extract_json_from_output(""))
    self.assertIsNone(extract_json_from_output(None))
    self.assertIsNone(extract_json_from_output("No JSON content here"))
    self.assertIsNone(extract_json_from_output("{incomplete json"))

  def test_retry_on_exception_success(self):
    """Test decorated function returns immediately on success."""
    mock_func = MagicMock(return_value="success")
    decorated = retry_on_exception(max_tries=3)(mock_func)
    self.assertEqual(decorated(), "success")
    self.assertEqual(mock_func.call_count, 1)

  def test_retry_on_exception_retry_then_succeed(self):
    """Test decorator retries transient error and succeeds."""
    mock_func = MagicMock(
        side_effect=[subprocess.CalledProcessError(1, "cmd"), "success"]
    )
    decorated = retry_on_exception(max_tries=3, initial_delay=0.01)(mock_func)
    self.assertEqual(decorated(), "success")
    self.assertEqual(mock_func.call_count, 2)

  @patch("subprocess.run")
  def test_free_port(self, mock_run):
    """Verify free_port invokes fuser correctly."""
    free_port(3000)
    mock_run.assert_called_once_with(
        ["fuser", "-k", "3000/tcp"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


  @patch("subprocess.Popen")
  def test_run_command_accumulates_multiple_retry_tokens(self, mock_popen):
    """Verify run_command sums tokens from multiple retries/turns in stdout."""
    stdout_lines = [
        "Attempt 1 failed. Tokens: 10k in / 500 out / 10.5k total\n",
        "Attempt 2 retrying. Tokens: 5k in / 200 out / 5.2k total\n",
        "Attempt 3 succeeded. Tokens: 2.5k in / 100 out / 2.6k total\n",
    ]
    mock_process = MagicMock()
    mock_stdout = MagicMock()
    mock_stdout.__iter__.return_value = stdout_lines
    mock_process.stdout = mock_stdout
    mock_process.wait.return_value = 0
    mock_popen.return_value = mock_process

    with patch.dict("os.environ", {"CODEMENDER_CLI_VERSION": "preview"}):
      res = run_command(["cm", "find"])
      # Expected sum: (10000 + 5000 + 2500) = 17500 in, (500 + 200 + 100) = 800 out, (10500 + 5200 + 2600) = 18300 total
      self.assertEqual(
          res.token_usage,
          {"in_tokens": 17500, "out_tokens": 800, "total_tokens": 18300},
      )


if __name__ == "__main__":
  unittest.main()
