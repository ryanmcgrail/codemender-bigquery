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

"""Unit tests for codemender_agent.codemender.db module."""

import os
import sqlite3
import tempfile
import unittest

from codemender_agent.codemender.db import get_finding_status, is_finding_verified


class TestCodeMenderDb(unittest.TestCase):

  def test_get_finding_status_and_is_finding_verified(self):
    """Verify SQLite database querying for finding status."""
    with tempfile.TemporaryDirectory() as temp_dir:
      db_path = os.path.join(temp_dir, "state.db")
      conn = sqlite3.connect(db_path)
      cursor = conn.cursor()
      cursor.execute(
          "CREATE TABLE findings (finding_id TEXT PRIMARY KEY, status TEXT)"
      )
      cursor.execute(
          "INSERT INTO findings VALUES ('f1', 'VERIFIED'), ('f2', 'FIXED')"
      )
      conn.commit()
      conn.close()

      self.assertEqual(get_finding_status(db_path, "f1"), "VERIFIED")
      self.assertTrue(is_finding_verified(db_path, "f1"))

      self.assertEqual(get_finding_status(db_path, "f2"), "FIXED")
      self.assertFalse(is_finding_verified(db_path, "f2"))


if __name__ == "__main__":
  unittest.main()
