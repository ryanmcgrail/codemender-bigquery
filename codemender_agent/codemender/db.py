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

"""CodeMender SQLite state database queries for CodeMender Agent."""

from contextlib import closing
import logging
import os
import sqlite3
from typing import Optional

logger = logging.getLogger("codemender-orchestrator")


def get_finding_status(db_path: str, finding_id: str) -> Optional[str]:
  """Retrieves the status of a finding directly from the state SQLite database."""
  if not os.path.exists(db_path):
    logger.warning("State database does not exist at: %s", db_path)
    return None
  try:
    with closing(sqlite3.connect(db_path)) as conn:
      cursor = conn.cursor()
      cursor.execute(
          "SELECT status FROM findings WHERE finding_id = ?", (finding_id,)
      )
      row = cursor.fetchone()
      if row:
        return row[0]
  except sqlite3.Error as e:
    logger.error("Failed to query state database: %s", e)
  return None


def is_finding_verified(db_path: str, finding_id: str) -> bool:
  """Check if the finding's status is 'VERIFIED' in the state SQLite database."""
  return get_finding_status(db_path, finding_id) == "VERIFIED"



