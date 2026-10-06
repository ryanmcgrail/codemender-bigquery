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

from contextlib import closing
import json
import os
import sqlite3
import sys
import time

def get_db_path():
  return os.path.expanduser("~/.codemender/state.db")

def init_db():
  db_path = get_db_path()
  os.makedirs(os.path.dirname(db_path), exist_ok=True)
  with closing(sqlite3.connect(db_path)) as conn:
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            finding_id TEXT PRIMARY KEY,
            session_id TEXT,
            title TEXT,
            file_path TEXT,
            severity TEXT,
            confidence TEXT,
            analysis TEXT,
            snippet TEXT,
            vuln_type TEXT,
            vuln_id TEXT,
            verified INTEGER,
            muted INTEGER,
            mute_reason TEXT,
            created_at TEXT,
            fingerprint TEXT,
            status TEXT,
            source_stage TEXT,
            finding_json TEXT,
            updated_at TEXT,
            start_line INTEGER,
            end_line INTEGER,
            dismiss_reason TEXT,
            confidence_level TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            operation_name TEXT,
            session_type TEXT,
            status TEXT,
            pipeline_mode TEXT,
            target TEXT,
            created_at TEXT,
            updated_at TEXT,
            project_root TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            filename TEXT,
            original_path TEXT,
            purpose TEXT,
            finding_id TEXT,
            created_at TEXT
        )
    """)
    conn.commit()

def main():
  args = sys.argv[1:]
  if not args:
    print("Dummy CM: No arguments provided.")
    sys.exit(1)

  cmd = args[0]
  cli_ver = os.environ.get("CODEMENDER_CLI_VERSION", "preview").lower()

  if cmd == "init":
    if "--verify" in args:
      print("Dummy CM: verifying init...")
    else:
      print("Dummy CM: initializing...")
      init_db()

  elif cmd == "verify" or (
      cmd == "find" and len(args) > 1 and args[1] == "verify"
  ):
    if cmd == "verify":
      positional_args = [a for a in args[1:] if not a.startswith("-")]
      finding_id = positional_args[-1] if positional_args else "fid-1"
    else:
      positional_args = [a for a in args[2:] if not a.startswith("-")]
      finding_id = positional_args[0] if positional_args else "fid-1"

    print(f"Dummy CM: verifying finding {finding_id}...")
    if cli_ver == "preview":
      print("Tokens: 10k in / 500 out / 10.5k total")

    with closing(sqlite3.connect(get_db_path())) as conn:
      cursor = conn.cursor()
      cursor.execute(
          "UPDATE findings SET verified = 1, status = 'VERIFIED', updated_at ="
          " ? WHERE finding_id = ?",
          (time.strftime("%Y-%m-%d %H:%M:%S"), finding_id),
      )
      conn.commit()

  elif cmd == "find":
    positional_args = [a for a in args[1:] if not a.startswith("-")]
    target = positional_args[-1] if positional_args else "."
    print(f"Dummy CM: finding in target {target}...")
    if cli_ver == "preview":
      print("Tokens: 30k in / 1k out / 31k total")

    with closing(sqlite3.connect(get_db_path())) as conn:
      cursor = conn.cursor()

      session_id = "sess-123"
      cursor.execute(
          "INSERT OR REPLACE INTO sessions (session_id, status, updated_at)"
          " VALUES (?, ?, ?)",
          (session_id, "RUNNING", time.strftime("%Y-%m-%d %H:%M:%S")),
      )

      findings = [
          ("fid-1", "SQL_INJECTION", "db.py", "SQL Injection in db.py"),
          ("fid-2", "XSS", "web.py", "XSS in web.py")
      ]
      for fid, vtype, fpath, title in findings:
        cursor.execute(
            """
            INSERT OR REPLACE INTO findings 
            (finding_id, session_id, vuln_type, file_path, title, status, severity, updated_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                fid,
                session_id,
                vtype,
                fpath,
                title,
                "DETECTED",
                "HIGH",
                time.strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )

      conn.commit()

  elif cmd == "fix":
    positional_args = [a for a in args[1:] if not a.startswith("-")]
    finding_id = positional_args[-1] if positional_args else "fid-1"
    print(f"Dummy CM: fixing finding {finding_id}...")
    if cli_ver == "preview":
      print("Tokens: 15k in / 800 out / 15.8k total")

    with closing(sqlite3.connect(get_db_path())) as conn:
      cursor = conn.cursor()

      cursor.execute(
          "SELECT file_path, vuln_type FROM findings WHERE finding_id = ?",
          (finding_id,),
      )
      row = cursor.fetchone()
      if row:
        file_path, vuln_type = row
        if os.path.exists(file_path):
          with open(file_path, "a") as f:
            f.write(f"\n# Fixed {vuln_type} vulnerability\n")
        else:
          if os.path.exists(os.path.basename(file_path)):
            with open(os.path.basename(file_path), "a") as f:
              f.write(f"\n# Fixed {vuln_type} vulnerability\n")

        cursor.execute(
            "UPDATE findings SET status = 'FIXED', updated_at = ? WHERE"
            " finding_id = ?",
            (time.strftime("%Y-%m-%d %H:%M:%S"), finding_id),
        )

        cursor.execute(
            """
            INSERT INTO artifacts (session_id, filename, purpose, finding_id, created_at)
            VALUES (?, ?, ?, ?, ?)
        """,
            (
                "sess-123",
                f"patch_{finding_id}.diff",
                "patch",
                finding_id,
                time.strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )

      conn.commit()

  elif cmd == "report":
    is_json = False
    is_html = False
    for i, arg in enumerate(args):
      if arg == "--format" and i + 1 < len(args) and args[i + 1] == "json":
        is_json = True
      if arg == "-f" and i + 1 < len(args) and args[i + 1] == "html":
        is_html = True

    if is_json:
      with closing(sqlite3.connect(get_db_path())) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT finding_id, vuln_type, file_path, title, status, severity,"
            " analysis FROM findings"
        )
        rows = cursor.fetchall()
        findings = []
        for r in rows:
          findings.append({
              "FindingID": r[0],
              "VulnType": r[1],
              "FilePath": r[2],
              "Title": r[3],
              "Status": r[4],
              "Severity": r[5],
              "Analysis": r[6],
          })
        print(json.dumps(findings))

    elif is_html:
      report_path = os.path.expanduser("~/.codemender/reports/report.html")
      os.makedirs(os.path.dirname(report_path), exist_ok=True)
      with open(report_path, "w") as f:
        f.write("<html><body><h1>CodeMender Consolidated Report</h1></body></html>")
      print("Dummy CM: Generated HTML report.")

  else:
    print(f"Dummy CM: Unknown command {cmd}")
    sys.exit(1)

if __name__ == "__main__":
  main()
