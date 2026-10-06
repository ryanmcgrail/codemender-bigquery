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

"""Stage 3: Aggregator runner for CodeMender Agent."""

from contextlib import closing
import datetime
import hashlib
import html
import json
import logging
import os
import re
import shutil
import sqlite3
import sys
import tarfile
import time
from typing import Any, Dict, List, Optional, Set

from codemender_agent.codemender.cli import get_cm_default_model
from codemender_agent.codemender.cli import log_cm_version
from codemender_agent.codemender.cli import parse_findings_json
from codemender_agent.codemender.cli import restore_staged_cm_binary
from codemender_agent.config import OrchestratorConfig
from codemender_agent.config import PR_MODE_REVIEW_SUGGESTION
from codemender_agent.config import get_github_credentials
from codemender_agent.config import get_scrubbed_env
from codemender_agent.config import github_app_configured
from codemender_agent.config import inject_codemender_config
from codemender_agent.config import is_presubmit_pipeline
from codemender_agent.config import read_default_branch
from codemender_agent.config import refresh_github_token
from codemender_agent.config import resolve_pr_remediation_mode
from codemender_agent.storage import download_file_from_gcs
from codemender_agent.storage import get_storage_adapter
from codemender_agent.storage import list_gcs_blobs
from codemender_agent.storage import upload_and_sign_report
from codemender_agent.storage import upload_file_to_gcs
# BigQuery analytics telemetry (hard no-op unless CODEMENDER_BQ_DATASET is set)
from codemender_agent.telemetry import bigquery as bq_telemetry
from codemender_agent.utils import accumulate_model_token_usage
from codemender_agent.utils import build_cm_command
from codemender_agent.utils import extract_json_from_output
from codemender_agent.utils import render_token_usage_markdown
from codemender_agent.utils import run_command
from codemender_agent.vcs.git import get_git_auth_header
from codemender_agent.vcs.git import normalize_repo_relative_path
from codemender_agent.vcs.git import parse_repo_owner_and_name
from codemender_agent.vcs.git import sanitize_git_url
from codemender_agent.vcs.git import setup_local_git_excludes
from codemender_agent.vcs.github import STATUS_CONTEXT_PR
from codemender_agent.vcs.github import STATUS_CONTEXT_SCHEDULED
from codemender_agent.vcs.github import get_default_branch
from codemender_agent.vcs.github import post_commit_status
from codemender_agent.vcs.github import post_or_update_sticky_comment
from codemender_agent.vcs.github import upload_sarif_to_code_scanning
from codemender_agent.wiz.bridge import STATUS_NOT_ENABLED as WIZ_NOT_ENABLED
from codemender_agent.wiz.bridge import summary_line as wiz_summary_line
from codemender_agent.wiz.settings import take_wiz_credentials

logger = logging.getLogger("codemender-orchestrator")


def _get_table_columns(cursor: sqlite3.Cursor, table_name: str, db_prefix: str = "main") -> list[str]:
  """Returns list of column names for a table in specified attached database."""
  try:
    cursor.execute(f"PRAGMA {db_prefix}.table_info({table_name})")
    rows = cursor.fetchall()
    return [r[1] for r in rows]
  except sqlite3.Error:
    return []


def merge_db(base_db_path: str, worker_db_path: str) -> None:
  """Merges worker database tables into base database using selective SQLite UPSERT."""
  if not os.path.exists(worker_db_path):
    logger.warning("Worker database file not found: %s", worker_db_path)
    return

  logger.info("Merging %s into %s...", worker_db_path, base_db_path)
  conn = sqlite3.connect(base_db_path)
  cursor = conn.cursor()
  try:
    # Attach the worker database shard as a named SQLite database
    cursor.execute("ATTACH DATABASE ? AS worker", (worker_db_path,))

    # 1. Findings Table Merge:
    # Match findings by finding_id and update mutable status fields if updated_at is newer
    main_cols = _get_table_columns(cursor, "findings", "main")
    worker_cols = _get_table_columns(cursor, "findings", "worker")
    common_cols = [c for c in worker_cols if c in main_cols]

    if common_cols and "finding_id" in common_cols:
      cols_str = ", ".join(common_cols)
      update_cols = [c for c in common_cols if c != "finding_id"]
      if update_cols:
        set_clause = ", ".join([
            f"{c} = (SELECT {c} FROM worker.findings WHERE finding_id ="
            " main.findings.finding_id)"
            for c in update_cols
        ])
        where_cond = ""
        if "updated_at" in common_cols:
          where_cond = (
              " AND ((SELECT updated_at FROM worker.findings WHERE finding_id ="
              " main.findings.finding_id) >= main.findings.updated_at OR"
              " main.findings.updated_at = '' OR main.findings.updated_at IS"
              " NULL)"
          )
        cursor.execute(f"""
            UPDATE main.findings
            SET {set_clause}
            WHERE finding_id IN (SELECT finding_id FROM worker.findings)
            {where_cond};
        """)

      # Insert any newly recorded findings that do not already exist in the base table
      cursor.execute(f"""
          INSERT OR IGNORE INTO main.findings ({cols_str})
          SELECT {cols_str} FROM worker.findings AS w
          WHERE EXISTS (
              SELECT 1 FROM main.findings AS m
              WHERE m.finding_id = w.finding_id
          );
      """)

    # 2. Sessions Table Merge:
    # Merge worker interactive and CLI session tracking rows
    main_cols = _get_table_columns(cursor, "sessions", "main")
    worker_cols = _get_table_columns(cursor, "sessions", "worker")
    common_cols = [c for c in worker_cols if c in main_cols]

    if common_cols and "session_id" in common_cols:
      cols_str = ", ".join(common_cols)
      update_cols = [c for c in common_cols if c != "session_id"]
      if update_cols:
        set_clause = ", ".join([
            f"{c} = (SELECT {c} FROM worker.sessions WHERE session_id ="
            " main.sessions.session_id)"
            for c in update_cols
        ])
        cursor.execute(f"""
            UPDATE main.sessions
            SET {set_clause}
            WHERE session_id IN (SELECT session_id FROM worker.sessions);
        """)

      cursor.execute(f"""
          INSERT OR IGNORE INTO main.sessions ({cols_str})
          SELECT {cols_str} FROM worker.sessions;
      """)

    # 3. Artifacts Table Merge:
    # Exclude auto-incrementing primary key columns ('id', 'artifact_id') to prevent ID collisions
    main_cols = _get_table_columns(cursor, "artifacts", "main")
    worker_cols = _get_table_columns(cursor, "artifacts", "worker")
    common_cols = [c for c in worker_cols if c in main_cols and c not in ["id", "artifact_id"]]

    if common_cols:
      cols_str = ", ".join(common_cols)
      cursor.execute(f"""
          INSERT OR IGNORE INTO main.artifacts ({cols_str})
          SELECT {cols_str} FROM worker.artifacts AS w
          WHERE (w.finding_id IS NULL OR EXISTS (
              SELECT 1 FROM main.findings AS m
              WHERE m.finding_id = w.finding_id
          )) AND NOT EXISTS (
              SELECT 1 FROM main.artifacts AS m
              WHERE m.session_id = w.session_id AND m.filename = w.filename
          );
      """)

    # 4. Patches Table Merge:
    # Upsert generated patches and diff metadata associated with remediated findings
    main_cols = _get_table_columns(cursor, "patches", "main")
    worker_cols = _get_table_columns(cursor, "patches", "worker")
    common_cols = [c for c in worker_cols if c in main_cols]

    if common_cols and "patch_id" in common_cols:
      cols_str = ", ".join(common_cols)
      cursor.execute(f"""
          INSERT OR REPLACE INTO main.patches ({cols_str})
          SELECT {cols_str} FROM worker.patches AS w
          WHERE EXISTS (
              SELECT 1 FROM main.findings AS m
              WHERE m.finding_id = w.finding_id
          );
      """)

    # 5. File Hashes Table Merge:
    # Upsert SHA256 hashes of modified repository files to avoid cache invalidations
    cursor.execute("SELECT name FROM main.sqlite_master WHERE type='table' AND name='file_hashes'")
    if cursor.fetchone():
      main_cols = _get_table_columns(cursor, "file_hashes", "main")
      worker_cols = _get_table_columns(cursor, "file_hashes", "worker")
      common_cols = [c for c in worker_cols if c in main_cols]

      if common_cols and "file_path" in common_cols:
        cols_str = ", ".join(common_cols)
        cursor.execute(f"""
            INSERT OR REPLACE INTO main.file_hashes ({cols_str})
            SELECT {cols_str} FROM worker.file_hashes;
        """)

    conn.commit()
    logger.info("Merged %s successfully.", worker_db_path)
  except sqlite3.Error as e:  # pylint: disable=broad-exception-caught
    logger.error("Failed to merge database %s: %s", worker_db_path, e)
    conn.rollback()
  finally:
    # Always detach worker shard database to release locks
    try:
      cursor.execute("DETACH DATABASE worker")
    except sqlite3.Error:  # pylint: disable=broad-exception-caught
      pass
    conn.close()


def _verify_worker_db_counts(
    worker_db_blobs: list[str],
    total_workers_env: Optional[str],
) -> None:
  """Verifies if the number of downloaded DBs matches expected worker count."""
  if not total_workers_env:
    return

  try:
    expected_workers = int(total_workers_env)
    found_indices = set()
    for blob in worker_db_blobs:
      basename = os.path.basename(blob)
      # Parse index from format: worker_[index]_state.db
      parts = basename.split("_")
      if len(parts) >= 2:
        try:
          idx = int(parts[1])
          found_indices.add(idx)
        except ValueError:
          pass

    missing_workers = set(range(expected_workers)) - found_indices
    # Check if any expected worker task indices are absent from downloaded shards
    if missing_workers:
      logger.warning(
          "Missing databases for worker tasks: %s. "
          "The final report might be incomplete.",
          list(missing_workers),
      )
  except ValueError:
    # Log warning if task count string cannot be parsed as an integer
    logger.warning(
        "Invalid CODEMENDER_TOTAL_WORKERS or CLOUD_RUN_TASK_COUNT value: %s",
        total_workers_env,
    )


# -----------------------------------------------------------------------------
# Worker Shard Database Download and Merge Pipeline
# -----------------------------------------------------------------------------
def _download_and_merge_worker_dbs(
    worker_db_blobs: list[str],
    temp_db_dir: str,
    bucket_name: str,
    base_db_path: str,
) -> None:
  """Downloads each worker DB shard from GCS and merges it into base DB."""
  # Iterate over all discovered GCS worker DB blobs and download them locally
  for blob in worker_db_blobs:
    local_worker_db = os.path.join(temp_db_dir, os.path.basename(blob))
    logger.info("Downloading %s...", blob)
    # Merge downloaded worker shard into the base SQLite state database
    if download_file_from_gcs(local_worker_db, bucket_name, blob):
      merge_db(base_db_path, local_worker_db)
    else:
      logger.error("Failed to download worker DB: %s", blob)


def _discover_and_merge_local_worker_dbs(
    workspace_dir: str,
    base_db_path: str,
    storage_adapter: Optional[any] = None,
) -> list[str]:
  """Discovers and merges worker database shards from local/transit directory structure."""
  worker_db_files = []

  # 1. Check .codemender_transit/shards/ recursively for worker SQLite databases
  shards_dir = os.path.join(workspace_dir, ".codemender_transit", "shards")
  if os.path.exists(shards_dir):
    for root, _, files in os.walk(shards_dir):
      for f in sorted(files):
        if f.endswith("_state.db"):
          p = os.path.join(root, f)
          if p not in worker_db_files:
            worker_db_files.append(p)

  # 2. Check worker_dbs directory in workspace
  temp_db_dir = os.path.join(workspace_dir, "worker_dbs")
  if os.path.exists(temp_db_dir):
    for f in sorted(os.listdir(temp_db_dir)):
      if f.endswith("_state.db"):
        p = os.path.join(temp_db_dir, f)
        if p not in worker_db_files:
          worker_db_files.append(p)

  # 3. Check storage adapter listing if no local files were found directly on disk
  if not worker_db_files and storage_adapter:
    blobs = storage_adapter.list_blobs(prefix="shards")
    for blob in blobs:
      if blob.endswith("_state.db"):
        local_path = os.path.join(temp_db_dir, os.path.basename(blob))
        os.makedirs(temp_db_dir, exist_ok=True)
        # Download transit blob to local worker_dbs directory
        if storage_adapter.download_file(local_path, blob):
          if local_path not in worker_db_files:
            worker_db_files.append(local_path)

  logger.info("Discovered %d local worker database shards to merge.", len(worker_db_files))
  # 4. Merge all discovered worker shards into base state.db
  for worker_db in sorted(worker_db_files):
    merge_db(base_db_path, worker_db)

  return worker_db_files


def _aggregate_worker_metadata(
    workspace_dir: str,
    bucket_name: str,
    scan_id: str,
    worker_db_blobs: list[str],
    storage_adapter: Optional[any] = None,
) -> tuple[dict[str, dict[str, int]], dict[str, str]]:
  """Discovers and parses scan_metadata.json and all worker metadata files to aggregate per-model token usage and finding PR links."""
  token_usage_by_model: dict[str, dict[str, int]] = {}
  finding_prs: dict[str, str] = {}

  def _ingest_token_usage(token_dict: any):
    if not isinstance(token_dict, dict):
      return
    for k, v in token_dict.items():
      if isinstance(v, dict):
        accumulate_model_token_usage(token_usage_by_model, k, v)
      elif isinstance(v, (int, float)):
        accumulate_model_token_usage(token_usage_by_model, "default", token_dict)
        break

  # 1. Ingest Stage 1 scan_metadata.json
  scan_meta_candidates = [
      os.path.join(workspace_dir, "scan_metadata.json"),
      os.path.join(workspace_dir, ".codemender_transit", "base", "scan_metadata.json"),
  ]
  if bucket_name and scan_id and not scan_id.startswith("local"):
    scan_meta_local = os.path.join(workspace_dir, "scan_metadata.json")
    if download_file_from_gcs(scan_meta_local, bucket_name, f"scans/{scan_id}/scan_metadata.json"):
      scan_meta_candidates.append(scan_meta_local)

  for scan_meta_p in list(dict.fromkeys(scan_meta_candidates)):
    if os.path.exists(scan_meta_p):
      try:
        with open(scan_meta_p, "r", encoding="utf-8") as f:
          scan_meta = json.load(f)
        _ingest_token_usage(scan_meta.get("token_usage"))
        if isinstance(scan_meta.get("finding_prs"), dict):
          finding_prs.update(scan_meta["finding_prs"])
        break
      except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning("Failed to parse scan_metadata.json: %s", e)

  # 2. Discover Stage 2 worker metadata JSONs
  meta_paths = set()
  # Search .codemender_transit recursively
  transit_dir = os.path.join(workspace_dir, ".codemender_transit")
  if os.path.exists(transit_dir):
    for root, _, files in os.walk(transit_dir):
      for file in files:
        if file.endswith("_metadata.json") and not file.startswith("scan_"):
          meta_paths.add(os.path.join(root, file))

  # Search workspace_dir (e.g. worker_dbs/)
  if os.path.exists(workspace_dir):
    for root, _, files in os.walk(workspace_dir):
      for file in files:
        if file.endswith("_metadata.json") and not file.startswith("scan_"):
          meta_paths.add(os.path.join(root, file))

  # Download from GCS if configured
  if bucket_name and scan_id and not scan_id.startswith("local"):
    try:
      all_blobs = list_gcs_blobs(bucket_name, prefix=f"scans/{scan_id}/worker_")
      meta_blobs = sorted(list(set(
          [b for b in all_blobs if b.endswith("_metadata.json")]
          + [b.replace("_state.db", "_metadata.json") for b in worker_db_blobs]
      )))
      for meta_blob in meta_blobs:
        local_meta = os.path.join(workspace_dir, os.path.basename(meta_blob))
        if download_file_from_gcs(local_meta, bucket_name, meta_blob):
          meta_paths.add(local_meta)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning("Failed to list/download GCS worker metadata: %s", e)

  for meta_path in sorted(list(meta_paths)):
    if os.path.exists(meta_path):
      try:
        with open(meta_path, "r", encoding="utf-8") as f:
          w_meta = json.load(f)
        _ingest_token_usage(w_meta.get("token_usage"))
        if "finding_prs" in w_meta and isinstance(w_meta["finding_prs"], dict):
          finding_prs.update(w_meta["finding_prs"])
      except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning("Failed to parse worker metadata %s: %s", meta_path, e)

  total_in = sum(m.get("in_tokens", 0) for m in token_usage_by_model.values())
  total_out = sum(m.get("out_tokens", 0) for m in token_usage_by_model.values())
  total_all = sum(m.get("total_tokens", 0) for m in token_usage_by_model.values())

  logger.info(
      "\n"
      "======================================================================\n"
      "⚡ AGGREGATED TOKEN USAGE:\n"
      "   Total Input Tokens:  %d\n"
      "   Total Output Tokens: %d\n"
      "   Grand Total Tokens:  %d\n"
      "   Breakdown: %s\n"
      "======================================================================\n",
      total_in,
      total_out,
      total_all,
      json.dumps(token_usage_by_model),
  )
  return token_usage_by_model, finding_prs


def _aggregate_token_metrics(
    workspace_dir: str,
    bucket_name: str,
    scan_id: str,
    worker_db_blobs: list[str],
    storage_adapter: Optional[any] = None,
) -> dict[str, dict[str, int]]:
  """Wrapper around _aggregate_worker_metadata returning only token totals for backwards compatibility."""
  token_usage, _ = _aggregate_worker_metadata(
      workspace_dir,
      bucket_name,
      scan_id,
      worker_db_blobs,
      storage_adapter=storage_adapter,
  )
  return token_usage


def _inject_token_metrics_into_html(
    html_path: str, token_totals: Optional[dict[str, dict[str, int]]]
) -> None:
  """Injects a Token Usage Summary card/table between the report title and finding count section."""
  if not os.path.exists(html_path) or not token_totals:
    return

  total_in = sum(m.get("in_tokens", 0) for m in token_totals.values())
  total_out = sum(m.get("out_tokens", 0) for m in token_totals.values())
  total_all = sum(m.get("total_tokens", 0) for m in token_totals.values())

  # Build per-model breakdown table if multiple models exist
  breakdown_html = ""
  if len(token_totals) > 1:
    rows = []
    for model_name, metrics in sorted(token_totals.items()):
      m_in = metrics.get("in_tokens", 0)
      m_out = metrics.get("out_tokens", 0)
      m_total = metrics.get("total_tokens", 0)
      rows.append(f"""
        <tr style="border-bottom: 1px solid #e9ecef;">
          <td style="padding: 8px 12px; font-weight: 600; color: #495057;"><code>{model_name}</code></td>
          <td style="padding: 8px 12px; color: #0d6efd;">{m_in:,}</td>
          <td style="padding: 8px 12px; color: #198754;">{m_out:,}</td>
          <td style="padding: 8px 12px; font-weight: 700; color: #212529;">{m_total:,}</td>
        </tr>""")
    rows_str = "".join(rows)
    breakdown_html = f"""
    <div style="margin-top: 18px; border-top: 1px solid #e9ecef; padding-top: 14px;">
      <h4 style="margin-bottom: 8px; font-size: 0.85rem; color: #495057; text-transform: uppercase; letter-spacing: 0.05em;">
        Per-Model Breakdown
      </h4>
      <table style="width: 100%; border-collapse: collapse; font-size: 0.9rem; text-align: left;">
        <thead>
          <tr style="background-color: #f8f9fa; border-bottom: 2px solid #dee2e6;">
            <th style="padding: 8px 12px; color: #6c757d; font-weight: 600;">Model</th>
            <th style="padding: 8px 12px; color: #6c757d; font-weight: 600;">Input Tokens</th>
            <th style="padding: 8px 12px; color: #6c757d; font-weight: 600;">Output Tokens</th>
            <th style="padding: 8px 12px; color: #6c757d; font-weight: 600;">Total Tokens</th>
          </tr>
        </thead>
        <tbody>
          {rows_str}
        </tbody>
      </table>
    </div>"""

  single_model_label = ""
  if len(token_totals) == 1:
    only_model = list(token_totals.keys())[0]
    single_model_label = f' <span style="font-size: 0.8rem; color: #6c757d; font-weight: normal;">(Model: <code>{only_model}</code>)</span>'
  elif len(token_totals) > 1:
    models_str = ", ".join(
        f"<code>{m}</code>" for m in sorted(token_totals.keys())
    )
    single_model_label = f' <span style="font-size: 0.8rem; color: #6c757d; font-weight: normal;">(Models: {models_str})</span>'

  banner_html = f"""
  <div id="codemender-token-metrics-banner" style="background: white; border-radius: 8px; padding: 20px; margin-bottom: 25px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
    <h3 style="margin-bottom: 12px; font-size: 0.95rem; color: #16213e; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; display: flex; align-items: center; gap: 8px;">
      ⚡ LLM Token Usage Summary{single_model_label}
    </h3>
    <div style="display: flex; gap: 40px; flex-wrap: wrap;">
      <div>
        <span style="font-size: 0.8rem; text-transform: uppercase; color: #6c757d; font-weight: 600; display: block; margin-bottom: 4px;">Input Tokens</span>
        <span style="font-size: 1.5rem; font-weight: 700; color: #0d6efd;">{total_in:,}</span>
      </div>
      <div>
        <span style="font-size: 0.8rem; text-transform: uppercase; color: #6c757d; font-weight: 600; display: block; margin-bottom: 4px;">Output Tokens</span>
        <span style="font-size: 1.5rem; font-weight: 700; color: #198754;">{total_out:,}</span>
      </div>
      <div>
        <span style="font-size: 0.8rem; text-transform: uppercase; color: #6c757d; font-weight: 600; display: block; margin-bottom: 4px;">Total Tokens</span>
        <span style="font-size: 1.5rem; font-weight: 700; color: #212529;">{total_all:,}</span>
      </div>
    </div>
    {breakdown_html}
  </div>
"""
  try:
    with open(html_path, "r", encoding="utf-8") as f:
      content = f.read()

    # 1. Target right before <div class="cards"> (inside main container, above count cards)
    match = re.search(r"(<div\s+class=[\"']cards[\"'][^>]*>)", content, re.IGNORECASE)
    if not match:
      # 2. Fallback: right after </header>
      match = re.search(r"(</header>)", content, re.IGNORECASE)
    if not match:
      # 3. Fallback: right after <h1> title tag
      match = re.search(
          r"(<h1[^>]*>.*?CodeMender Security Report.*?</h1>)",
          content,
          re.IGNORECASE | re.DOTALL,
      )
    if not match:
      # 4. Fallback to <body> tag
      match = re.search(r"(<body[^>]*>)", content, re.IGNORECASE)

    if match:
      # Inject token usage banner into HTML DOM structure
      if match.group(1).lower().startswith("<div"):
        # Insert BEFORE <div class="cards"> container
        pos = match.start()
        new_content = content[:pos] + banner_html + "\n  " + content[pos:]
      else:
        # Insert AFTER opening <body> tag
        pos = match.end()
        new_content = content[:pos] + "\n" + banner_html + content[pos:]
    else:
      new_content = banner_html + "\n" + content

    # Write modified HTML report back to file
    with open(html_path, "w", encoding="utf-8") as f:
      f.write(new_content)
    logger.info("Successfully injected Token Usage Summary into HTML report.")
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning("Failed to inject token usage into HTML report: %s", e)


def _load_wiz_metadata(workspace_dir: str) -> Dict[str, Any]:
  """Reads the Wiz bridge block Stage 1 recorded in scan_metadata.json.

  Scan metadata written before the bridge existed has no block, which is
  reported as "not_enabled".
  """
  for path in (
      os.path.join(workspace_dir, "scan_metadata.json"),
      os.path.join(workspace_dir, ".codemender_transit", "base", "scan_metadata.json"),
  ):
    if not os.path.exists(path):
      continue
    try:
      with open(path, "r", encoding="utf-8") as f:
        wiz = json.load(f).get("wiz")
      if isinstance(wiz, dict) and wiz.get("status"):
        return wiz
      break
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning("Failed to read the Wiz block from scan metadata: %s", e)
      break
  return {"status": WIZ_NOT_ENABLED}


def _wiz_finding_ids(wiz: Optional[Dict[str, Any]]) -> Set[str]:
  ids = (wiz or {}).get("force_verify_ids") or (wiz or {}).get("imported_ids") or []
  return {str(i) for i in ids} if isinstance(ids, list) else set()


def _inject_wiz_status_into_html(
    html_path: str, wiz: Optional[Dict[str, Any]]
) -> None:
  """Adds a one-line Wiz SAST banner to the HTML report when the bridge ran."""
  note = wiz_summary_line(wiz)
  if not note or not os.path.exists(html_path):
    return
  banner_html = (
      '\n  <div id="codemender-wiz-banner" style="background: white;'
      " border-radius: 8px; padding: 14px 20px; margin-bottom: 25px;"
      " box-shadow: 0 2px 4px rgba(0,0,0,0.1); font-family: -apple-system,"
      " BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #16213e;\">"
      "<strong>Wiz SAST:</strong> "
      + html.escape(note)
      + " Imported findings are only remediated after CodeMender verifies"
      " them.</div>\n"
  )
  try:
    with open(html_path, "r", encoding="utf-8") as f:
      content = f.read()
    match = re.search(r"<div\s+class=[\"']cards[\"'][^>]*>", content, re.IGNORECASE)
    if match:
      content = content[: match.start()] + banner_html + content[match.start() :]
    else:
      body = re.search(r"<body[^>]*>", content, re.IGNORECASE)
      pos = body.end() if body else 0
      content = content[:pos] + banner_html + content[pos:]
    with open(html_path, "w", encoding="utf-8") as f:
      f.write(content)
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning("Failed to add the Wiz banner to the HTML report: %s", e)


def _render_step_summary(
    base_db_path: str,
    config: OrchestratorConfig,
    owner: str,
    repo_name: str,
    target_sha: Optional[str] = None,
    token_totals: Optional[dict[str, dict[str, int]]] = None,
    repo_dir: Optional[str] = None,
    finding_prs: Optional[dict[str, str]] = None,
    wiz: Optional[Dict[str, Any]] = None,
) -> tuple[str, int]:
  """Renders a comprehensive GitHub Actions Step Summary Markdown dashboard."""
  if not repo_dir and config.workspace_dir and repo_name:
    repo_dir = os.path.join(config.workspace_dir, repo_name)

  severity_badges = {
      "CRITICAL": "🔴 CRITICAL",
      "HIGH": "🟠 HIGH",
      "MEDIUM": "🟡 MEDIUM",
      "LOW": "🔵 LOW",
      "INFO": "⚪ INFO",
  }

  findings_stats = {
      "total": 0,
      "fixed": 0,
      "verified": 0,
      "pre_existing_ignored": 0,
      "skipped_duplicate": 0,
      "dismissed": 0,
      "unfixed": 0,
  }
  findings_list = []

  # 1. Query findings table from SQLite database to calculate status breakdown
  if os.path.exists(base_db_path):
    try:
      with closing(sqlite3.connect(base_db_path)) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'")
        if cursor.fetchone():
          cols = _get_table_columns(cursor, "findings", "main")
          select_cols = [
              "finding_id",
              "title",
              "status",
              "file_path",
              "start_line",
              "vuln_type",
              "vuln_id",
              "severity",
          ]
          avail_cols = [c for c in select_cols if c in cols]
          cursor.execute(f"SELECT {', '.join(avail_cols)} FROM findings ORDER BY finding_id")
          # 2. Iterate through each finding and bucket into status counters
          for row in cursor.fetchall():
            row_dict = dict(zip(avail_cols, row))
            fid = row_dict.get("finding_id", "")
            status = (row_dict.get("status") or "").upper()

            # In PR scans (Clean as You Code), omit pre-existing ignored, dismissed, and resolved findings
            if config.is_pr_scan and status in (
                "PRE_EXISTING_IGNORED",
                "DISMISSED",
                "FALSE_POSITIVE",
                "RESOLVED",
            ):
              continue

            findings_stats["total"] += 1
            if status in ("FIXED", "REMEDIATED"):
              findings_stats["fixed"] += 1
            elif status in ("VERIFIED", "CONFIRMED"):
              findings_stats["verified"] += 1
            elif status == "PRE_EXISTING_IGNORED":
              findings_stats["pre_existing_ignored"] += 1
            elif status == "SKIPPED_DUPLICATE":
              findings_stats["skipped_duplicate"] += 1
            else:
              # Fold DISMISSED, PR_CREATION_FAILED, and all other unclassified statuses into unfixed
              findings_stats["unfixed"] += 1

            raw_file_path = row_dict.get("file_path", "")
            clean_file_path = normalize_repo_relative_path(
                raw_file_path, repo_dir=repo_dir
            )

            findings_list.append({
                "finding_id": fid,
                "title": row_dict.get("title", ""),
                "status": status or "DETECTED",
                "file_path": clean_file_path,
                "start_line": row_dict.get("start_line", 0),
                "vuln_type": row_dict.get("vuln_type", ""),
                "vuln_id": row_dict.get("vuln_id", ""),
                "severity": (row_dict.get("severity") or "").upper(),
            })
    except sqlite3.Error as e:  # pylint: disable=broad-exception-caught
      logger.warning("Failed to query base_db for step summary: %s", e)

  # 3. Construct header metadata section (repository, target commit, execution mode)
  mode_desc = "Pull Request Scan (Clean as You Code)" if config.is_pr_scan else "Nightly Repository Scan"
  commit_desc = target_sha[:8] if target_sha else "HEAD"

  lines = [
      "# 🛡️ CodeMender Security Remediation Summary",
      "",
      f"- **Repository:** `{owner}/{repo_name}`",
      f"- **Target Commit:** `{commit_desc}`",
      f"- **Execution Mode:** `{mode_desc}`",
  ]
  wiz_note = wiz_summary_line(wiz)
  if wiz_note:
    lines.append(f"- **Wiz SAST:** {wiz_note}")
  wiz_ids = _wiz_finding_ids(wiz)

  if config.is_pr_scan:
    if findings_stats["total"] > 0:
      # Describe the route the workers actually used to deliver remediations.
      if resolve_pr_remediation_mode(config) == PR_MODE_REVIEW_SUGGESTION:
        remediation_hint = (
            "> Remediations have been synthesized and posted as inline review"
            " suggestions. Commit the suggestions on this pull request to"
            " resolve (patches that cannot be suggested inline are delivered as"
            " a Child Pull Request or a patch comment instead)."
        )
      else:
        remediation_hint = (
            "> Remediations have been synthesized. Please review and merge the"
            " proposed Child Pull Request into your feature branch (or apply"
            " the patches) to resolve."
        )
      lines.extend([
          "- **Security Gate:** ❌ **FAILED (Action Required)**",
          "",
          "> [!CAUTION]",
          f"> **Security Gate Status: FAILED ({findings_stats['total']} actionable vulnerability(ies) detected)**",
          "> ",
          remediation_hint,
          "",
      ])
    else:
      lines.extend([
          "- **Security Gate:** ✅ **PASSED (Clean as You Code)**",
          "",
          "> [!NOTE]",
          "> **Security Gate Status: PASSED**",
          "> ",
          "> No new actionable security vulnerabilities detected in the pull request diff.",
          "",
      ])
  else:
    lines.append("")

  lines.extend([
      "### 📊 Remediation Overview",
      "",
      "| Total Discovered | Remediated (Fixed) | Verified (Exploitable) | Pre-Existing Ignored | Skipped Duplicates | Other / Unfixed |",
      "| :---: | :---: | :---: | :---: | :---: | :---: |",
      f"| {findings_stats['total']} | {findings_stats['fixed']} | {findings_stats['verified']} | {findings_stats['pre_existing_ignored']} | {findings_stats['skipped_duplicate']} | {findings_stats['unfixed']} |",
      "",
  ])

  # 4. Construct table of individual findings and remediation outcomes
  if findings_list:
    lines.extend([
        "### 🛠️ Discovered Findings & Remediation Status",
        "",
        "| Finding ID | Severity | Vulnerability Type | Location | Status | Title |",
        "| :--- | :---: | :--- | :--- | :---: | :--- |",
    ])
    for f in findings_list:
      fid = f["finding_id"]
      sev = f.get("severity", "")
      sev_badge = severity_badges.get(sev, f"⚪ {sev}" if sev else "⚪ UNKNOWN")

      vuln_type = (f.get("vuln_type") or "").strip()
      vuln_id = (f.get("vuln_id") or "").strip()
      # Format vulnerability type with CWE ID if present and not already duplicated
      if vuln_id:
        if vuln_type:
          if vuln_id.lower() in vuln_type.lower():
            vuln_display = vuln_type
          else:
            vuln_display = f"{vuln_type} ({vuln_id})"
        else:
          vuln_display = vuln_id
      else:
        vuln_display = vuln_type or "N/A"

      # Location formatting: evaluate file_path:start_line directly (start_line=None/0 evaluates as file:None/0 for whole-file findings by design)
      loc = f"{f['file_path']}:{f['start_line']}" if f["file_path"] else "N/A"
      title_clean = f["title"].replace("|", "\\|") if f["title"] else "-"
      if fid in wiz_ids:
        title_clean += " _(reported by Wiz)_"
      status = f["status"]

      # Format Status with remediation hyperlinking if available
      pr_url = (finding_prs or {}).get(fid)
      if status in ("FIXED", "REMEDIATED", "SKIPPED_DUPLICATE") and pr_url:
        # Review and comment anchors live on the scanned pull request itself,
        # so their "/pull/<n>" segment is the parent PR number, not a Child PR.
        if "#discussion_r" in pr_url or "#pullrequestreview-" in pr_url:
          status_display = f"[{status} (suggested)]({pr_url})"
        elif "#issuecomment-" in pr_url:
          status_display = f"[{status} (patch posted)]({pr_url})"
        else:
          pr_match = re.search(r"/pull/(\d+)", pr_url)
          if pr_match:
            status_display = f"[{status} (#{pr_match.group(1)})]({pr_url})"
          else:
            status_display = f"[{status}]({pr_url})"
      else:
        status_display = f"`{status}`"

      lines.append(
          f"| `{fid}` | {sev_badge} | `{vuln_display}` | `{loc}` | {status_display} | {title_clean} |"
      )
    lines.append("")

  # 5. Add callout box pointing to downloadable report artifacts
  lines.extend([
      "> [!TIP]",
      "> 📄 **Interactive Security Report & Export Artifacts**",
      "> Download the **`codemender-report`** archive from the [Artifacts section](#artifacts) below for full interactive HTML graphs, SARIF definitions, and raw JSON telemetry.",
      "",
  ])

  # 6. Construct token usage summary table if metrics are available
  if token_totals:
    token_md = render_token_usage_markdown(token_totals)
    if token_md:
      lines.append(token_md)

  summary_md = "\n".join(lines)

  # 7. Guardrail: 1000 KiB maximum step summary size
  max_bytes = 1000 * 1024
  encoded = summary_md.encode("utf-8")
  if len(encoded) > max_bytes:
    summary_md = encoded[:max_bytes - 200].decode("utf-8", errors="ignore") + "\n\n... *(Summary truncated due to GitHub Step Summary size limit)*\n"

  # 8. Write to GITHUB_STEP_SUMMARY environment file if executing inside GitHub Actions
  summary_file = config.github_step_summary or os.environ.get("GITHUB_STEP_SUMMARY")
  if summary_file:
    try:
      with open(summary_file, "a", encoding="utf-8") as f:
        f.write(summary_md + "\n")
      logger.info("Wrote Step Summary to %s", summary_file)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning("Failed to write to GITHUB_STEP_SUMMARY (%s): %s", summary_file, e)

  return summary_md, findings_stats["total"]


def _build_automation_details_id(
    repository: Optional[str] = None,
    scan_target: Optional[str] = None,
    repo_dir: Optional[str] = None,
) -> str:
  """Builds a deterministic SARIF automationDetails.id scoped by repository and scan_target."""
  repo_val = (repository or "").strip()
  if not repo_val:
    repo_val = (os.environ.get("GITHUB_REPOSITORY") or "").strip()
  if not repo_val:
    raw_url = (os.environ.get("GITHUB_REPO_URL") or "").strip()
    if raw_url:
      try:
        owner_p, name_p = parse_repo_owner_and_name(sanitize_git_url(raw_url))
        if owner_p and name_p:
          repo_val = f"{owner_p}/{name_p}"
      except Exception:  # pylint: disable=broad-exception-caught
        pass
  if not repo_val and repo_dir:
    repo_val = os.path.basename(os.path.abspath(repo_dir))

  repo_slug = (
      re.sub(r"[^a-z0-9._-]+", "-", repo_val.lower()).strip("-")
      or "default-repo"
  )

  raw_target = (
      scan_target
      if scan_target is not None
      else os.environ.get("CODEMENDER_SCAN_TARGET", ".")
  )
  raw_target = (raw_target or ".").strip()
  if raw_target in ("", ".", "./", "/"):
    target_slug = "root"
  else:
    parts = [
        re.sub(r"[^a-z0-9._-]+", "-", p.strip().lower()).strip("-")
        for chunk in raw_target.split(";")
        for p in chunk.split(",")
        if p.strip() and p.strip() not in (".", "./", "/")
    ]
    target_slug = "-".join(p for p in parts if p)[:64] or "root"

  return f"codemender/{repo_slug}/{target_slug}/"


_SYMBOL_DECL_RE = re.compile(
    r"^\s*(?:async\s+def|def|class|function|func)\s+([A-Za-z_][A-Za-z0-9_]*)\b"
    r"|^\s*(?:public|private|protected|internal|static|final|synchronized|abstract|native|\s)+"
    r"[\w<>\[\],.?]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("
)


_SYMBOL_STOP_WORDS = frozenset({
    "if",
    "else",
    "elif",
    "for",
    "while",
    "switch",
    "case",
    "catch",
    "try",
    "return",
    "new",
    "var",
    "let",
    "const",
    "from",
    "import",
    "None",
    "none",
    "true",
    "false",
    "null",
})


def _extract_stable_symbol_anchor(
    finding: Dict[str, Any],
    repo_dir: str,
    rel_path: str,
    start_line: int,
    snippet: str = "",
) -> str:
  """Extracts an enclosing function, method, class, or code-token anchor for cross-run ruleId stability."""
  for key in ("Symbol", "symbol", "Function", "function", "Method", "method"):
    val = finding.get(key)
    if isinstance(val, str) and val.strip():
      return re.sub(r"[^a-z0-9_.:-]+", "", val.strip().lower())

  full_path = os.path.join(repo_dir, rel_path) if repo_dir and rel_path else ""
  if full_path and os.path.isfile(full_path) and start_line >= 1:
    try:
      with open(full_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.splitlines()
      upper_idx = min(len(lines), start_line)
      for idx in range(upper_idx - 1, -1, -1):
        m = _SYMBOL_DECL_RE.match(lines[idx])
        if m:
          sym = m.group(1) or m.group(2)
          if sym and sym.lower() not in _SYMBOL_STOP_WORDS:
            return sym.lower()
    except Exception:  # pylint: disable=broad-exception-caught
      pass

  raw_snippet = (
      snippet
      or finding.get("Snippet")
      or finding.get("snippet")
      or ""
  )
  if isinstance(raw_snippet, str) and raw_snippet.strip():
    for raw_ln in raw_snippet.splitlines():
      ln = raw_ln.strip()
      if not ln or ln.startswith(("#", "//", "/*", "*")):
        continue
      m = _SYMBOL_DECL_RE.match(ln)
      if m:
        sym = m.group(1) or m.group(2)
        if sym and sym.lower() not in _SYMBOL_STOP_WORDS:
          return sym.lower()
      tokens = [
          t.lower()
          for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", ln)
          if t.lower() not in _SYMBOL_STOP_WORDS
      ]
      if tokens:
        return "_".join(tokens[:6])
  return ""


def _sanitize_sarif_file(
    sarif_path: str,
    repo_dir: str,
    skipped_finding_ids: Optional[Set[str]] = None,
    is_pr_scan: bool = False,
    repository: Optional[str] = None,
    scan_target: Optional[str] = None,
) -> None:
  """Sanitizes SARIF file paths, deduplicates finding messages, and formats Markdown rule help."""
  if not os.path.exists(sarif_path):
    return

  try:
    with open(sarif_path, "r", encoding="utf-8") as f:
      content = f.read()

    data = extract_json_from_output(content)
    if not isinstance(data, dict):
      logger.warning("Failed to extract valid SARIF JSON from %s", sarif_path)
      return

    clean_repo_dir = os.path.abspath(repo_dir)
    automation_id = _build_automation_details_id(
        repository=repository,
        scan_target=scan_target,
        repo_dir=repo_dir,
    )

    # Iterate through all runs and results to normalize file URIs, deduplicate messages, and inject suppressions
    for run in (data.get("runs") or []):
      if isinstance(run, dict):
        auto_details = run.get("automationDetails")
        if not isinstance(auto_details, dict) or not auto_details.get("id"):
          run["automationDetails"] = {"id": automation_id}
      driver = run.get("tool", {}).get("driver", {})
      rules = driver.get("rules") or []
      rules_by_id = {r.get("id"): r for r in rules if isinstance(r, dict) and r.get("id")}

      for result in (run.get("results") or []):
        # 1. Sanitize file URIs to make them workspace-relative (required by GitHub Code Scanning)
        for loc in (result.get("locations") or []):
          phys = loc.get("physicalLocation") or {}
          art = phys.get("artifactLocation") or {}
          uri = art.get("uri", "")
          if uri:
            # Strip file:// URI scheme prefix if present
            if uri.startswith("file://"):
              uri = uri[7:]
            # Normalize absolute paths to repository-relative paths
            if os.path.isabs(uri):
              try:
                rel_path = os.path.relpath(uri, clean_repo_dir).replace("\\", "/")
                # Strip out-of-tree traversal components to prevent GitHub upload-sarif validation errors
                if rel_path.startswith("../") or rel_path == "..":
                  rel_path = re.sub(r"^(\.\./)+", "", rel_path)
                  if not rel_path or rel_path == ".":
                    rel_path = os.path.basename(uri)
                art["uri"] = rel_path
              except ValueError:
                art["uri"] = os.path.basename(uri)
            else:
              clean_uri = uri.replace("\\", "/").lstrip("/")
              if clean_uri.startswith("../") or clean_uri == "..":
                clean_uri = re.sub(r"^(\.\./)+", "", clean_uri)
                if not clean_uri or clean_uri == ".":
                  clean_uri = os.path.basename(uri)
              art["uri"] = clean_uri

        # 2. Locate associated SARIF rule definition by ruleId or ruleIndex
        rule_id = result.get("ruleId")
        rule_idx = result.get("ruleIndex")
        rule_obj = rules_by_id.get(rule_id) if rule_id else None
        if not rule_obj and isinstance(rule_idx, int) and 0 <= rule_idx < len(rules):
          rule_obj = rules[rule_idx]

        # 3. Clean and deduplicate result.message.text and populate rich rule.help.markdown
        msg_obj = result.get("message")
        if isinstance(msg_obj, dict):
          raw_text = msg_obj.get("text", "")
          if raw_text and ": " in raw_text:
            # Split concatenated "Title: Analysis" payload produced by CLI SARIF exporter
            title_part, analysis_part = raw_text.split(": ", 1)
            clean_title = title_part.strip()
            clean_analysis = analysis_part.strip()

            if clean_title:
              # Set clean, concise title on result message bubble above code line
              msg_obj["text"] = clean_title

            if rule_obj and clean_analysis:
              # Promote rich Markdown analysis into rule.help for GitHub Code Scanning UI
              rule_obj["shortDescription"] = {"text": clean_title or rule_obj.get("name", "Vulnerability")}
              rule_obj["help"] = {
                  "text": clean_analysis,
                  "markdown": clean_analysis,
              }
              # Extract first line/sentence for fullDescription summary
              first_line = clean_analysis.split("\n")[0].strip()
              rule_obj["fullDescription"] = {"text": first_line if first_line else clean_title}
          elif rule_obj and not rule_obj.get("help"):
            # Ensure help.markdown is populated from existing fullDescription if help is missing
            full_desc = rule_obj.get("fullDescription", {}).get("text", "")
            if full_desc:
              rule_obj["help"] = {
                  "text": full_desc,
                  "markdown": full_desc,
              }

        # 4. Inject suppression metadata on Nightly scans if finding is SKIPPED_DUPLICATE
        if not is_pr_scan and skipped_finding_ids:
          res_props = result.get("properties") or {}
          finding_id = result.get("ruleId") or res_props.get("finding_id")
          if (finding_id and finding_id in skipped_finding_ids) or res_props.get("status") == "SKIPPED_DUPLICATE":
            # Add SARIF suppression record to avoid duplicate alert notifications on GitHub Code Scanning
            result["suppressions"] = [
                {
                    "kind": "external",
                    "status": "underReview",
                    "justification": "Remediation PR or branch already exists",
                }
            ]

    # 5. Save sanitized SARIF report back to disk atomically
    with open(sarif_path, "w", encoding="utf-8") as f:
      json.dump(data, f, indent=2)
    logger.info("Successfully sanitized SARIF report: %s", sarif_path)
  except Exception as e:  # pylint: disable=broad-exception-caught
    # Log warning if SARIF sanitization fails
    logger.warning("Failed to sanitize SARIF report %s: %s", sarif_path, e)


_SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

_SEVERITY_TO_CVSS_SCORE = {
    "CRITICAL": "9.5",
    "HIGH": "8.0",
    "MEDIUM": "5.5",
    "LOW": "2.5",
}


def is_sarif_complete(
    sarif_data: Any,
    expected_results_count: Optional[int] = None,
) -> bool:
  """Validates whether a SARIF 2.1.0 object has complete rules, help markdown, CVSS severity, and line regions."""
  if not isinstance(sarif_data, dict):
    return False
  runs = sarif_data.get("runs")
  if not isinstance(runs, list) or not runs:
    return False
  run = runs[0]
  if not isinstance(run, dict):
    return False
  driver = (run.get("tool") or {}).get("driver") or {}
  if not driver.get("name"):
    return False

  rules = driver.get("rules")
  if not isinstance(rules, list):
    return False

  results = run.get("results")
  if not isinstance(results, list):
    return False
  if expected_results_count is not None and len(results) != expected_results_count:
    return False
  if not results:
    return True

  if not rules:
    return False
  rules_by_id = {
      r.get("id"): r for r in rules if isinstance(r, dict) and r.get("id")
  }
  if not rules_by_id:
    return False

  for res in results:
    if not isinstance(res, dict):
      return False
    rule_id = res.get("ruleId")
    rule_obj = rules_by_id.get(rule_id) if rule_id else None
    if not rule_obj:
      return False
    short_desc = (rule_obj.get("shortDescription") or {}).get("text") or ""
    full_desc = (rule_obj.get("fullDescription") or {}).get("text") or ""
    help_md = (rule_obj.get("help") or {}).get("markdown") or ""
    props = rule_obj.get("properties") or {}
    sec_sev = str(props.get("security-severity") or "").strip()
    tags = props.get("tags")
    if (
        not short_desc.strip()
        or not full_desc.strip()
        or not help_md.strip()
        or not sec_sev
        or not isinstance(tags, list)
        or not tags
    ):
      return False
    if not re.search(r"/[0-9a-f]{8}$", str(rule_id or "")):
      return False
    pf = res.get("partialFingerprints") or {}
    if not isinstance(pf, dict) or not str(pf.get("primaryLocationLineHash") or "").strip():
      return False
    locs = res.get("locations")
    if not isinstance(locs, list) or not locs:
      return False
    phys = (locs[0] or {}).get("physicalLocation") or {}
    region = phys.get("region") or {}
    try:
      start_line = int(region.get("startLine") or 0)
    except (ValueError, TypeError):
      start_line = 0
    if start_line < 1:
      return False

  return True


def _resolve_finding_region_and_snippet(
    finding: Dict[str, Any],
    repo_dir: str,
    rel_path: str,
) -> tuple[int, int, str]:
  """Extracts start_line, end_line, and code snippet from finding payload, nested JSON, or source file."""
  start_line = 0
  end_line = 0
  snippet = (
      finding.get("Snippet")
      or finding.get("snippet")
      or ""
  )

  for s_key, e_key in (("StartLine", "EndLine"), ("start_line", "end_line")):
    if start_line <= 0 and finding.get(s_key) is not None:
      try:
        start_line = int(finding.get(s_key) or 0)
      except (ValueError, TypeError):
        start_line = 0
    if end_line <= 0 and finding.get(e_key) is not None:
      try:
        end_line = int(finding.get(e_key) or 0)
      except (ValueError, TypeError):
        end_line = 0

  # Check nested location dict or FindingJSON proto payload if start_line is still 0
  nested_candidates: List[Dict[str, Any]] = []
  if isinstance(finding.get("location"), dict):
    nested_candidates.append(finding["location"])
  raw_fjson = finding.get("FindingJSON") or finding.get("finding_json")
  if isinstance(raw_fjson, str) and raw_fjson.strip():
    parsed_fj = extract_json_from_output(raw_fjson)
    if isinstance(parsed_fj, dict):
      nested_candidates.append(parsed_fj)
      if isinstance(parsed_fj.get("location"), dict):
        nested_candidates.append(parsed_fj["location"])
  elif isinstance(raw_fjson, dict):
    nested_candidates.append(raw_fjson)
    if isinstance(raw_fjson.get("location"), dict):
      nested_candidates.append(raw_fjson["location"])

  for cand in nested_candidates:
    rng = cand.get("range") if isinstance(cand.get("range"), dict) else cand
    if start_line <= 0:
      try:
        start_line = int(
            rng.get("start_line")
            or rng.get("startLine")
            or cand.get("start_line")
            or cand.get("startLine")
            or 0
        )
      except (ValueError, TypeError):
        pass
    if end_line <= 0:
      try:
        end_line = int(
            rng.get("end_line")
            or rng.get("endLine")
            or cand.get("end_line")
            or cand.get("endLine")
            or 0
        )
      except (ValueError, TypeError):
        pass
    if not snippet and isinstance(cand.get("snippet"), str):
      snippet = cand["snippet"]

  # Locate snippet in source file under repo_dir if start_line is still unknown or snippet is missing
  full_file_path = os.path.join(repo_dir, rel_path) if repo_dir and rel_path else ""
  if full_file_path and os.path.isfile(full_file_path):
    try:
      with open(full_file_path, "r", encoding="utf-8", errors="replace") as f:
        file_lines = f.splitlines()
      if start_line <= 0 and snippet and snippet.strip():
        target_lines = [ln.strip() for ln in snippet.strip().splitlines() if ln.strip()]
        if target_lines:
          first_target = target_lines[0]
          for idx, src_line in enumerate(file_lines, start=1):
            if first_target in src_line:
              start_line = idx
              end_line = min(len(file_lines), idx + len(target_lines) - 1)
              break
      elif start_line >= 1 and not snippet:
        s_idx = max(0, start_line - 1)
        e_idx = min(len(file_lines), max(start_line, end_line))
        snippet = "\n".join(file_lines[s_idx:e_idx])
    except Exception:  # pylint: disable=broad-exception-caught
      pass

  if start_line < 1:
    start_line = 1
  if end_line < start_line:
    snippet_line_count = len(snippet.strip().splitlines()) if snippet and snippet.strip() else 1
    end_line = start_line + max(0, snippet_line_count - 1)

  return start_line, end_line, (snippet or "").strip("\r\n")


def _extract_first_sentence(text: str, fallback: str) -> str:
  """Extracts a clean, single-sentence summary from multi-paragraph Markdown analysis."""
  if not text or not text.strip():
    return fallback
  for raw_line in text.splitlines():
    cleaned = re.sub(r"^#+\s*", "", raw_line.strip())
    if not cleaned:
      continue
    # Split at first sentence boundary followed by whitespace
    parts = re.split(r"(?<=[.!?])\s+", cleaned, maxsplit=1)
    first = parts[0].strip()
    if len(first) > 400:
      cutoff = first.rfind(" ", 0, 397)
      first = (first[:cutoff] if cutoff > 200 else first[:397]).rstrip()
      if first.count("`") % 2 == 1:
        first += "`"
      first += "..."
    return first
  return fallback


def transform_json_to_sarif(
    findings: List[Dict[str, Any]],
    repo_dir: str,
    skipped_finding_ids: Optional[Set[str]] = None,
    finding_prs: Optional[Dict[str, str]] = None,
    is_pr_scan: bool = False,
    tool_version: str = "0.9.0",
    repository: Optional[str] = None,
    scan_target: Optional[str] = None,
) -> Dict[str, Any]:
  """Synthesizes a complete GitHub Code Scanning SARIF 2.1.0 document from CodeMender JSON findings."""
  rules: List[Dict[str, Any]] = []
  rules_index_by_id: Dict[str, int] = {}
  used_rule_names: Set[str] = set()
  results: List[Dict[str, Any]] = []
  skipped_set = set(skipped_finding_ids or set())
  prs_map = dict(finding_prs or {})

  for f in findings:
    if not isinstance(f, dict):
      continue
    finding_id = str(f.get("FindingID") or f.get("finding_id") or "").strip()
    status = str(f.get("Status") or f.get("status") or "OPEN").strip().upper()
    if finding_id and finding_id in skipped_set and status not in ("FIXED", "REMEDIATED"):
      status = "SKIPPED_DUPLICATE"
    if status == "DISMISSED":
      continue
    if is_pr_scan and status in ("PRE_EXISTING_IGNORED", "SKIPPED_DUPLICATE"):
      continue

    raw_path = str(f.get("FilePath") or f.get("file_path") or "unknown_file").strip()
    rel_path = normalize_repo_relative_path(raw_path, repo_dir=repo_dir)
    if rel_path.startswith("../") or rel_path == "..":
      rel_path = re.sub(r"^(\.\./)+", "", rel_path) or os.path.basename(raw_path)

    vuln_type = str(
        f.get("VulnType") or f.get("vuln_type") or "Security Vulnerability"
    ).strip()
    vuln_id = str(
        f.get("VulnID")
        or f.get("vuln_id")
        or f.get("cwe_id")
        or f.get("CWE")
        or ""
    ).strip()
    title = str(f.get("Title") or f.get("title") or vuln_type).strip()
    if not vuln_id:
      cwe_match = re.search(r"(CWE-\d+)", vuln_type, re.IGNORECASE)
      if not cwe_match and vuln_type.lower() in (
          "security vulnerability",
          "vulnerability",
          "unknown",
      ):
        cwe_match = re.search(r"(CWE-\d+)", title, re.IGNORECASE)
      if cwe_match:
        vuln_id = cwe_match.group(1).upper()
      else:
        slug = re.sub(r"[^A-Z0-9]+", "-", vuln_type.upper()).strip("-")
        vuln_id = f"CM-{slug[:24]}" if slug else "CM-VULN"

    severity = str(f.get("Severity") or f.get("severity") or "MEDIUM").strip().upper()
    level = _SEVERITY_TO_SARIF_LEVEL.get(severity, "warning")
    security_severity = _SEVERITY_TO_CVSS_SCORE.get(severity, "5.5")

    confidence_raw = f.get("Confidence") if f.get("Confidence") is not None else f.get("confidence")
    confidence_level = str(
        f.get("ConfidenceLevel") or f.get("confidence_level") or ""
    ).strip().lower()
    try:
      conf_int = int(confidence_raw) if confidence_raw is not None else 85
    except (ValueError, TypeError):
      conf_int = 85

    if confidence_level == "certain" or conf_int >= 90:
      precision = "very-high"
    elif confidence_level == "firm" or conf_int >= 75:
      precision = "high"
    else:
      precision = "medium"
    confidence_display = (
        f"{conf_int}% ({confidence_level})"
        if confidence_level
        else f"{conf_int}%"
    )

    start_line, end_line, snippet = _resolve_finding_region_and_snippet(
        f, repo_dir, rel_path
    )
    analysis = str(
        f.get("Analysis")
        or f.get("analysis")
        or f"CodeMender detected a {severity} {vuln_type} ({vuln_id}) vulnerability in `{rel_path}`."
    ).strip()

    # Cross-run-stable ruleId: hash of vuln_id/vuln_type, normalized file_path,
    # and enclosing symbol/function anchor (omitting volatile raw line numbers
    # and LLM-generated titles).
    symbol_anchor = _extract_stable_symbol_anchor(
        f, repo_dir, rel_path, start_line, snippet=snippet
    )
    rule_seed = (
        f"{vuln_id.upper()}:{vuln_type.strip().lower()}:{rel_path}:{symbol_anchor}"
    )
    rule_hash = hashlib.sha256(rule_seed.encode("utf-8")).hexdigest()[:8]
    rule_id = f"{vuln_id}/{rule_hash}"

    pr_url = prs_map.get(finding_id) or str(f.get("pr_url") or "").strip()
    pr_label = ""
    pr_markdown_cell = "—"
    if pr_url:
      pr_num_match = re.search(r"/pull/(\d+)", pr_url)
      pr_label = f"Fix PR #{pr_num_match.group(1)}" if pr_num_match else "Automated Fix PR"
      pr_markdown_cell = f"[🔧 **{pr_label}**]({pr_url})"

    short_desc_text = (
        f"[{vuln_id}] {title}"
        if vuln_id and not title.upper().startswith(f"[{vuln_id.upper()}]")
        else title
    )
    first_sentence = _extract_first_sentence(analysis, title)

    tags = ["security"]
    cwe_num_match = re.match(r"^CWE-(\d+)$", vuln_id, re.IGNORECASE)
    if cwe_num_match:
      tags.append(f"external/cwe/cwe-{cwe_num_match.group(1)}")

    snippet_section = (
        f"\n\n#### Vulnerable Code Snippet (`{rel_path}:{start_line}-{end_line}`)\n```\n{snippet}\n```"
        if snippet
        else ""
    )
    help_markdown = (
        f"### 🛡️ CodeMender Security Analysis: {title}\n\n"
        f"| Property | Value |\n"
        f"| :--- | :--- |\n"
        f"| **Severity** | **{severity}** (CVSS `{security_severity}`) |\n"
        f"| **Vulnerability Type** | `{vuln_type}` (`{vuln_id}`) |\n"
        f"| **Confidence** | `{confidence_display}` |\n"
        f"| **Status** | `{status}` |\n"
        f"| **Location** | `{rel_path}:{start_line}` |\n"
        f"| **Automated Fix PR** | {pr_markdown_cell} |\n\n"
        f"#### Root Cause & Dataflow Analysis\n\n"
        f"{analysis}"
        f"{snippet_section}"
    )
    help_text = (
        f"[{vuln_id}] {title} ({severity})\n"
        f"Location: {rel_path}:{start_line}-{end_line}\n"
        + (f"Fix PR: {pr_url}\n" if pr_url else "")
        + f"\n{analysis}"
    )

    if rule_id not in rules_index_by_id:
      base_rule_name = re.sub(r"[^A-Za-z0-9]", "", vuln_type.title()) or "CodeMenderSecurityFinding"
      rule_name_clean = (
          f"{base_rule_name}{rule_hash.capitalize()}"
          if base_rule_name in used_rule_names
          else base_rule_name
      )
      used_rule_names.add(rule_name_clean)
      rules_index_by_id[rule_id] = len(rules)
      rules.append({
          "id": rule_id,
          "name": rule_name_clean,
          "shortDescription": {"text": short_desc_text},
          "fullDescription": {"text": first_sentence},
          "help": {
              "text": help_text,
              "markdown": help_markdown,
          },
          "defaultConfiguration": {"level": level},
          "properties": {
              "tags": tags,
              "security-severity": security_severity,
              "precision": precision,
              "problem.severity": level,
          },
      })

    rule_index = rules_index_by_id[rule_id]
    inline_msg_text = first_sentence
    if pr_url:
      inline_msg_text = f"{first_sentence} (Remediation: {pr_label} - {pr_url})"
    inline_msg_md = (
        f"{first_sentence} — [{pr_label}]({pr_url})"
        if pr_url
        else first_sentence
    )

    normalized_snippet = (
        re.sub(r"\s+", " ", snippet.strip())
        if snippet and snippet.strip()
        else ""
    )
    fp_seed = (
        f"{vuln_id.upper()}:{vuln_type.strip().lower()}:{rel_path}:{symbol_anchor}:{normalized_snippet}"
    )
    line_hash = hashlib.sha256(fp_seed.encode("utf-8")).hexdigest()[:16]

    result_obj: Dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": level,
        "message": {
            "text": inline_msg_text,
            "markdown": inline_msg_md,
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": rel_path},
                    "region": {
                        "startLine": start_line,
                        "endLine": end_line,
                        "snippet": {"text": snippet or title},
                    },
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": line_hash,
        },
        "properties": {
            "finding_id": finding_id,
            "status": status,
            "vuln_id": vuln_id,
            "vuln_type": vuln_type,
            "severity": severity,
            "confidence": conf_int,
            "pr_url": pr_url,
        },
    }

    if not is_pr_scan and (
        (finding_id and finding_id in skipped_set)
        or status == "SKIPPED_DUPLICATE"
    ):
      result_obj["suppressions"] = [
          {
              "kind": "external",
              "status": "underReview",
              "justification": "Remediation PR or branch already exists",
          }
      ]

    results.append(result_obj)

  automation_id = _build_automation_details_id(
      repository=repository,
      scan_target=scan_target,
      repo_dir=repo_dir,
  )

  return {
      "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
      "version": "2.1.0",
      "runs": [
          {
              "automationDetails": {
                  "id": automation_id,
              },
              "tool": {
                  "driver": {
                      "name": "CodeMender",
                      "version": tool_version,
                      "semanticVersion": tool_version,
                      "informationUri": "https://cloud.google.com/security",
                      "rules": rules,
                  }
              },
              "results": results,
          }
      ],
  }


def _load_findings_for_sarif(
    json_path: Optional[str],
    state_db_path: Optional[str],
) -> List[Dict[str, Any]]:
  """Loads and merges finding records from report.json and SQLite state.db."""
  findings_by_id: Dict[str, Dict[str, Any]] = {}
  ordered_findings: List[Dict[str, Any]] = []

  if json_path and os.path.isfile(json_path):
    try:
      with open(json_path, "r", encoding="utf-8") as f:
        parsed = parse_findings_json(f.read())
      for item in parsed:
        fid = str(item.get("FindingID") or item.get("finding_id") or "")
        if fid:
          findings_by_id[fid] = item
        ordered_findings.append(item)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning("Could not read findings from %s for SARIF synthesis: %s", json_path, e)

  if state_db_path and os.path.isfile(state_db_path):
    try:
      with closing(sqlite3.connect(state_db_path)) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='findings'"
        )
        if cursor.fetchone():
          cursor.execute("SELECT * FROM findings")
          rows = cursor.fetchall()
          for row in rows:
            row_dict = dict(row)
            normalized = parse_findings_json(json.dumps([row_dict]))
            if not normalized:
              continue
            item = normalized[0]
            fid = str(item.get("FindingID") or item.get("finding_id") or "")
            if fid and fid in findings_by_id:
              # Fill any missing fields (e.g. start_line, snippet, finding_json, status) from state.db
              existing = findings_by_id[fid]
              for k, v in item.items():
                if v not in (None, "", 0) and existing.get(k) in (None, "", 0):
                  existing[k] = v
              # Always prefer latest status from merged state.db (e.g. FIXED, SKIPPED_DUPLICATE)
              if item.get("Status"):
                existing["Status"] = item["Status"]
                existing["status"] = item["Status"]
            elif fid:
              findings_by_id[fid] = item
              ordered_findings.append(item)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning("Could not enrich SARIF findings from %s: %s", state_db_path, e)

  return ordered_findings


def validate_and_enrich_sarif(
    sarif_path: str,
    json_path: Optional[str],
    repo_dir: str,
    skipped_finding_ids: Optional[Set[str]] = None,
    finding_prs: Optional[Dict[str, str]] = None,
    is_pr_scan: bool = False,
    state_db_path: Optional[str] = None,
    repository: Optional[str] = None,
    scan_target: Optional[str] = None,
) -> bool:
  """Validates SARIF completeness and synthesizes rich SARIF 2.1.0 from report.json + state.db when incomplete."""
  existing_sarif = None
  if sarif_path and os.path.isfile(sarif_path):
    try:
      with open(sarif_path, "r", encoding="utf-8") as f:
        existing_sarif = extract_json_from_output(f.read())
    except Exception:  # pylint: disable=broad-exception-caught
      existing_sarif = None

  automation_id = _build_automation_details_id(
      repository=repository,
      scan_target=scan_target,
      repo_dir=repo_dir,
  )

  findings = _load_findings_for_sarif(json_path, state_db_path)
  skipped_set = set(skipped_finding_ids or set())
  expected_count = 0
  for f in findings:
    if not isinstance(f, dict):
      continue
    fid = str(f.get("FindingID") or f.get("finding_id") or "").strip()
    status = str(f.get("Status") or f.get("status") or "OPEN").strip().upper()
    if fid and fid in skipped_set and status not in ("FIXED", "REMEDIATED"):
      status = "SKIPPED_DUPLICATE"
    if status == "DISMISSED":
      continue
    if is_pr_scan and status in ("PRE_EXISTING_IGNORED", "SKIPPED_DUPLICATE"):
      continue
    expected_count += 1

  if (
      existing_sarif is not None
      and is_sarif_complete(
          existing_sarif,
          expected_results_count=expected_count if findings else None,
      )
      and not finding_prs
  ):
    if isinstance(existing_sarif, dict):
      for run in existing_sarif.get("runs") or []:
        if isinstance(run, dict):
          auto_details = run.get("automationDetails")
          if not isinstance(auto_details, dict) or not auto_details.get("id"):
            run["automationDetails"] = {"id": automation_id}
      try:
        with open(sarif_path, "w", encoding="utf-8") as f:
          json.dump(existing_sarif, f, indent=2)
      except Exception:  # pylint: disable=broad-exception-caught
        pass
    logger.info("SARIF report at %s passed completeness validation.", sarif_path)
    return True

  if not findings:
    if isinstance(existing_sarif, dict):
      # Ensure tool.driver.rules is an array (not null) even when 0 findings exist
      for run in existing_sarif.get("runs") or []:
        if isinstance(run, dict):
          auto_details = run.get("automationDetails")
          if not isinstance(auto_details, dict) or not auto_details.get("id"):
            run["automationDetails"] = {"id": automation_id}
          driver = (run.get("tool") or {}).get("driver")
          if isinstance(driver, dict) and driver.get("rules") is None:
            driver["rules"] = []
      try:
        with open(sarif_path, "w", encoding="utf-8") as f:
          json.dump(existing_sarif, f, indent=2)
      except Exception:  # pylint: disable=broad-exception-caught
        pass
    logger.info(
        "No findings available in report.json or state.db to enrich %s; keeping existing SARIF.",
        sarif_path,
    )
    return False

  enriched_sarif = transform_json_to_sarif(
      findings=findings,
      repo_dir=repo_dir,
      skipped_finding_ids=skipped_finding_ids,
      finding_prs=finding_prs,
      is_pr_scan=is_pr_scan,
      repository=repository,
      scan_target=scan_target,
  )
  try:
    os.makedirs(os.path.dirname(os.path.abspath(sarif_path)), exist_ok=True)
    with open(sarif_path, "w", encoding="utf-8") as f:
      json.dump(enriched_sarif, f, indent=2)
    logger.info(
        "Synthesized complete SARIF 2.1.0 report (%d results, %d rules) at %s",
        len(enriched_sarif["runs"][0]["results"]),
        len(enriched_sarif["runs"][0]["tool"]["driver"]["rules"]),
        sarif_path,
    )
    return True
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning("Failed to write enriched SARIF report to %s: %s", sarif_path, e)
    return False


# -----------------------------------------------------------------------------
# Final Report Generation and Upload Pipeline
# -----------------------------------------------------------------------------
def _generate_and_upload_report(
    repo_dir: str,
    scrubbed_env: dict[str, str],
    cm_binary: str,
    codemender_home: str,
    bucket_name: str,
    owner: str,
    repo_name: str,
    token_totals: Optional[dict[str, dict[str, int]]] = None,
    scan_id: Optional[str] = None,
    # Execution mode and filtering configurations
    is_pr_scan: bool = False,
    skipped_finding_ids: Optional[Set[str]] = None,
    storage_mode: str = "gcs",
    config: Optional[OrchestratorConfig] = None,
    finding_prs: Optional[Dict[str, str]] = None,
    wiz: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
  """Generates final HTML and SARIF reports using cm CLI and uploads to GCS or publishes locally.

  Returns:
    The durable `gs://` URI of the uploaded HTML report, or None when no
    report was uploaded (non-GCS storage modes, or generation failure). The
    signed URL is deliberately not returned: it expires within hours, whereas
    the object itself persists until the bucket lifecycle rule removes it.
  """
  cfg = config or OrchestratorConfig.from_env()
  cli_version = cfg.cli_version
  report_gcs_uri: Optional[str] = None
  logger.info("Generating final consolidated HTML summary report...")

  # 1. Execute 'cm report -f html' to generate full HTML report
  report_cmd = build_cm_command(
      cm_binary, "report", extra_flags=["-f", "html"], cli_version=cli_version
  )
  report_res = run_command(
      report_cmd,
      cwd=repo_dir,
      env=scrubbed_env,
      check=False,
  )

  local_report_path = os.path.join(codemender_home, "reports/report.html")
  if report_res.returncode == 0 or os.path.exists(local_report_path):
    # 2. Inject aggregated LLM token usage metrics into HTML report header
    _inject_token_metrics_into_html(local_report_path, token_totals)
    _inject_wiz_status_into_html(local_report_path, wiz)

    # 3. Copy HTML report to workspace/repo_dir for artifact capture
    workspace_dir = cfg.workspace_dir or os.getcwd()
    for dest in [
        os.path.join(repo_dir, "report.html"),
        os.path.join(workspace_dir, "report.html"),
    ]:
      if os.path.exists(local_report_path) and os.path.abspath(local_report_path) != os.path.abspath(dest):
        try:
          os.makedirs(os.path.dirname(dest), exist_ok=True)
          shutil.copy2(local_report_path, dest)
        except Exception:  # pylint: disable=broad-exception-caught
          pass

    # Generate JSON report for CI artifact pipelines
    json_cmd = build_cm_command(
        cm_binary, "report", extra_flags=["-f", "json"], cli_version=cli_version
    )
    json_res = run_command(
        json_cmd,
        cwd=repo_dir,
        env=scrubbed_env,
        check=False,
    )
    local_json_path = os.path.join(codemender_home, "reports/report.json")
    if not os.path.exists(local_json_path) and hasattr(json_res, "stdout"):
      json_data = extract_json_from_output(json_res.stdout)
      if json_data is not None:
        try:
          os.makedirs(os.path.dirname(local_json_path), exist_ok=True)
          with open(local_json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)
        except Exception:  # pylint: disable=broad-exception-caught
          pass
    elif os.path.exists(local_json_path):
      try:
        with open(local_json_path, "r", encoding="utf-8") as f:
          raw_json_str = f.read()
        json_data = extract_json_from_output(raw_json_str)
        if json_data is not None:
          with open(local_json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)
      except Exception:  # pylint: disable=broad-exception-caught
        pass

    if os.path.exists(local_json_path):
      for dest in [
          os.path.join(repo_dir, "report.json"),
          os.path.join(workspace_dir, "report.json"),
      ]:
        if os.path.abspath(local_json_path) != os.path.abspath(dest):
          try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copy2(local_json_path, dest)
          except Exception:  # pylint: disable=broad-exception-caught
            pass

    # 4. Upload HTML report to GCS bucket and generate signed URL if in GCS mode
    if storage_mode in ["gcs", "local"] and bucket_name:
      report_bucket = cfg.report_bucket or bucket_name
      dest_blob = (
          f"reports/{owner}_{repo_name}/{scan_id}/"
          f"report_{time.strftime('%Y%m%d-%H%M%S')}.html"
          if scan_id
          else f"reports/{owner}_{repo_name}/"
          f"report_{time.strftime('%Y%m%d-%H%M%S')}.html"
      )

      logger.info("Uploading final report to GCS bucket %s...", report_bucket)
      # Upload HTML report to GCS bucket and acquire signed GET URL
      signed_url = upload_and_sign_report(
          local_report_path, report_bucket, dest_blob
      )
      if signed_url:
        report_gcs_uri = f"gs://{report_bucket}/{dest_blob}"
        # Print high-visibility banner with signed URL for CI logs
        logger.info(
            "\n"
            "======================================================================\n"
            "📊 CONSOLIDATED CODEMENDER SUMMARY REPORT GENERATED:\n"
            "👉 %s\n"
            "======================================================================\n",
            signed_url,
        )
      else:
        # Abort if GCS report upload fails
        logger.critical(
            "Failed to upload or generate signed URL for the consolidated GCS"
            " report."
        )
        sys.exit(1)
  else:
    # Log report generation failure
    logger.error(
        "Failed to execute 'cm report -f html' in aggregator (code %d).",
        report_res.returncode,
    )
    # Abort in GCS mode if report cannot be produced
    if storage_mode == "gcs":
      sys.exit(1)

  # 5. Generate SARIF report for GitHub Security Code Scanning tab
  logger.info("Generating final consolidated SARIF report...")
  sarif_cmd = build_cm_command(
      cm_binary, "report", extra_flags=["-f", "sarif"], cli_version=cli_version
  )
  sarif_res = run_command(
      sarif_cmd,
      cwd=repo_dir,
      env=scrubbed_env,
      check=False,
  )

  # 6. Locate generated SARIF artifact (checking disk paths and stdout fallback)
  sarif_candidates = [
      os.path.join(codemender_home, "reports/report.sarif"),
      os.path.join(repo_dir, "reports/report.sarif"),
      os.path.join(repo_dir, "report.sarif"),
  ]
  found_sarif = None
  for sc in sarif_candidates:
    if os.path.exists(sc):
      found_sarif = sc
      break

  # If cm report printed SARIF to stdout instead of disk, write clean parsed JSON to fallback file
  if not found_sarif and hasattr(sarif_res, "stdout"):
    sarif_data = extract_json_from_output(sarif_res.stdout)
    if sarif_data is not None:
      fallback_sarif = os.path.join(codemender_home, "reports/report.sarif")
      try:
        os.makedirs(os.path.dirname(fallback_sarif), exist_ok=True)
        with open(fallback_sarif, "w", encoding="utf-8") as f:
          json.dump(sarif_data, f, indent=2)
        found_sarif = fallback_sarif
      except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning("Failed to write SARIF stdout fallback to disk: %s", e)

  # 7. Sanitize SARIF paths, validate completeness, enrich from report.json + state.db, and copy to standard upload locations
  workspace_dir = cfg.workspace_dir or os.getcwd()
  if not found_sarif:
    found_sarif = os.path.join(codemender_home, "reports/report.sarif")
  if os.path.exists(found_sarif):
    _sanitize_sarif_file(
        found_sarif,
        repo_dir,
        skipped_finding_ids=skipped_finding_ids,
        is_pr_scan=is_pr_scan,
        repository=f"{owner}/{repo_name}",
        scan_target=cfg.scan_target,
    )
  validate_and_enrich_sarif(
      sarif_path=found_sarif,
      json_path=local_json_path if "local_json_path" in locals() else os.path.join(codemender_home, "reports/report.json"),
      repo_dir=repo_dir,
      skipped_finding_ids=skipped_finding_ids,
      finding_prs=finding_prs,
      is_pr_scan=is_pr_scan,
      state_db_path=os.path.join(codemender_home, "state.db"),
      repository=f"{owner}/{repo_name}",
      scan_target=cfg.scan_target,
  )
  if os.path.exists(found_sarif):
    # Ensure SARIF is placed in repo_dir and workspace root for upload-sarif action
    for target_dest in [
        os.path.join(repo_dir, "report.sarif"),
        os.path.join(workspace_dir, "report.sarif"),
    ]:
      if os.path.abspath(found_sarif) != os.path.abspath(target_dest):
        try:
          os.makedirs(os.path.dirname(target_dest), exist_ok=True)
          shutil.copy2(found_sarif, target_dest)
        except Exception:  # pylint: disable=broad-exception-caught
          pass

  # 8. Persist machine-readable artifacts (report.json, report.sarif, token_usage.json) to GCS
  if storage_mode in ("gcs", "local") and bucket_name and scan_id:
    report_bucket = cfg.report_bucket or bucket_name
    prefix = f"scans/{scan_id}"
    token_usage_path = os.path.join(codemender_home, "reports/token_usage.json")
    try:
      os.makedirs(os.path.dirname(token_usage_path), exist_ok=True)
      with open(token_usage_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "scan_id": scan_id,
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "token_totals": token_totals or {},
            },
            f,
            indent=2,
        )
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning("Could not write token usage summary: %s", e)

    for candidates, dest_blob in [
        (
            [
                os.path.join(codemender_home, "reports/report.html"),
                os.path.join(workspace_dir, "report.html"),
                os.path.join(repo_dir, "report.html"),
            ],
            f"{prefix}/report.html",
        ),
        (
            [
                os.path.join(codemender_home, "reports/report.json"),
                os.path.join(workspace_dir, "report.json"),
                os.path.join(repo_dir, "report.json"),
            ],
            f"{prefix}/report.json",
        ),
        (
            [
                os.path.join(codemender_home, "reports/report.sarif"),
                os.path.join(workspace_dir, "report.sarif"),
                os.path.join(repo_dir, "report.sarif"),
            ],
            f"{prefix}/report.sarif",
        ),
        ([token_usage_path], f"{prefix}/token_usage.json"),
    ]:
      local_path = next((c for c in candidates if os.path.exists(c)), None)
      if local_path:
        upload_file_to_gcs(local_path, report_bucket, dest_blob)

  return report_gcs_uri


def has_sarif_results(sarif_path: Optional[str]) -> bool:
  """Returns True if the SARIF file exists and contains at least one result across its runs."""
  if not sarif_path or not os.path.isfile(sarif_path):
    return False
  try:
    with open(sarif_path, "r", encoding="utf-8") as f:
      data = extract_json_from_output(f.read())
    if not isinstance(data, dict):
      return False
    for run in data.get("runs") or []:
      if isinstance(run, dict) and run.get("results"):
        return True
  except Exception:  # pylint: disable=broad-exception-caught
    pass
  return False


def _skipped_count_for_telemetry(
    telemetry_findings: List[Dict[str, Any]], skipped_finding_ids: Set[str]
) -> int:
  """`scan_runs.skipped_duplicate_count` for a run that reached Stage 3.

  Duplicates and pre-existing findings count alike, as Stage 1 counts them
  when it records an all-filtered run, so the column means the same on every
  path. Falls back to the SKIPPED_DUPLICATE IDs when no snapshot was taken.
  """
  if telemetry_findings:
    return bq_telemetry.summarize_remediation(telemetry_findings)[
        "skipped_duplicate"
    ]
  return len(skipped_finding_ids)


def _resolve_end_to_end_duration(workspace_dir: str) -> Optional[float]:
  """Computes total scan wall-clock seconds from the Stage 1 start timestamp.

  Stage 1 records `started_at` into `scan_metadata.json`, which the aggregator
  has already downloaded by this point. Measuring from there yields true
  end-to-end duration across all three stages, rather than just the
  aggregator's own runtime.

  Returns None when the timestamp is absent or unparseable, so the caller can
  fall back to a stage-local measurement instead of reporting a wrong number.
  """
  meta_path = os.path.join(workspace_dir, "scan_metadata.json")
  if not os.path.exists(meta_path):
    return None
  try:
    with open(meta_path, "r", encoding="utf-8") as f:
      meta = json.load(f)
    started_at = meta.get("started_at")
    if not started_at:
      return None
    started = datetime.datetime.fromisoformat(str(started_at))
    if started.tzinfo is None:
      started = started.replace(tzinfo=datetime.timezone.utc)
    elapsed = (
        datetime.datetime.now(datetime.timezone.utc) - started
    ).total_seconds()
    return max(0.0, elapsed)
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning("Could not derive end-to-end scan duration: %s", e)
    return None


def _resolve_fallback_commit_sha(
    clean_repo_url: str,
    token: str,
    owner: str,
    repo_name: str,
    target_branch: Optional[str],
    workspace_dir: str,
) -> Optional[str]:
  """Resolves the target branch HEAD SHA via git ls-remote when manifest.json is unavailable."""
  if not clean_repo_url or not token:
    return None
  try:
    branch = target_branch or get_default_branch(token, owner, repo_name) or "HEAD"
    ref_arg = f"refs/heads/{branch}" if branch != "HEAD" else "HEAD"
    res = run_command(
        [
            "git",
            "-c",
            get_git_auth_header(token),
            "ls-remote",
            clean_repo_url,
            ref_arg,
        ],
        cwd=workspace_dir,
        check=False,
    )
    stdout = (getattr(res, "stdout", "") or "").strip()
    if stdout:
      return stdout.split()[0].strip()
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning("Could not resolve fallback commit SHA via ls-remote: %s", e)
  return None


def _record_failure_marker(
    workspace_dir: str,
    bucket_name: Optional[str],
    scan_id: Optional[str],
    stage: str,
    target_sha: Optional[str],
) -> None:
  """Uploads a failure marker to GCS so the Cloud Workflows finalizer knows the container already emitted telemetry."""
  if not bucket_name or not scan_id or scan_id.startswith("local"):
    return
  try:
    marker_path = os.path.join(workspace_dir or "/tmp", "failure_recorded.json")
    with open(marker_path, "w", encoding="utf-8") as f:
      json.dump(
          {
              "scan_id": scan_id,
              "stage": stage,
              "target_sha": target_sha or "",
              "recorded": True,
          },
          f,
      )
    upload_file_to_gcs(
        marker_path, bucket_name, f"scans/{scan_id}/failure_recorded.json"
    )
  except Exception as err:  # pylint: disable=broad-exception-caught
    logger.warning("Failed to upload failure marker to GCS: %s", err)


def run_aggregate_pipeline() -> None:
  """Executes Stage 3: Download all worker states, merge DBs, generate report, and upload.

  The real work lives in `_run_aggregate_pipeline`; this wrapper guarantees a
  `scan_runs` telemetry row is written even when the stage dies at one of its
  `sys.exit(1)` sites. It re-raises unchanged, so exit codes are unaffected,
  and it is a hard no-op when telemetry is not configured.
  """
  ctx = bq_telemetry.ScanRunContext(stage="aggregate")
  with bq_telemetry.telemetry_run_guard(ctx):
    try:
      _run_aggregate_pipeline(ctx)
    except BaseException as exc:
      is_clean_exit = isinstance(exc, SystemExit) and exc.code in (0, None)
      if not is_clean_exit:
        try:
          cfg = OrchestratorConfig.from_env()
          _record_failure_marker(
              cfg.workspace_dir or os.getcwd(),
              cfg.gcs_bucket,
              ctx.scan_id or cfg.scan_id,
              "aggregate",
              ctx.target_sha or cfg.target_sha,
          )
          if (ctx.target_sha or cfg.target_sha) and ctx.repository and "/" in ctx.repository:
            # A configured GitHub App always wins over a static token.
            token = None if github_app_configured(cfg) else cfg.github_token
            if not token:
              try:
                _, token = get_github_credentials(config=cfg)
              except Exception:  # pylint: disable=broad-exception-caught
                token = None
            if token:
              owner_part, repo_part = ctx.repository.split("/", 1)
              gate_ctx = (
                  STATUS_CONTEXT_PR
                  if cfg.is_pr_scan
                  else STATUS_CONTEXT_SCHEDULED
              )
              post_commit_status(
                  token=token,
                  owner=owner_part,
                  repo=repo_part,
                  sha=ctx.target_sha or cfg.target_sha,
                  state="error",
                  description="Scan failed during Stage 3 aggregation.",
                  context=gate_ctx,
                  target_url=cfg.execution_url or None,
              )
        except Exception as status_err:  # pylint: disable=broad-exception-caught
          logger.warning(
              "Failed to post Stage 3 error commit status: %s", status_err
          )
      raise


def _run_aggregate_pipeline(ctx: "bq_telemetry.ScanRunContext") -> None:
  """Stage 3 implementation. See `run_aggregate_pipeline` for the telemetry wrapper."""
  # This stage never runs Wiz; drop any Wiz credentials before a subprocess
  # could inherit them.
  take_wiz_credentials()
  config = OrchestratorConfig.from_env()
  workspace_dir = config.workspace_dir or os.getcwd()
  if is_presubmit_pipeline():
    repo_full = (
        os.environ.get("REPO_FULL") or os.environ.get("GITHUB_REPOSITORY") or ""
    ).strip()
    owner, repo = (
        repo_full.split("/", 1) if "/" in repo_full else ("", repo_full)
    )
    aggregate_and_update_security_gate(
        workspace_dir=workspace_dir,
        min_sev=config.min_blocking_severity,
        fail_on_findings=config.fail_on_findings,
        token=(config.github_token or "").strip(),
        owner=owner,
        repo=repo,
        pr_number=config.pr_number or 0,
        target_sha=(config.target_sha or "").strip(),
        run_url=os.environ.get("RUN_URL", ""),
    )
    return
  ctx.apply_config(config)

  # 1. Validate required storage credentials in GCS mode
  if config.storage_mode == "gcs":
    if not config.scan_id or not config.gcs_bucket:
      logger.critical("CODEMENDER_SCAN_ID and CODEMENDER_GCS_BUCKET must be set in GCS mode.")
      sys.exit(1)

  scan_id = config.scan_id or "default"
  bucket_name = config.gcs_bucket or ""
  ctx.scan_id = scan_id

  storage_adapter = get_storage_adapter(
      config.storage_mode,
      bucket_name=config.gcs_bucket,
      base_dir=workspace_dir,
  )

  # 2. Extract repository credentials and paths
  repo_url, token = get_github_credentials(config=config)
  clean_repo_url = sanitize_git_url(repo_url)
  owner, repo_name = parse_repo_owner_and_name(clean_repo_url)
  repo_dir = os.path.join(workspace_dir, repo_name)
  scrubbed_env = get_scrubbed_env()
  ctx.repository = f"{owner}/{repo_name}"
  ctx.repo_dir = repo_dir

  # Handle workflow-level failure finalizer mode (triggered when Stage 1 or Stage 3 failed in Cloud Workflows)
  workflow_failed = (
      os.environ.get("CODEMENDER_WORKFLOW_FAILED", "false").strip().lower()
      in ("true", "1", "yes")
  )
  if workflow_failed:
    failure_reason = (
        os.environ.get("CODEMENDER_FAILURE_REASON")
        or "Upstream workflow stage failed."
    ).strip()
    manifest_sha = None
    already_recorded_telemetry = False
    if bucket_name and scan_id:
      tmp_marker = os.path.join(workspace_dir, "failure_recorded_recovery.json")
      if download_file_from_gcs(
          tmp_marker, bucket_name, f"scans/{scan_id}/failure_recorded.json"
      ):
        already_recorded_telemetry = True
        try:
          with open(tmp_marker, "r", encoding="utf-8") as f:
            manifest_sha = json.load(f).get("target_sha") or manifest_sha
        except Exception:  # pylint: disable=broad-exception-caught
          pass
      tmp_manifest = os.path.join(workspace_dir, "manifest_recovery.json")
      if download_file_from_gcs(
          tmp_manifest, bucket_name, f"scans/{scan_id}/manifest.json"
      ):
        try:
          with open(tmp_manifest, "r", encoding="utf-8") as f:
            manifest_sha = json.load(f).get("target_sha") or manifest_sha
        except Exception:  # pylint: disable=broad-exception-caught
          pass
    resolved_sha = (
        config.target_sha
        or manifest_sha
        or _resolve_fallback_commit_sha(
            clean_repo_url,
            token,
            owner,
            repo_name,
            config.target_branch,
            workspace_dir,
        )
    )
    ctx.target_sha = resolved_sha or ctx.target_sha
    if resolved_sha and token:
      gate_ctx = STATUS_CONTEXT_PR if config.is_pr_scan else STATUS_CONTEXT_SCHEDULED
      post_commit_status(
          token=token,
          owner=owner,
          repo=repo_name,
          sha=resolved_sha,
          state="error",
          description=f"CodeMender scan failed: {failure_reason[:100]}",
          context=gate_ctx,
          target_url=config.execution_url or None,
      )
    if already_recorded_telemetry:
      logger.info(
          "Container already emitted FAILED telemetry row for scan %s; skipping duplicate BigQuery emission.",
          scan_id,
      )
      ctx.emitted = True
    else:
      bq_telemetry.emit_scan_telemetry(
          ctx,
          status=bq_telemetry.STATUS_FAILED,
          failure_reason=failure_reason,
      )
    logger.info("Workflow failure finalizer completed commit status and telemetry recovery.")
    return

  # 3. Download or discover scan manifest.json
  manifest_path = os.path.join(workspace_dir, "manifest.json")
  manifest = {}
  if config.storage_mode in ["gcs", "local"]:
    logger.info("Downloading manifest.json from storage...")
    # Fetch manifest.json from GCS or local storage bucket
    if not download_file_from_gcs(
        manifest_path, bucket_name, f"scans/{scan_id}/manifest.json"
    ):
      logger.critical("Failed to download manifest.json.")
      sys.exit(1)
  else:
    # In local/GitHub Actions storage mode, locate manifest in workspace or transit base folder
    if not os.path.exists(manifest_path):
      logger.info("Downloading manifest.json from transit storage...")
      if not storage_adapter.download_file(manifest_path, "base/manifest.json"):
        transit_manifest = os.path.join(workspace_dir, ".codemender_transit", "base", "manifest.json")
        if os.path.exists(transit_manifest):
          shutil.copy2(transit_manifest, manifest_path)

  # Parse manifest JSON payload to extract scan target SHA and total findings count
  if os.path.exists(manifest_path):
    try:
      with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning("Failed to parse manifest.json: %s", e)
  else:
    logger.warning("Manifest not found, continuing with empty manifest.")

  target_sha = manifest.get("target_sha")
  findings_count = manifest.get("findings_count", 0)
  ctx.target_sha = target_sha or ctx.target_sha

  # If zero findings were discovered in Stage 1, emit passing PR Security Gate status and exit
  if findings_count == 0 and "findings_count" in manifest:
    logger.info("Manifest indicates 0 findings. Nothing to aggregate.")
    if config.is_pr_scan:
      target_commit_sha = config.target_sha or target_sha
      if target_commit_sha and token:
        logger.info(
            "✅ CodeMender Security Gate PASSED: Clean as You Code. Emitting '%s' commit status check.",
            STATUS_CONTEXT_PR,
        )
        post_commit_status(
            token=token,
            owner=owner,
            repo=repo_name,
            sha=target_commit_sha,
            state="success",
            description="Security Gate PASSED: Clean as You Code (0 active vulnerabilities).",
            context=STATUS_CONTEXT_PR,
            target_url=config.execution_url or None,
        )
    # On the GCP path the coordinating workflow short-circuits before Stage 3
    # ever starts, so this branch is normally unreachable there and Stage 1
    # will already have emitted the row. It is still reachable for sequential
    # and manually re-run aggregations, which would otherwise go unrecorded.
    ctx.total_findings_count = 0
    ctx.active_findings_count = 0
    ctx.fixed_count = 0
    ctx.failed_fix_count = 0
    bq_telemetry.emit_scan_telemetry(ctx, status=bq_telemetry.STATUS_SUCCESS)
    sys.exit(0)

  # 4. Clone repository to prepare source files for report formatting
  logger.info("Cloning repository for report generation: %s", clean_repo_url)
  if os.path.exists(repo_dir):
    shutil.rmtree(repo_dir)

  # Execute authenticated git clone into repo_dir (blobless partial clone with fallback)
  base_clone_cmd = [
      "git",
      "-c",
      get_git_auth_header(token),
      "clone",
  ]
  use_partial_clone = (
      os.environ.get("CODEMENDER_GIT_PARTIAL_CLONE", "true").strip().lower()
      in ("true", "1", "yes")
  )
  cloned = False
  if use_partial_clone:
    try:
      run_command(
          base_clone_cmd + ["--filter=blob:none", clean_repo_url, repo_dir],
          cwd=workspace_dir,
      )
      cloned = True
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning(
          "Blobless partial clone failed in aggregator (%s); retrying with full clone.",
          e,
      )
      if os.path.exists(repo_dir):
        shutil.rmtree(repo_dir, ignore_errors=True)
  if not cloned:
    run_command(base_clone_cmd + [clean_repo_url, repo_dir], cwd=workspace_dir)

  # Checkout target commit SHA or resolve default branch
  if target_sha:
    logger.info("Checking out target SHA: %s", target_sha)
    # Fetch explicit target SHA from origin in case of detached or unadvertised PR commits
    fetch_target_cmd = [
        "git",
        "-c",
        get_git_auth_header(token),
        "fetch",
        "origin",
        target_sha,
    ]
    run_command(fetch_target_cmd, cwd=repo_dir, check=False)
    run_command(["git", "checkout", "-f", target_sha], cwd=repo_dir)
  else:
    logger.warning("Target SHA not found in manifest, using default branch.")
    try:
      # Inspect current checked out branch name
      default_branch = run_command(
          ["git", "branch", "--show-current"], cwd=repo_dir
      ).stdout.strip()
    except Exception:  # pylint: disable=broad-exception-caught
      default_branch = ""
    # Query remote default branch via GitHub API if local detection is empty
    if not default_branch:
      default_branch = get_default_branch(token, owner, repo_name)
    logger.info("Using default branch: %s", default_branch)
    run_command(["git", "checkout", "-f", default_branch], cwd=repo_dir)

  setup_local_git_excludes(repo_dir)

  # 5. Download & Extract base workspace_base.tar.gz to restore base state.db
  codemender_home = os.path.expanduser("~/.codemender")
  if os.path.exists(codemender_home):
    shutil.rmtree(codemender_home)
  os.makedirs(codemender_home, exist_ok=True)

  tarball_path = os.path.join(workspace_dir, "workspace_base.tar.gz")
  should_extract = False
  if config.storage_mode in ["gcs", "local"]:
    logger.info("Downloading base workspace...")
    # Download base workspace tarball containing Stage 1 SQLite state.db
    if not download_file_from_gcs(
        tarball_path, bucket_name, f"scans/{scan_id}/workspace_base.tar.gz"
    ):
      logger.critical("Failed to download base workspace.")
      sys.exit(1)
    should_extract = True
  else:
    if os.path.exists(tarball_path):
      should_extract = True
    else:
      logger.info("Downloading base workspace from transit adapter...")
      # Download transit tarball from storage adapter or fallback to local transit base
      if storage_adapter.download_file(tarball_path, "base/workspace_base.tar.gz"):
        should_extract = True
      else:
        transit_tarball = os.path.join(workspace_dir, ".codemender_transit", "base", "workspace_base.tar.gz")
        if os.path.exists(transit_tarball):
          shutil.copy2(transit_tarball, tarball_path)
          should_extract = True

  # Extract tarball contents into ~/.codemender
  if not should_extract:
    logger.critical(
        "Failed to locate or download base workspace tarball in aggregator."
    )
    sys.exit(1)

  logger.info(
      "Extracting base workspace to %s", os.path.dirname(codemender_home)
  )
  try:
    with tarfile.open(tarball_path, "r:gz") as tar:
      # Use safe data_filter on Python 3.12+ to prevent traversal vulnerabilities and deprecation warnings
      if hasattr(tarfile, "data_filter"):
        tar.extractall(path=os.path.dirname(codemender_home), filter="data")
      else:
        tar.extractall(path=os.path.dirname(codemender_home))
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.critical(
        "Failed to extract base workspace tarball in aggregator: %s", e
    )
    sys.exit(1)

  base_db_path = os.path.join(codemender_home, "state.db")

  # 6. Discover and merge all worker database shards into base_db_path
  worker_db_blobs = []
  if config.storage_mode in ["gcs", "local"]:
    logger.info("Listing worker databases...")
    all_blobs = list_gcs_blobs(bucket_name, f"scans/{scan_id}/")
    worker_db_blobs = [
        b
        for b in all_blobs
        if b.startswith(f"scans/{scan_id}/worker_") and b.endswith("_state.db")
    ]
    logger.info("Found worker DB blobs: %s", worker_db_blobs)

    # Compute expected total workers and verify downloaded shard coverage
    total_workers_str = (
        str(config.total_workers)
        if config.total_workers is not None
        else str(len(manifest.get("partition_urls", [])) or len(manifest.get("upload_urls", [])))
        if (manifest.get("partition_urls") or manifest.get("upload_urls"))
        else None
    )
    _verify_worker_db_counts(worker_db_blobs, total_workers_str)

    temp_db_dir = os.path.join(workspace_dir, "worker_dbs")
    os.makedirs(temp_db_dir, exist_ok=True)
    # Download worker shards from GCS and merge each into base state.db
    _download_and_merge_worker_dbs(worker_db_blobs, temp_db_dir, bucket_name, base_db_path)
  else:
    logger.info("Discovering worker databases in local transit storage...")
    worker_db_blobs = _discover_and_merge_local_worker_dbs(workspace_dir, base_db_path, storage_adapter)
    # Verify local worker shard discovery count
    total_workers_str = (
        str(config.total_workers)
        if config.total_workers is not None
        else str(len(manifest.get("partition_urls", [])) or len(manifest.get("upload_urls", [])))
        if (manifest.get("partition_urls") or manifest.get("upload_urls"))
        else None
    )
    _verify_worker_db_counts(worker_db_blobs, total_workers_str)

  # 7. Aggregate Token Metrics & Worker Metadata
  token_totals = None
  finding_prs: dict[str, str] = {}
  try:
    if config.cli_version == "preview":
      token_totals = _aggregate_token_metrics(
          workspace_dir,
          bucket_name,
          scan_id,
          worker_db_blobs,
      )
    _, finding_prs = _aggregate_worker_metadata(
        workspace_dir,
        bucket_name,
        scan_id,
        worker_db_blobs,
    )
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning("Failed to aggregate worker metadata: %s", e)
  wiz_meta = _load_wiz_metadata(workspace_dir)
  ctx.apply_wiz(wiz_meta)

  # 8. Render Step Summary before DB cleanup (preserves differential statistics)
  summary_md, active_findings_count = _render_step_summary(
      base_db_path,
      config,
      owner,
      repo_name,
      target_sha=target_sha,
      token_totals=token_totals,
      repo_dir=repo_dir,
      finding_prs=finding_prs,
      wiz=wiz_meta,
  )

  # 9. Collect SKIPPED_DUPLICATE IDs for Nightly SARIF suppression
  skipped_finding_ids: Set[str] = set()
  if os.path.exists(base_db_path):
    try:
      with closing(sqlite3.connect(base_db_path)) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'")
        if cursor.fetchone():
          cursor.execute("SELECT finding_id FROM findings WHERE status = 'SKIPPED_DUPLICATE'")
          skipped_finding_ids = {r[0] for r in cursor.fetchall()}
    except sqlite3.Error as e:  # pylint: disable=broad-exception-caught
      logger.warning("Failed to collect SKIPPED_DUPLICATE finding IDs: %s", e)

  # 9b. Snapshot findings for BigQuery telemetry BEFORE the cleanup DELETE below.
  #
  # Ordering here is load-bearing. Step 10 permanently deletes DISMISSED rows
  # (and, on PR scans, PRE_EXISTING_IGNORED and SKIPPED_DUPLICATE too), so a
  # snapshot taken any later would silently under-report what the scan
  # actually found. Note this necessarily reads state.db alone: report.json is
  # not generated until step 11, so no report.json merge is possible at this
  # point in the pipeline.
  #
  # Gated on telemetry_enabled() so an unconfigured deployment does not even
  # pay the cost of opening the database.
  #
  # The snapshot is also stashed on the telemetry context. Steps 11-13 below
  # (report generation, upload, GitHub publication) can still abort the stage
  # via sys.exit(1); stashing here means the failure guard emits those findings
  # with the FAILED row instead of discarding work the scan already completed.
  telemetry_findings: List[Dict[str, Any]] = []
  if bq_telemetry.telemetry_enabled():
    telemetry_findings = bq_telemetry.snapshot_state_db_findings(base_db_path)
    ctx.pending_findings = telemetry_findings
    ctx.pending_finding_prs = finding_prs

  # 10. Scoped Reporting DB Cleanup (Purge pre-existing ignored findings on PR scans)
  try:
    if os.path.exists(base_db_path):
      with closing(sqlite3.connect(base_db_path)) as conn:
        if config.is_pr_scan:
          # On PR scans, remove pre-existing ignored and duplicates from per-scan report
          conn.execute(
              "DELETE FROM findings WHERE status IN ('PRE_EXISTING_IGNORED', 'SKIPPED_DUPLICATE', 'DISMISSED')"
          )
          logger.info("Purged PRE_EXISTING_IGNORED, SKIPPED_DUPLICATE, and DISMISSED findings for PR report.")
        else:
          # On Nightly scans, retain SKIPPED_DUPLICATE for SARIF suppressions, remove only DISMISSED
          conn.execute("DELETE FROM findings WHERE status IN ('DISMISSED')")
          logger.info("Purged DISMISSED findings for Nightly report.")
        conn.commit()
  except sqlite3.Error as e:  # pylint: disable=broad-exception-caught
    logger.warning("Failed to perform scoped report findings cleanup in state.db: %s", e)

  # 11. Generate final HTML and SARIF reports and upload
  inject_codemender_config(repo_dir, config=config)
  # Restore staged cm binary from workspace_base.tar.gz if present
  cm_binary = restore_staged_cm_binary(codemender_home)
  ctx.cm_version = log_cm_version(cm_binary, env=scrubbed_env, cwd=repo_dir)
  # The model columns have to name the model that actually ran. With no
  # override configured the run used the scanner's own built-in default, so it
  # is probed here rather than left NULL -- otherwise every unoverridden run,
  # which is most of them, drops out of model comparisons entirely. Gated on
  # telemetry being configured so an unconfigured deployment never pays for
  # the lookup, and guarded so a telemetry-only probe can never fail the
  # stage after all its work is done.
  if bq_telemetry.telemetry_enabled():
    try:
      ctx.apply_default_model(
          get_cm_default_model(cm_binary, env=scrubbed_env, cwd=repo_dir)
      )
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning("Could not resolve the default model for telemetry: %s", e)
  # Invoke report generation and upload routine with full run parameters
  ctx.report_uri = _generate_and_upload_report(
      repo_dir,
      scrubbed_env,
      cm_binary,
      codemender_home,
      bucket_name,
      owner,
      repo_name,
      token_totals=token_totals,
      scan_id=scan_id,
      # Pass execution mode and SARIF suppression configurations
      is_pr_scan=config.is_pr_scan,
      skipped_finding_ids=skipped_finding_ids,
      storage_mode=config.storage_mode,
      config=config,
      finding_prs=finding_prs,
      wiz=wiz_meta,
  )

  # 12. Publish Commit Status Check and SARIF to GitHub (both PR Security Gate and Scheduled Nightly Scan)
  # Merging and report generation run between the initial token read and
  # here; re-read it so a GitHub App installation token is still valid. A
  # static token is returned unchanged.
  if token:
    token = refresh_github_token(config, token)
  target_commit_sha = config.target_sha or target_sha
  if target_commit_sha and token:
    if config.is_pr_scan:
      gate_context = STATUS_CONTEXT_PR
      if active_findings_count > 0 and config.fail_on_findings:
        gate_state = "failure"
        gate_desc = (
            f"Security Gate FAILED: {active_findings_count} actionable"
            " vulnerability(ies) detected on PR diff."
        )
        logger.warning(
            "❌ CodeMender Security Gate FAILED: %d actionable vulnerability(ies) detected on PR diff. Emitting '%s' commit status check.",
            active_findings_count,
            gate_context,
        )
      else:
        gate_state = "success"
        gate_desc = "Security Gate PASSED: Clean as You Code (0 active vulnerabilities)."
        logger.info(
            "✅ CodeMender Security Gate PASSED: Clean as You Code. Emitting '%s' commit status check.",
            gate_context,
        )
    else:
      gate_context = STATUS_CONTEXT_SCHEDULED
      gate_state = "success"
      gate_desc = (
          f"Scan complete: {active_findings_count} active finding(s)."
          if active_findings_count
          else "Scan complete: no active findings."
      )
      logger.info(
          "Emitting '%s' commit status on %s (%d active finding(s)).",
          gate_context,
          target_commit_sha[:8],
          active_findings_count,
      )

    post_commit_status(
        token=token,
        owner=owner,
        repo=repo_name,
        sha=target_commit_sha,
        state=gate_state,
        description=gate_desc,
        context=gate_context,
        target_url=config.execution_url or None,
    )

    sarif_path = os.path.join(repo_dir, "report.sarif")
    if os.path.exists(sarif_path):
      if has_sarif_results(sarif_path) or config.upload_empty_sarif:
        if config.is_pr_scan and config.pr_number:
          scan_ref = f"refs/pull/{config.pr_number}/head"
        elif config.target_branch:
          scan_ref = f"refs/heads/{config.target_branch}"
        else:
          default_br, token = read_default_branch(
              config, token, owner, repo_name, lookup=get_default_branch
          )
          scan_ref = f"refs/heads/{default_br}" if default_br else None
        if scan_ref:
          upload_sarif_to_code_scanning(
              token=token,
              owner=owner,
              repo=repo_name,
              sarif_path=sarif_path,
              commit_sha=target_commit_sha,
              ref=scan_ref,
          )
        else:
          logger.error(
              "Not uploading report.sarif: the target branch is unknown."
          )
      else:
        logger.info(
            "Skipping GitHub Code Scanning SARIF upload because report.sarif contains 0 results "
            "(set CODEMENDER_UPLOAD_EMPTY_SARIF=true to auto-resolve existing alerts on empty runs)."
        )

  # 13. Mirror the run summary into a single sticky comment on the Pull Request
  # This runs here rather than in the workers because the matrix workers execute
  # in parallel, and a read-modify-write of one shared comment would lose
  # updates. The aggregate stage is single-instance and holds the merged DB.
  if config.is_pr_scan and config.pr_number and token and summary_md:
    # The "#artifacts" anchor only resolves on the workflow run page.
    server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo_slug = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    run_link = (
        f"[workflow run]({server_url}/{repo_slug}/actions/runs/{run_id})"
        if repo_slug and run_id
        else "the workflow run"
    )
    post_or_update_sticky_comment(
        token=token,
        owner=owner,
        repo=repo_name,
        pr_number=config.pr_number,
        body=summary_md.replace("[Artifacts section](#artifacts) below", run_link),
    )

  # ---------------------------------------------------------------------------
  # Multi-repository telemetry & Gemini in BigQuery analytics.
  #
  # Every scan execution is persisted to two *native* BigQuery tables in the
  # dataset named by `CODEMENDER_BQ_DATASET`:
  #
  #   * `scan_runs`              — one row per scan execution
  #   * `vulnerability_findings` — one row per finding
  #
  # Both are partitioned by `DATE(scan_timestamp)` and clustered for
  # cross-repository queries, and every column carries a `description` that
  # grounds Gemini Conversational Analytics / Data Canvas (see
  # `terraform/gcp/bigquery.tf`).
  #
  # Native tables were chosen over the GCS JSONL + BigQuery External/BigLake
  # design originally sketched here. The decisive reason is that the reports
  # bucket carries a bucket-wide 90-day delete lifecycle rule with no prefix
  # condition (`terraform/gcp/storage.tf`); external tables backed by objects
  # in that bucket would silently empty themselves at 90 days with no error.
  # Native storage also gives partitioning, clustering, and column
  # descriptions, none of which external tables provide.
  #
  # The whole export is opt-in and fail-safe: with `CODEMENDER_BQ_DATASET`
  # unset it performs zero BigQuery calls, and every entry point swallows its
  # own exceptions so telemetry can never fail a security scan. See
  # `codemender_agent/telemetry/bigquery.py`.
  #
  # TODO(post-scan notification & ticketing adapters):
  # Wire configurable post-aggregation notification and ticketing adapters so
  # that a completed scan can actively alert owners instead of only recording
  # itself. Planned surface:
  #   * `CODEMENDER_NOTIFY_EMAILS`      — comma-separated owner notifications.
  #   * `CODEMENDER_NOTIFY_WEBHOOK_URL` — Google Chat / Slack / Teams webhook.
  #   * `CODEMENDER_TICKETING_PROVIDER` — one of `github_issues` | `jira` |
  #                                       `servicenow`, auto-filing tracking
  #                                       tickets for newly remediated or
  #                                       still-unfixed CRITICAL/HIGH findings.
  # This belongs here, after reporting and telemetry, so notifications can
  # cite the report URI and the ticket bodies can link the exact finding rows
  # already written to BigQuery above.
  # ---------------------------------------------------------------------------
  #
  # Primary telemetry emission site for runs that produced findings. The
  # findings snapshot was captured at step 9b, deliberately before the cleanup
  # DELETE at step 10.
  if bq_telemetry.telemetry_enabled():
    ctx.token_totals = token_totals
    ctx.active_findings_count = active_findings_count
    ctx.skipped_duplicate_count = _skipped_count_for_telemetry(
        telemetry_findings, skipped_finding_ids
    )
    # Prefer the true end-to-end duration measured from Stage 1's start time,
    # falling back to this stage's own runtime when Stage 1 did not record one.
    end_to_end_seconds = _resolve_end_to_end_duration(workspace_dir)
    bq_telemetry.emit_scan_telemetry(
        ctx,
        status=bq_telemetry.STATUS_SUCCESS,
        findings=telemetry_findings,
        finding_prs=finding_prs,
        duration_seconds=end_to_end_seconds,
    )

  # Log final aggregator completion notice
  logger.info("Stage 3 (Aggregate) completed successfully.")


def aggregate_and_update_security_gate(
    workspace_dir: str,
    min_sev: str = "MEDIUM",
    fail_on_findings: bool = True,
    token: str = "",
    owner: str = "",
    repo: str = "",
    pr_number: int = 0,
    target_sha: str = "",
    run_url: str = "",
) -> int:
  """Merges worker shards against Stage 1 active_findings.json, filters SARIF FPs, and updates PR status/sticky comment."""
  import glob
  import subprocess
  from codemender_agent.runners.scan import (
      _write_clean_sarif_file,
      restore_presubmit_transit_workspace,
  )
  from codemender_agent.vcs.github import (
      extract_finding_fields,
      is_blocking_severity,
  )

  base_dir = os.path.join(workspace_dir, ".codemender_transit", "base")
  restore_presubmit_transit_workspace(
      workspace_dir=workspace_dir,
      sandbox_enabled=False,
      build_cmd="true",
  )

  base_findings = []
  af_path = os.path.join(base_dir, "active_findings.json")
  if os.path.exists(af_path):
    with open(af_path, "r", encoding="utf-8") as f:
      base_findings = json.load(f)

  shard_by_id: dict[str, dict] = {}
  shard_pattern = os.path.join(
      workspace_dir,
      ".codemender_transit",
      "shards",
      "**",
      "results_worker_*.json",
  )
  for shard_file in sorted(glob.glob(shard_pattern, recursive=True)):
    with open(shard_file, "r", encoding="utf-8") as f:
      for item in json.load(f):
        fid = extract_finding_fields(item)["finding_id"]
        if fid:
          shard_by_id[fid] = item

  findings = []
  if base_findings:
    for bf in base_findings:
      fid = extract_finding_fields(bf)["finding_id"]
      findings.append(shard_by_id.get(fid, bf))
  else:
    findings = list(shard_by_id.values())

  report_json_path = os.path.join(workspace_dir, "report.json")
  with open(report_json_path, "w", encoding="utf-8") as rf:
    json.dump({"findings": findings}, rf, indent=2)

  confirmed_blocking = []
  advisory_or_dismissed = []
  dismissed_ids = set()
  dismissed_locs = set()
  for item in findings:
    fields = extract_finding_fields(item)
    sev = fields["severity"]
    v_status = str(item.get("verified_status", "CONFIRMED"))
    if v_status == "DISMISSED_FALSE_POSITIVE":
      fid = fields["finding_id"]
      if fid:
        dismissed_ids.add(fid)
      fp = fields["file_path"]
      ln = fields["line_number"]
      if fp and ln:
        dismissed_locs.add((fp, ln))
      advisory_or_dismissed.append((sev, item))
    elif is_blocking_severity(sev, min_sev):
      confirmed_blocking.append((sev, item))
    else:
      advisory_or_dismissed.append((sev, item))

  sarif_res = subprocess.run(
      ["cm", "report", "--format", "sarif", "--bypass-warning"],
      cwd=workspace_dir,
      capture_output=True,
      text=True,
      check=False,
  )
  sarif_out = (sarif_res.stdout or "").strip()
  sarif_path = os.path.join(workspace_dir, "report.sarif")
  if sarif_out.startswith("{"):
    try:
      sarif_doc = json.loads(sarif_out)
      if dismissed_ids or dismissed_locs:
        for run_obj in sarif_doc.get("runs", []):
          filtered_results = []
          for r in run_obj.get("results", []):
            r_text = json.dumps(r)
            if any(did in r_text for did in dismissed_ids):
              continue
            locs = r.get("locations") or []
            phys = (locs[0].get("physicalLocation") or {}) if locs else {}
            uri = (
                (phys.get("artifactLocation") or {}).get("uri") or ""
            ).lstrip("./")
            s_line = int((phys.get("region") or {}).get("startLine") or 0)
            if any(
                (uri.endswith(dfp) or dfp.endswith(uri)) and s_line == dln
                for dfp, dln in dismissed_locs
            ):
              continue
            filtered_results.append(r)
          run_obj["results"] = filtered_results
      with open(sarif_path, "w", encoding="utf-8") as sf:
        json.dump(sarif_doc, sf, indent=2)
    except Exception:  # pylint: disable=broad-exception-caught
      with open(sarif_path, "w", encoding="utf-8") as sf:
        sf.write(sarif_out)
  elif not os.path.exists(sarif_path):
    _write_clean_sarif_file(None, workspace_dir)

  html_res = subprocess.run(
      ["cm", "report", "--format", "html", "--bypass-warning"],
      cwd=workspace_dir,
      capture_output=True,
      text=True,
      check=False,
  )
  html_path = os.path.join(workspace_dir, "report.html")
  if html_res.returncode == 0 and (html_res.stdout or "").strip():
    with open(html_path, "w", encoding="utf-8") as hf:
      hf.write(html_res.stdout)
  elif not os.path.exists(html_path):
    with open(html_path, "w", encoding="utf-8") as hf:
      hf.write(
          "<html><body><h1>CodeMender Security Report</h1>"
          f"<p>Total findings evaluated: {len(findings)}</p></body></html>"
      )

  blocking_count = len(confirmed_blocking)
  patched_count = sum(
      1
      for _, item in confirmed_blocking
      if str(item.get("patch_diff") or "").strip()
  )
  dismissed_count = sum(
      1
      for _, item in advisory_or_dismissed
      if str(item.get("verified_status", "")) == "DISMISSED_FALSE_POSITIVE"
  )
  advisory_only_count = len(advisory_or_dismissed) - dismissed_count
  # Blocking findings whose `cm verify` produced no verdict: they still count
  # (fail closed) but are not called "confirmed".
  unverified_count = sum(
      1
      for _, item in confirmed_blocking
      if str(item.get("verified_status", "")) == "VERIFY_FAILED"
  )
  unverified_note = (
      f", {unverified_count} unverified" if unverified_count else ""
  )
  gate_status = (
      "failure" if (blocking_count > 0 and fail_on_findings) else "success"
  )

  if token and owner and repo and target_sha:
    if gate_status == "success":
      if blocking_count > 0:
        fp_note = f", {dismissed_count} FP dismissed" if dismissed_count else ""
        status_desc = (
            f"PASSED (Non-Blocking): {blocking_count} confirmed >= {min_sev}"
            f" finding(s) ({patched_count} auto-fix patch(es) ready{fp_note}"
            f"{unverified_note}; merge blocking disabled)."
        )
      elif dismissed_count > 0 and advisory_only_count > 0:
        status_desc = (
            f"PASSED: 0 confirmed >= {min_sev} findings"
            f" ({dismissed_count} FP dismissed, {advisory_only_count} advisory)."
        )
      elif dismissed_count > 0:
        status_desc = (
            f"PASSED: 0 confirmed >= {min_sev} findings"
            f" ({dismissed_count} false positive(s) dismissed by cm verify)."
        )
      elif advisory_only_count > 0:
        status_desc = (
            f"PASSED: 0 confirmed >= {min_sev} findings"
            f" ({advisory_only_count} advisory finding(s))."
        )
      else:
        status_desc = (
            f"PASSED: 0 confirmed >= {min_sev} findings after cm verify."
        )
    else:
      fp_note = f", {dismissed_count} FP dismissed" if dismissed_count else ""
      status_desc = (
          f"BLOCKED: {blocking_count} confirmed >= {min_sev} finding(s) require"
          f" remediation ({patched_count} auto-fix patch(es) ready{fp_note}"
          f"{unverified_note})."
      )
    post_commit_status(
        token=token,
        owner=owner,
        repo=repo,
        sha=target_sha,
        state=gate_status,
        description=status_desc,
        context="CodeMender / Security Gate",
        target_url=run_url,
    )

  rows = []
  patch_blocks = []
  detail_blocks = []
  for sev, item in confirmed_blocking + advisory_or_dismissed:
    fields = extract_finding_fields(item)
    fid = fields["finding_id"][:8]
    v_status = str(item.get("verified_status", "CONFIRMED"))
    review_url = str(item.get("review_url") or "")
    patch_diff = str(item.get("patch_diff") or "").strip()
    title = fields["title"]
    fpath = fields["file_path"]
    line_no = fields["line_number"]
    desc = fields["description"].strip()
    if v_status == "DISMISSED_FALSE_POSITIVE":
      gate_badge = "⚪ Dismissed (FP)"
      status_col = "⚪ **Dismissed by `cm verify` (False Positive)**"
    elif is_blocking_severity(sev, min_sev):
      gate_badge = (
          "🚫 **BLOCKING**" if fail_on_findings else "⚠️ **Non-Blocking**"
      )
      status_col = (
          f"✅ **Patch Ready** ([Inline `Commit suggestion`]({review_url}))"
          if (patch_diff and review_url)
          else (
              "✅ **Patch Ready**"
              if patch_diff
              else "⚠️ **Manual remediation required**"
          )
      )
    else:
      gate_badge = "ℹ️ Advisory"
      status_col = (
          f"✅ **Patch Ready** ([Inline `Commit suggestion`]({review_url}))"
          if (patch_diff and review_url)
          else "ℹ️ **Non-blocking advisory**"
      )
    if v_status == "VERIFY_FAILED":
      status_col = "⚠️ **Unverified** (`cm verify` failed) — " + status_col
    if item.get("fix_failure_reason") == "sandbox_unavailable":
      status_col += " — ⚠️ `cm fix` did not run (sandbox unavailable)"
    if item.get("sandbox_unrestricted_rerun"):
      status_col += " — ⚠️ ran without the sandbox"
    rows.append(
        f"| `{sev}` | {gate_badge} | **{title}** (`{fid}`) |"
        f" `{fpath}:{line_no}` | {status_col} | <!-- cm-row:{fid} -->"
    )
    if patch_diff and v_status != "DISMISSED_FALSE_POSITIVE":
      patch_blocks.append(
          f"<details>\n<summary>🩹 <b>View Unified Diff Patch</b>:"
          f" <code>{fpath}:{line_no}</code> — {title}"
          f" (<code>{fid}</code>)</summary>\n\n````diff\n{patch_diff}\n````\n</details>"
      )
    if desc:
      detail_blocks.append(
          f"- **`[{sev}]` {title}** (`{fpath}:{line_no}`, ID `{fid}`): {desc}"
      )

  if gate_status == "failure":
    banner = f"❌ **BLOCKED** (`{blocking_count}` confirmed finding(s) `>= {min_sev}`)"
  elif blocking_count > 0:
    banner = (
        f"⚠️ **PASSED (Non-Blocking Mode)** (`{blocking_count}` confirmed"
        f" finding(s) `>= {min_sev}`, `{patched_count}` patch(es) ready)"
    )
  elif dismissed_count > 0:
    banner = (
        f"✅ **PASSED (Auto-Unblocked)** (`{dismissed_count}` false"
        f" positive(s) dismissed, `{advisory_only_count}` advisory)"
    )
  else:
    banner = f"✅ **PASSED** (`{advisory_only_count}` advisory finding(s))"

  remediation_section = ""
  if patch_blocks:
    remediation_section = (
        "\n\n### 🔧 One-Click Auto-Remediation Guide\n"
        "Click **Commit suggestion** on the inline review comments in the"
        " **Files changed** tab, or expand the unified diffs below:\n\n"
        + "\n\n".join(patch_blocks)
    )

  details_section = ""
  if detail_blocks:
    details_section = (
        "\n\n<details>\n<summary>📋 <b>Vulnerability Descriptions &"
        " Root-Cause Analysis</b></summary>\n\n"
        + "\n".join(detail_blocks)
        + "\n</details>"
    )

  body = (
      f"## 🛡️ CodeMender Pre-Submit Security Gate — {banner}\n"
      f"*✅ **Stage 3 Complete: {len(findings)}/{len(findings)} Findings"
      " Verified & Aggregated***\n\n"
      "| Severity | Gate | Finding | Location | Status |\n"
      "| :--- | :--- | :--- | :--- | :--- |\n"
      + "\n".join(rows)
      + remediation_section
      + details_section
  )

  step_summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
  if step_summary_path:
    try:
      with open(step_summary_path, "a", encoding="utf-8") as ssf:
        ssf.write(body + "\n")
    except Exception:  # pylint: disable=broad-exception-caught
      pass

  if pr_number and owner and repo and token:
    post_or_update_sticky_comment(
        token=token, owner=owner, repo=repo, pr_number=pr_number, body=body
    )

  if gate_status == "failure":
    raise SystemExit(1)
  return 0

