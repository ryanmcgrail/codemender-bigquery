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

"""Weakness taxonomy used to label imported findings and match duplicates.

Imported findings are labelled "<Weakness name> (CWE-nnn)", for example
"SQL Injection (CWE-89)". Duplicate detection against CodeMender's own
findings works at the level of weakness *families*: CodeMender may call a bug
CWE-22 where an external scanner says CWE-23, and it usually names the class
("Path Traversal") rather than giving a CWE at all.
"""

import re
from typing import FrozenSet, Iterable, Optional, Set

# Short, human-readable names for the weaknesses SAST tools commonly report.
CWE_NAMES = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-23": "Path Traversal",
    "CWE-36": "Path Traversal",
    "CWE-73": "External Control of File Name or Path",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-Site Scripting",
    "CWE-88": "Argument Injection",
    "CWE-89": "SQL Injection",
    "CWE-90": "LDAP Injection",
    "CWE-91": "XML Injection",
    "CWE-93": "CRLF Injection",
    "CWE-94": "Code Injection",
    "CWE-95": "Eval Injection",
    "CWE-113": "HTTP Response Splitting",
    "CWE-117": "Log Injection",
    "CWE-183": "Permissive Allowlist",
    "CWE-200": "Sensitive Information Exposure",
    "CWE-209": "Information Exposure Through Error Messages",
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-259": "Hard-coded Password",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Broken or Risky Cryptographic Algorithm",
    "CWE-328": "Weak Hash",
    "CWE-330": "Insufficiently Random Values",
    "CWE-338": "Weak Pseudo-Random Number Generator",
    "CWE-346": "Origin Validation Error",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-362": "Race Condition",
    "CWE-377": "Insecure Temporary File",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-434": "Unrestricted File Upload",
    "CWE-470": "Unsafe Reflection",
    "CWE-489": "Active Debug Code",
    "CWE-502": "Insecure Deserialization",
    "CWE-521": "Weak Password Requirements",
    "CWE-532": "Sensitive Information in Log Files",
    "CWE-552": "Files Accessible to External Parties",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-614": "Sensitive Cookie Without Secure Attribute",
    "CWE-639": "Insecure Direct Object Reference",
    "CWE-643": "XPath Injection",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-776": "XML Entity Expansion",
    "CWE-798": "Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-915": "Mass Assignment",
    "CWE-916": "Weak Password Hash",
    "CWE-917": "Expression Language Injection",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-942": "Permissive CORS Policy",
    "CWE-943": "NoSQL Injection",
    "CWE-1004": "Sensitive Cookie Without HttpOnly Flag",
    "CWE-1321": "Prototype Pollution",
    "CWE-1333": "Regular Expression Denial of Service (ReDoS)",
    "CWE-1336": "Template Injection",
}

# Weakness families: CWEs in the same family describe the same underlying bug
# class for de-duplication purposes.
_FAMILY_MEMBERS = {
    "path_traversal": {"CWE-22", "CWE-23", "CWE-36", "CWE-73"},
    "command_injection": {"CWE-77", "CWE-78", "CWE-88"},
    "sql_injection": {"CWE-89", "CWE-564", "CWE-943"},
    "xss": {"CWE-79", "CWE-80", "CWE-83"},
    "code_injection": {"CWE-94", "CWE-95", "CWE-917", "CWE-1336"},
    "xxe": {"CWE-611", "CWE-776", "CWE-827"},
    "deserialization": {"CWE-502"},
    "ssrf": {"CWE-918"},
    "open_redirect": {"CWE-601"},
    "csrf": {"CWE-352"},
    "cors": {"CWE-942", "CWE-346"},
    "header_injection": {"CWE-93", "CWE-113"},
    "log_injection": {"CWE-117"},
    "hardcoded_credentials": {"CWE-259", "CWE-798"},
    "weak_crypto": {"CWE-326", "CWE-327", "CWE-328", "CWE-916"},
    "file_upload": {"CWE-434"},
    "access_control": {"CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863"},
}
CWE_FAMILY = {
    cwe: family for family, members in _FAMILY_MEMBERS.items() for cwe in members
}

# Keywords that identify a family from free text (CodeMender's vuln_type and
# title rarely carry a CWE). Checked in order; the first match wins per entry.
_KEYWORD_FAMILIES = (
    (("path traversal", "directory traversal", "zip slip"), "path_traversal"),
    (("command injection", "os command", "shell injection"), "command_injection"),
    (("sql injection", "nosql injection"), "sql_injection"),
    (("cross-site scripting", "cross site scripting", "xss"), "xss"),
    (
        (
            "code injection",
            "expression language",
            "spel injection",
            "template injection",
            "eval injection",
            "remote code execution",
        ),
        "code_injection",
    ),
    (("xml external entit", "xxe"), "xxe"),
    (("deserializ",), "deserialization"),
    (("server-side request forgery", "server side request forgery", "ssrf"), "ssrf"),
    (("open redirect", "unvalidated redirect"), "open_redirect"),
    (("cross-site request forgery", "cross site request forgery", "csrf"), "csrf"),
    (("cors", "cross-origin resource sharing"), "cors"),
    (("response splitting", "header injection", "crlf"), "header_injection"),
    (("log injection", "log forging"), "log_injection"),
    (("hard-coded", "hardcoded"), "hardcoded_credentials"),
    (("weak crypto", "weak hash", "broken crypto", "insecure hash"), "weak_crypto"),
    (("file upload",), "file_upload"),
    (
        (
            "access control",
            "authorization bypass",
            "missing authorization",
            "insecure direct object",
        ),
        "access_control",
    ),
)


def _keyword_pattern(keyword: str) -> str:
  # Short acronyms must match as whole words ("xss", "cors"); longer phrases
  # may match as word prefixes ("deserializ" -> "deserialization").
  escaped = re.escape(keyword)
  return rf"\b{escaped}\b" if len(keyword) <= 4 else rf"\b{escaped}"


_KEYWORD_FAMILY_PATTERNS = tuple(
    (re.compile("|".join(_keyword_pattern(k) for k in keywords)), family)
    for keywords, family in _KEYWORD_FAMILIES
)

_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)


def normalize_cwe(value: Optional[str]) -> Optional[str]:
  """Returns 'CWE-nnn' for any common spelling, or None."""
  if value is None:
    return None
  text = str(value).strip()
  if text.isdigit():
    return f"CWE-{int(text)}"
  match = _CWE_RE.search(text)
  return f"CWE-{int(match.group(1))}" if match else None


def cwes_in_text(*texts: Optional[str]) -> Set[str]:
  """Every CWE mentioned in the given strings."""
  found: Set[str] = set()
  for text in texts:
    if text:
      found.update(f"CWE-{int(m)}" for m in _CWE_RE.findall(str(text)))
  return found


def families_for(
    cwes: Iterable[str] = (), *texts: Optional[str]
) -> FrozenSet[str]:
  """Weakness families implied by CWEs and/or free-text names."""
  families = {CWE_FAMILY[c] for c in cwes if c in CWE_FAMILY}
  for text in texts:
    lowered = (text or "").lower()
    if not lowered:
      continue
    for pattern, family in _KEYWORD_FAMILY_PATTERNS:
      if pattern.search(lowered):
        families.add(family)
  return frozenset(families)


def weakness_label(cwe: Optional[str], fallback_name: Optional[str] = None) -> str:
  """Builds the display label, e.g. 'SQL Injection (CWE-89)'."""
  cwe = normalize_cwe(cwe)
  fallback = " ".join((fallback_name or "").split())
  if cwe:
    name = CWE_NAMES.get(cwe) or fallback or "Security Weakness"
    return f"{name} ({cwe})"
  return fallback or "Security Weakness"
