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

"""GitHub App installation token minting for CodeMender Agent.

A GitHub App authenticates in two steps:

1. The App signs a short-lived JWT (RS256, at most 10 minutes) with its
   private key. The JWT only grants access to the App's own `/app/...`
   endpoints.
2. The App exchanges the JWT for an installation access token, scoped to one
   installation (an organization or user account) and, here, to the single
   repository being scanned. Installation tokens expire after one hour.

Scans can run for many hours, so a token minted when the container starts
can expire long before the fix branches are pushed. `InstallationTokenProvider`
caches the current token and mints a fresh one once less than
`REFRESH_MARGIN_SECONDS` of its lifetime remains; callers re-read the token
right before each batch of GitHub calls instead of holding on to one string.
When no usable token is cached, transient mint failures are retried with
backoff for up to `MINT_RETRY_BUDGET_SECONDS`, and a token GitHub rejects
with HTTP 401 can be discarded with `invalidate_installation_token` so the
next read mints a new one.

Installation tokens are used exactly like a personal access token: as a
`Bearer` token for the REST API and as the `x-access-token` password for git
over HTTPS. Branch pushes, pull requests, comments and commit statuses made
with them are attributed to the App's bot account (`<app-slug>[bot]`). The
fix commits themselves carry the git identity the runners configure locally;
by default that is the same bot account, resolved by `get_app_bot_identity`
(see `codemender_agent.vcs.git.resolve_git_identity`).

Minting a token is not a write to the repository, so it also happens in a dry
run (CODEMENDER_DRY_RUN): the clone still needs credentials.

`google-auth` (a dependency of the Google Cloud client libraries) is only
imported when a JWT is actually signed, so deployments that authenticate with
a static token never load it.
"""

import dataclasses
import datetime
import logging
import os
import random
import re
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple
import urllib.parse

import requests

logger = logging.getLogger("codemender-orchestrator")

GITHUB_API_URL = "https://api.github.com"

# GitHub rejects App JWTs whose lifetime exceeds 10 minutes. `iat` is
# backdated to absorb clock drift between this host and GitHub.
JWT_CLOCK_SKEW_SECONDS = 60
JWT_LIFETIME_SECONDS = 9 * 60

# Mint a new installation token once less than this much lifetime remains.
# Installation tokens live for 60 minutes, so a token is reused for roughly
# the first 50 minutes and replaced after that. The margin must comfortably
# exceed the longest run of GitHub calls made with one token read (a push
# followed by pull request creation and a comment).
REFRESH_MARGIN_SECONDS = 10 * 60

# Operators can override the margin, for example to force re-mints during a
# short run and prove the refresh path live. The value is clamped so a token
# is never used with less than five minutes left, and is not re-minted more
# often than every five minutes.
REFRESH_MARGIN_ENV_VAR = "CODEMENDER_GITHUB_TOKEN_REFRESH_MARGIN_SECONDS"
MIN_REFRESH_MARGIN_SECONDS = 5 * 60
MAX_REFRESH_MARGIN_SECONDS = 55 * 60

# When a refresh fails, a cached token with at least this much lifetime left
# is still returned so that a transient GitHub outage does not fail a scan
# that holds a perfectly usable token.
MIN_USABLE_SECONDS = 60

# When no usable token is cached (typically right after a phase that ran for
# hours), a failed mint is retried with exponential backoff for up to this
# long before the stage gives up. Only transient failures are retried:
# network errors, HTTP 5xx, 429 and rate-limited 403 responses.
MINT_RETRY_BUDGET_SECONDS = 8 * 60
MINT_RETRY_INITIAL_DELAY_SECONDS = 5
MINT_RETRY_MAX_DELAY_SECONDS = 2 * 60
# Safety net in case the clock does not advance (it always does in
# production); the budget above is what normally ends the retries.
MINT_RETRY_MAX_ATTEMPTS = 20
# After the retry budget runs out, later reads make a single attempt for this
# long, so a sustained outage costs one retry budget rather than one per
# token read (the failure handlers and each Stage 2 finding read it too).
MINT_RETRY_COOLDOWN_SECONDS = 15 * 60

# GitHub can answer 401 for a few seconds after an installation token is
# minted, until the token has replicated. A request that is retried with a
# token minted to replace a rejected one first waits until the token is at
# least this old, so replication lag is not mistaken for a bad token.
NEW_TOKEN_SETTLE_SECONDS = 5

# Fallback lifetime used only if GitHub omits or garbles `expires_at`. Kept
# well under the documented 60 minutes so the token is refreshed early.
_FALLBACK_TOKEN_LIFETIME_SECONDS = 30 * 60

_REQUEST_TIMEOUT_SECONDS = 30

_PRIVATE_KEY_MARKER = "PRIVATE KEY-----"

_RATE_LIMIT_MARKERS = ("rate limit", "abuse detection")


class GitHubAppAuthError(RuntimeError):
  """A GitHub App configuration or authentication failure.

  Deliberately not a `requests.RequestException`, so the retry decorator does
  not retry failures that cannot succeed on a second attempt (a malformed key,
  an App that is not installed on the repository, a revoked App, ...).
  """


class GitHubAppTransientError(GitHubAppAuthError):
  """A GitHub App request failed in a way that may succeed if retried.

  Raised for HTTP 5xx, 429 and rate-limited 403 responses.

  Attributes:
    retry_after: Seconds GitHub asked the client to wait, when it said so.
  """

  def __init__(self, message: str, retry_after: Optional[float] = None):
    super().__init__(message)
    self.retry_after = retry_after


def resolve_refresh_margin(raw: Optional[str] = None) -> float:
  """Returns the refresh margin in seconds, honoring the env override.

  Args:
    raw: The override value; read from `REFRESH_MARGIN_ENV_VAR` when None.

  An empty or unparseable override falls back to `REFRESH_MARGIN_SECONDS`.
  Out-of-range values are clamped to
  [`MIN_REFRESH_MARGIN_SECONDS`, `MAX_REFRESH_MARGIN_SECONDS`].
  """
  value = os.environ.get(REFRESH_MARGIN_ENV_VAR, "") if raw is None else raw
  value = (value or "").strip()
  if not value:
    return float(REFRESH_MARGIN_SECONDS)
  try:
    margin = float(value)
  except ValueError:
    margin = float("nan")
  if margin != margin or margin in (float("inf"), float("-inf")):
    logger.warning(
        "Ignoring %s=%r: not a finite number. Using the default of %d"
        " seconds.",
        REFRESH_MARGIN_ENV_VAR,
        value,
        REFRESH_MARGIN_SECONDS,
    )
    return float(REFRESH_MARGIN_SECONDS)
  clamped = min(
      max(margin, MIN_REFRESH_MARGIN_SECONDS), MAX_REFRESH_MARGIN_SECONDS
  )
  if clamped != margin:
    logger.warning(
        "%s=%s is outside [%d, %d]; using %d seconds.",
        REFRESH_MARGIN_ENV_VAR,
        value,
        MIN_REFRESH_MARGIN_SECONDS,
        MAX_REFRESH_MARGIN_SECONDS,
        int(clamped),
    )
  return float(clamped)


def normalize_private_key(raw_key: str) -> str:
  """Returns the PEM private key with real newlines.

  Keys pasted into a single-line field often arrive with literal `\\n`
  sequences instead of newlines; those are converted back. Surrounding
  whitespace and quotes are stripped.
  """
  key = (raw_key or "").strip().strip("'\"").strip()
  if "\n" not in key and "\\n" in key:
    key = key.replace("\\n", "\n")
  key = key.replace("\r\n", "\n")
  return key + "\n" if key and not key.endswith("\n") else key


@dataclasses.dataclass(frozen=True)
class GitHubAppCredentials:
  """The static identity of a GitHub App installation.

  Attributes:
    app_id: The App ID (or client ID) shown on the App's settings page. Used
      as the JWT issuer.
    private_key: The App's PEM-encoded RSA private key. Never logged.
    installation_id: The installation to mint tokens for. When None, it is
      looked up from the repository being scanned, which requires the App to
      be installed on that repository.
  """

  app_id: str
  private_key: str = dataclasses.field(repr=False)
  installation_id: Optional[int] = None

  @classmethod
  def from_values(
      cls,
      app_id: Optional[str],
      private_key: Optional[str],
      installation_id: Optional[str] = None,
  ) -> "GitHubAppCredentials":
    """Validates raw configuration values and builds the credentials.

    Raises:
      GitHubAppAuthError: A required value is missing or malformed. The
        message names the environment variable to fix but never echoes the
        private key.
    """
    clean_app_id = (app_id or "").strip()
    if not clean_app_id:
      raise GitHubAppAuthError(
          "GITHUB_APP_ID is required when GitHub App authentication is"
          " configured."
      )
    if any(ch.isspace() for ch in clean_app_id):
      raise GitHubAppAuthError("GITHUB_APP_ID must not contain whitespace.")

    key = normalize_private_key(private_key or "")
    if not key:
      raise GitHubAppAuthError(
          "GITHUB_APP_PRIVATE_KEY is required when GitHub App authentication"
          " is configured."
      )
    if _PRIVATE_KEY_MARKER not in key:
      raise GitHubAppAuthError(
          "GITHUB_APP_PRIVATE_KEY does not look like a PEM private key"
          " (expected a '-----BEGIN RSA PRIVATE KEY-----' block)."
      )

    parsed_installation_id: Optional[int] = None
    raw_installation_id = (installation_id or "").strip()
    if raw_installation_id:
      if not raw_installation_id.isdigit() or int(raw_installation_id) <= 0:
        raise GitHubAppAuthError(
            "GITHUB_APP_INSTALLATION_ID must be a positive integer, got"
            f" '{raw_installation_id}'."
        )
      parsed_installation_id = int(raw_installation_id)

    return cls(
        app_id=clean_app_id,
        private_key=key,
        installation_id=parsed_installation_id,
    )


def build_app_jwt(
    credentials: GitHubAppCredentials, now: Optional[float] = None
) -> str:
  """Signs the short-lived App JWT used to call the `/app/...` endpoints."""
  # pylint: disable=g-import-not-at-top
  from google.auth import crypt as google_crypt
  from google.auth import jwt as google_jwt
  # pylint: enable=g-import-not-at-top

  issued = int(time.time() if now is None else now)
  payload = {
      "iat": issued - JWT_CLOCK_SKEW_SECONDS,
      "exp": issued + JWT_LIFETIME_SECONDS,
      "iss": credentials.app_id,
  }
  try:
    signer = google_crypt.RSASigner.from_string(credentials.private_key)
  except Exception as e:  # pylint: disable=broad-exception-caught
    # The underlying error can quote key material; report only its type.
    raise GitHubAppAuthError(
        "GITHUB_APP_PRIVATE_KEY could not be loaded as an RSA private key"
        f" ({type(e).__name__})."
    ) from None
  encoded = google_jwt.encode(signer, payload, header={"alg": "RS256"})
  return encoded.decode("utf-8") if isinstance(encoded, bytes) else encoded


def _parse_expires_at(value: Any, now: float) -> float:
  """Converts GitHub's `expires_at` timestamp to epoch seconds."""
  if isinstance(value, str) and value.strip():
    try:
      parsed = datetime.datetime.fromisoformat(
          value.strip().replace("Z", "+00:00")
      )
      if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
      return parsed.timestamp()
    except ValueError:
      pass
  logger.warning(
      "GitHub App token response had no parseable expires_at (%r); assuming"
      " a %d-minute lifetime.",
      value,
      _FALLBACK_TOKEN_LIFETIME_SECONDS // 60,
  )
  return now + _FALLBACK_TOKEN_LIFETIME_SECONDS


def _error_detail(resp: requests.Response) -> str:
  """Extracts GitHub's error message from a response without echoing headers."""
  try:
    body = resp.json()
    if isinstance(body, dict) and body.get("message"):
      return str(body["message"])
  except ValueError:
    pass
  return (resp.text or "").strip()[:200]


def _header(resp: Any, name: str) -> Optional[str]:
  """Reads a response header case-insensitively; None when absent."""
  headers = getattr(resp, "headers", None) or {}
  value = headers.get(name)
  if value is None:
    lowered = name.lower()
    for key, candidate in headers.items():
      if str(key).lower() == lowered:
        value = candidate
        break
  return None if value is None else str(value)


def _retry_after_seconds(resp: Any) -> Optional[float]:
  """Returns how long GitHub asked us to wait, from Retry-After or the reset."""
  retry_after = _header(resp, "Retry-After")
  if retry_after:
    try:
      return max(0.0, float(retry_after))
    except ValueError:
      pass
  if _header(resp, "X-RateLimit-Remaining") == "0":
    reset = _header(resp, "X-RateLimit-Reset")
    if reset:
      try:
        return max(0.0, float(reset) - time.time())
      except ValueError:
        pass
  return None


def _is_rate_limited_403(resp: Any) -> bool:
  """Whether a 403 is a (secondary) rate limit rather than a permission error."""
  if _header(resp, "Retry-After") or _header(
      resp, "X-RateLimit-Remaining"
  ) == "0":
    return True
  text = (getattr(resp, "text", "") or "").lower()
  return any(marker in text for marker in _RATE_LIMIT_MARKERS)


def _app_request(
    session: Any,
    method: str,
    path: str,
    app_jwt: str,
    json_body: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
  """Calls a GitHub App endpoint with the App JWT, once.

  Server errors (5xx), 429 and rate-limited 403 responses raise
  `GitHubAppTransientError`; network failures propagate as
  `requests.RequestException`. The provider retries both. Any other non-2xx
  response raises `GitHubAppAuthError`, which is never retried.
  """
  resp = session.request(
      method,
      f"{GITHUB_API_URL}{path}",
      headers={
          "Authorization": f"Bearer {app_jwt}",
          "Accept": "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
          "User-Agent": "codemender-orchestrator",
      },
      json=json_body,
      timeout=_REQUEST_TIMEOUT_SECONDS,
  )
  status = resp.status_code
  if (
      status >= 500
      or status == 429
      or (status == 403 and _is_rate_limited_403(resp))
  ):
    raise GitHubAppTransientError(
        f"GitHub App request {method} {path} failed with HTTP"
        f" {status}: {_error_detail(resp)}",
        retry_after=_retry_after_seconds(resp),
    )
  if status >= 400:
    raise GitHubAppAuthError(
        f"GitHub App request {method} {path} failed with HTTP"
        f" {status}: {_error_detail(resp)}"
    )
  try:
    data = resp.json()
  except ValueError:
    data = None
  if not isinstance(data, dict):
    raise GitHubAppAuthError(
        f"GitHub App request {method} {path} returned an unexpected body."
    )
  return data


def _is_retryable_mint_error(error: BaseException) -> bool:
  return isinstance(
      error, (GitHubAppTransientError, requests.RequestException)
  )


class InstallationTokenProvider:
  """Mints, caches and refreshes installation tokens for one repository."""

  def __init__(
      self,
      credentials: GitHubAppCredentials,
      owner: str,
      repo: str,
      *,
      clock: Callable[[], float] = time.time,
      session: Optional[Any] = None,
      sleep: Optional[Callable[[float], None]] = None,
      refresh_margin: Optional[float] = None,
      retry_budget: float = MINT_RETRY_BUDGET_SECONDS,
  ) -> None:
    self._credentials = credentials
    self._owner = owner
    self._repo = repo
    self._clock = clock
    self._session = session if session is not None else requests
    # Resolved at call time so tests that patch time.sleep still apply.
    self._sleep = sleep
    self._refresh_margin = (
        resolve_refresh_margin() if refresh_margin is None else refresh_margin
    )
    self._retry_budget = retry_budget
    self._installation_id: Optional[int] = credentials.installation_id
    self._token: Optional[str] = None
    self._expires_at: float = 0.0
    self._minted_at: float = 0.0
    self._retry_exhausted_at: Optional[float] = None
    self._lock = threading.Lock()

  @property
  def expires_at(self) -> float:
    """Epoch seconds at which the cached token expires (0 when none)."""
    return self._expires_at

  @property
  def refresh_margin(self) -> float:
    """Seconds of remaining lifetime below which the token is re-minted."""
    return self._refresh_margin

  def get_token(self) -> str:
    """Returns a token with at least the refresh margin of life left.

    Falls back to the cached token when a refresh fails but the cached token
    is still usable for a little while. When no usable token is cached, a
    transient mint failure is retried with backoff for up to the retry
    budget.

    Raises:
      GitHubAppAuthError: No usable token could be obtained.
    """
    with self._lock:
      now = self._clock()
      if self._token and self._expires_at - now > self._refresh_margin:
        return self._token
      has_usable_token = bool(
          self._token and self._expires_at - now > MIN_USABLE_SECONDS
      )
      recently_exhausted = (
          self._retry_exhausted_at is not None
          and now - self._retry_exhausted_at < MINT_RETRY_COOLDOWN_SECONDS
      )
      try:
        if has_usable_token or recently_exhausted:
          # Either the cached token covers a failure, or a full retry budget
          # just failed; one attempt is enough and the next read tries again.
          self._token, self._expires_at = self._mint(now)
        else:
          self._token, self._expires_at = self._mint_with_retry()
        self._minted_at = self._clock()
        self._retry_exhausted_at = None
      except Exception as e:  # pylint: disable=broad-exception-caught
        now = self._clock()
        if self._token and self._expires_at - now > MIN_USABLE_SECONDS:
          logger.warning(
              "Could not refresh the GitHub App installation token for %s/%s"
              " (%s); reusing the cached token, which expires in %d seconds.",
              self._owner,
              self._repo,
              e,
              int(self._expires_at - now),
          )
          return self._token
        if isinstance(e, GitHubAppAuthError):
          raise
        raise GitHubAppAuthError(
            "Could not mint a GitHub App installation token for"
            f" {self._owner}/{self._repo}: {e}"
        ) from e
      return self._token

  def invalidate(self, token: Optional[str] = None) -> bool:
    """Drops the cached token so the next `get_token` mints a new one.

    Called after GitHub rejected a token with HTTP 401. When `token` is
    given and is no longer the cached token (another caller already replaced
    it), nothing is dropped, so a burst of 401s for one stale token causes a
    single re-mint.

    Returns:
      True if the cached token was dropped.
    """
    with self._lock:
      if self._token is None or (token is not None and token != self._token):
        return False
      logger.warning(
          "GitHub rejected the cached installation token for %s/%s;"
          " discarding it so a new one is minted.",
          self._owner,
          self._repo,
      )
      self._token = None
      self._expires_at = 0.0
      return True

  def wait_until_settled(self, token: str) -> float:
    """Waits until `token` is `NEW_TOKEN_SETTLE_SECONDS` old, if just minted.

    GitHub can reject an installation token with 401 for a few seconds after
    minting it. Only the currently cached token is waited on; any other token
    returns immediately.

    Returns:
      The number of seconds waited.
    """
    with self._lock:
      if not token or token != self._token:
        return 0.0
      delay = self._minted_at + NEW_TOKEN_SETTLE_SECONDS - self._clock()
    if delay <= 0:
      return 0.0
    (self._sleep or time.sleep)(delay)
    return delay

  def _mint_with_retry(self) -> Tuple[str, float]:
    """Mints a token, retrying transient failures within the retry budget."""
    started = self._clock()
    deadline = started + self._retry_budget
    delay = float(MINT_RETRY_INITIAL_DELAY_SECONDS)
    attempt = 0
    while True:
      attempt += 1
      try:
        return self._mint(self._clock())
      except Exception as e:  # pylint: disable=broad-exception-caught
        if not _is_retryable_mint_error(e):
          raise
        now = self._clock()
        remaining = deadline - now
        if remaining <= 0 or attempt >= MINT_RETRY_MAX_ATTEMPTS:
          self._retry_exhausted_at = now
          raise GitHubAppAuthError(
              "Could not mint a GitHub App installation token for"
              f" {self._owner}/{self._repo} after {attempt} attempt(s) over"
              f" {int(now - started)} seconds: {e}"
          ) from e
        wait = delay * random.uniform(0.8, 1.2)
        retry_after = getattr(e, "retry_after", None)
        if retry_after:
          wait = max(wait, retry_after)
        wait = min(wait, remaining)
        logger.warning(
            "Minting a GitHub App installation token for %s/%s failed"
            " (attempt %d: %s); retrying in %d seconds (%d seconds of retry"
            " budget left).",
            self._owner,
            self._repo,
            attempt,
            e,
            int(wait),
            int(remaining),
        )
        (self._sleep or time.sleep)(wait)
        delay = min(delay * 2, MINT_RETRY_MAX_DELAY_SECONDS)

  def _mint(self, now: float) -> Tuple[str, float]:
    app_jwt = build_app_jwt(self._credentials, now=now)
    if self._installation_id is None:
      self._installation_id = self._lookup_installation_id(app_jwt)
    data = _app_request(
        self._session,
        "POST",
        f"/app/installations/{self._installation_id}/access_tokens",
        app_jwt,
        # Scope the token to the repository being scanned, even when the App
        # is installed on the whole organization.
        json_body={"repositories": [self._repo]},
    )
    token = data.get("token")
    if not token or not isinstance(token, str):
      raise GitHubAppAuthError(
          "GitHub App access token response did not contain a token."
      )
    expires_at = _parse_expires_at(data.get("expires_at"), now)
    logger.info(
        "Minted a GitHub App installation token for %s/%s (installation %s,"
        " valid for %d minutes).",
        self._owner,
        self._repo,
        self._installation_id,
        max(0, int((expires_at - now) // 60)),
    )
    return token, expires_at

  def _lookup_installation_id(self, app_jwt: str) -> int:
    try:
      data = _app_request(
          self._session,
          "GET",
          f"/repos/{self._owner}/{self._repo}/installation",
          app_jwt,
      )
    except GitHubAppTransientError:
      raise
    except GitHubAppAuthError as e:
      raise GitHubAppAuthError(
          f"GitHub App {self._credentials.app_id} does not appear to be"
          f" installed on {self._owner}/{self._repo}. Install the App on the"
          " repository or set GITHUB_APP_INSTALLATION_ID. Details:"
          f" {e}"
      ) from None
    installation_id = data.get("id")
    if not isinstance(installation_id, int) or installation_id <= 0:
      raise GitHubAppAuthError(
          f"GitHub returned no installation ID for {self._owner}/{self._repo}."
      )
    return installation_id


_providers: Dict[
    Tuple[str, Optional[int], str, str], InstallationTokenProvider
] = {}
_providers_lock = threading.Lock()


def _provider_for(
    credentials: GitHubAppCredentials, owner: str, repo: str
) -> InstallationTokenProvider:
  key = (credentials.app_id, credentials.installation_id, owner, repo)
  with _providers_lock:
    provider = _providers.get(key)
    if provider is None:
      provider = InstallationTokenProvider(credentials, owner, repo)
      _providers[key] = provider
  return provider


def get_installation_token(
    credentials: GitHubAppCredentials, owner: str, repo: str
) -> str:
  """Returns a fresh-enough installation token for `owner/repo`.

  Providers are cached per process, so calling this before every batch of
  GitHub operations is cheap: it only contacts GitHub when the cached token
  is close to expiry.
  """
  return _provider_for(credentials, owner, repo).get_token()


def invalidate_installation_token(
    credentials: GitHubAppCredentials,
    owner: str,
    repo: str,
    token: Optional[str] = None,
) -> bool:
  """Discards the cached token for `owner/repo` after GitHub rejected it.

  See `InstallationTokenProvider.invalidate`. The next
  `get_installation_token` call mints a new token.
  """
  return _provider_for(credentials, owner, repo).invalidate(token)


def wait_for_installation_token(
    credentials: GitHubAppCredentials, owner: str, repo: str, token: str
) -> float:
  """Waits out GitHub's replication lag for a just-minted `token`.

  See `InstallationTokenProvider.wait_until_settled`.

  Returns:
    The number of seconds waited.
  """
  return _provider_for(credentials, owner, repo).wait_until_settled(token)


# The App's bot account, keyed by App ID and cached for the life of the
# process. A failed lookup is cached as None as well, so a scan makes at most
# one attempt and never retries it on a later code path.
_bot_identities: Dict[str, Optional[Tuple[str, str]]] = {}
_bot_identities_lock = threading.Lock()

# GitHub App slugs are lowercase letters, digits and hyphens. Anything else
# is rejected rather than interpolated into a URL and a commit identity.
_APP_SLUG_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*$")


def bot_noreply_email(slug: str, user_id: int) -> str:
  """Returns the noreply address GitHub attributes to `<slug>[bot]`.

  This is the format GitHub uses for its own bot commits (for example
  `41898282+github-actions[bot]@users.noreply.github.com`) and the one
  `actions/create-github-app-token` documents for an App's committer string.
  """
  return f"{user_id}+{slug}[bot]@users.noreply.github.com"


def _lookup_app_bot_identity(
    credentials: GitHubAppCredentials,
    token: Optional[str],
    session: Any,
) -> Tuple[str, str]:
  """Resolves (name, email) of the App's bot account. Raises on any failure."""
  app = _app_request(session, "GET", "/app", build_app_jwt(credentials))
  slug = app.get("slug")
  if not isinstance(slug, str) or not _APP_SLUG_PATTERN.match(slug):
    raise GitHubAppAuthError(f"GET /app returned no usable slug ({slug!r}).")
  login = f"{slug}[bot]"
  headers = {
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "codemender-orchestrator",
  }
  # The bot user is public; the installation token only avoids the low
  # unauthenticated rate limit.
  if token:
    headers["Authorization"] = f"Bearer {token}"
  path = f"/users/{urllib.parse.quote(login, safe='')}"
  resp = session.request(
      "GET",
      f"{GITHUB_API_URL}{path}",
      headers=headers,
      timeout=_REQUEST_TIMEOUT_SECONDS,
  )
  if resp.status_code >= 400:
    raise GitHubAppAuthError(
        f"GET {path} failed with HTTP {resp.status_code}: {_error_detail(resp)}"
    )
  try:
    data = resp.json()
  except ValueError:
    data = None
  if not isinstance(data, dict):
    raise GitHubAppAuthError(f"GET {path} returned an unexpected body.")
  user_id = data.get("id")
  if (
      not isinstance(user_id, int)
      or isinstance(user_id, bool)
      or user_id <= 0
      or data.get("type") != "Bot"
  ):
    raise GitHubAppAuthError(f"GET {path} did not return a bot account.")
  return login, bot_noreply_email(slug, user_id)


def get_app_bot_identity(
    credentials: GitHubAppCredentials,
    token: Optional[str] = None,
    *,
    session: Optional[Any] = None,
) -> Optional[Tuple[str, str]]:
  """Returns the git (name, email) of the App's bot account, or None.

  The slug comes from `GET /app` (signed with the App JWT) and the bot's user
  ID from `GET /users/<slug>[bot]`. Commits authored with the resulting
  `<slug>[bot]` / `<id>+<slug>[bot]@users.noreply.github.com` identity are
  shown on GitHub as made by the App.

  Never raises: any failure is logged once and returns None, so a lookup
  problem can only change the commit author, never fail a scan.

  Args:
    credentials: The App credentials.
    token: Optional installation token, used for the `/users` request.
    session: `requests` or a stand-in with the same `request` method.
  """
  with _bot_identities_lock:
    if credentials.app_id in _bot_identities:
      return _bot_identities[credentials.app_id]
    try:
      identity: Optional[Tuple[str, str]] = _lookup_app_bot_identity(
          credentials, token, session if session is not None else requests
      )
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning(
          "Could not look up the bot account of GitHub App %s (%s: %s);"
          " fix commits use the default git identity instead.",
          credentials.app_id,
          type(e).__name__,
          e,
      )
      identity = None
    _bot_identities[credentials.app_id] = identity
    return identity


def reset_token_cache() -> None:
  """Drops every cached provider, token and bot identity. Intended for tests."""
  with _providers_lock:
    _providers.clear()
  with _bot_identities_lock:
    _bot_identities.clear()
