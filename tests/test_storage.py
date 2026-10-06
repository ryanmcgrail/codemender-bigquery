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

"""Unit tests for codemender_agent.storage module."""

import datetime
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from codemender_agent.storage import upload_and_sign_report


class TestStorage(unittest.TestCase):

  @patch("codemender_agent.storage.storage.Client")
  def test_upload_and_sign_report_with_signing_credentials(
      self, mock_client_cls
  ):
    """Test GCS URL signing when credentials already support signing (e.g.

    JSON key).
    """
    mock_client = MagicMock()
    mock_bucket = MagicMock()
    mock_blob = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob

    # Setup mocked google.auth namespaces
    mock_google = MagicMock()
    mock_auth = MagicMock()
    mock_credentials_module = MagicMock()

    class FakeSigning:
      pass

    mock_credentials_module.Signing = FakeSigning
    mock_auth.credentials = mock_credentials_module
    mock_google.auth = mock_auth

    # Create mock credentials that inherit from FakeSigning
    class SigningCredentials(FakeSigning):
      pass

    mock_credentials = SigningCredentials()
    mock_client._credentials = mock_credentials

    mock_blob.generate_signed_url.return_value = (
        "https://storage.googleapis.com/signed-url"
    )

    with patch.dict(
        sys.modules,
        {
            "google": mock_google,
            "google.auth": mock_auth,
            "google.auth.credentials": mock_credentials_module,
        },
    ):
      with tempfile.NamedTemporaryFile(suffix=".html") as temp_file:
        url = upload_and_sign_report(
            temp_file.name, "my-bucket", "reports/r.html"
        )
        self.assertEqual(url, "https://storage.googleapis.com/signed-url")

        # Verify generate_signed_url was called with default kwargs (no wrapped credentials)
        mock_blob.generate_signed_url.assert_called_once_with(
            version="v4",
            expiration=datetime.timedelta(days=3),
            method="GET",
        )

  @patch("codemender_agent.storage.storage.Client")
  def test_upload_and_sign_report_with_impersonated_credentials(
      self, mock_client_cls
  ):
    """Test GCS URL signing using Impersonated Credentials (e.g. Cloud Run)."""
    mock_client = MagicMock()
    mock_bucket = MagicMock()
    mock_blob = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob

    # Configure credentials that do NOT inherit from Signing
    mock_credentials = MagicMock()
    mock_credentials.service_account_email = (
        "test-sa@project.iam.gserviceaccount.com"
    )
    mock_client._credentials = mock_credentials

    # Setup mocked google.auth namespaces
    mock_google = MagicMock()
    mock_auth = MagicMock()
    mock_credentials_module = MagicMock()

    class FakeSigning:
      pass

    mock_credentials_module.Signing = FakeSigning
    mock_auth.credentials = mock_credentials_module
    mock_google.auth = mock_auth

    mock_impersonated_module = MagicMock()
    mock_signing_creds = MagicMock()
    mock_impersonated_module.Credentials.return_value = mock_signing_creds
    mock_auth.impersonated_credentials = mock_impersonated_module

    mock_blob.generate_signed_url.return_value = (
        "https://storage.googleapis.com/signed-url"
    )

    with patch.dict(
        sys.modules,
        {
            "google": mock_google,
            "google.auth": mock_auth,
            "google.auth.credentials": mock_credentials_module,
            "google.auth.impersonated_credentials": mock_impersonated_module,
        },
    ):
      with tempfile.NamedTemporaryFile(suffix=".html") as temp_file:
        url = upload_and_sign_report(
            temp_file.name, "my-bucket", "reports/r.html"
        )
        self.assertEqual(url, "https://storage.googleapis.com/signed-url")

        # Verify impersonated credentials wrapper was constructed
        mock_impersonated_module.Credentials.assert_called_once_with(
            source_credentials=mock_credentials,
            target_principal="test-sa@project.iam.gserviceaccount.com",
            target_scopes=[
                "https://www.googleapis.com/auth/devstorage.read_write"
            ],
        )

        # Verify generate_signed_url was called with the impersonated signing credentials
        mock_blob.generate_signed_url.assert_called_once_with(
            version="v4",
            expiration=datetime.timedelta(days=3),
            method="GET",
            credentials=mock_signing_creds,
        )

  @patch("codemender_agent.storage.requests.get")
  @patch("codemender_agent.storage.storage.Client")
  def test_upload_and_sign_report_with_cloud_run_default_service_account_metadata_fallback(
      self, mock_client_cls, mock_requests_get
  ):
    """Test GCS URL signing when credentials.service_account_email is 'default' on Cloud Run."""
    mock_client = MagicMock()
    mock_bucket = MagicMock()
    mock_blob = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob

    # Configure Compute Engine / Cloud Run credentials returning 'default'
    mock_credentials = MagicMock()
    mock_credentials.service_account_email = "default"
    mock_client._credentials = mock_credentials

    # Mock metadata server response
    mock_meta_resp = MagicMock()
    mock_meta_resp.status_code = 200
    mock_meta_resp.text = "cloudrun-runner-sa@xz-cm-agent-demo.iam.gserviceaccount.com"
    mock_requests_get.return_value = mock_meta_resp

    # Setup mocked google.auth namespaces
    mock_google = MagicMock()
    mock_auth = MagicMock()
    mock_credentials_module = MagicMock()

    class FakeSigning:
      pass

    mock_credentials_module.Signing = FakeSigning
    mock_auth.credentials = mock_credentials_module
    mock_google.auth = mock_auth

    mock_impersonated_module = MagicMock()
    mock_signing_creds = MagicMock()
    mock_impersonated_module.Credentials.return_value = mock_signing_creds
    mock_auth.impersonated_credentials = mock_impersonated_module

    mock_blob.generate_signed_url.return_value = (
        "https://storage.googleapis.com/signed-url"
    )

    with patch.dict(
        sys.modules,
        {
            "google": mock_google,
            "google.auth": mock_auth,
            "google.auth.credentials": mock_credentials_module,
            "google.auth.impersonated_credentials": mock_impersonated_module,
        },
    ):
      with tempfile.NamedTemporaryFile(suffix=".html") as temp_file:
        url = upload_and_sign_report(
            temp_file.name, "my-bucket", "reports/r.html"
        )
        self.assertEqual(url, "https://storage.googleapis.com/signed-url")

        # Verify Metadata server was queried to resolve 'default' email
        mock_requests_get.assert_called_once_with(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
            headers={"Metadata-Flavor": "Google"},
            timeout=2,
        )

        # Verify impersonated credentials wrapper was constructed using resolved metadata SA email
        mock_impersonated_module.Credentials.assert_called_once_with(
            source_credentials=mock_credentials,
            target_principal="cloudrun-runner-sa@xz-cm-agent-demo.iam.gserviceaccount.com",
            target_scopes=[
                "https://www.googleapis.com/auth/devstorage.read_write"
            ],
        )

        # Verify generate_signed_url was called with the impersonated signing credentials
        mock_blob.generate_signed_url.assert_called_once_with(
            version="v4",
            expiration=datetime.timedelta(days=3),
            method="GET",
            credentials=mock_signing_creds,
        )

  def test_github_actions_transit_storage_adapter(self):
    """Test GitHubActionsTransitStorageAdapter uploads, downloads, and lists blobs correctly."""
    import os
    from codemender_agent.storage import GitHubActionsTransitStorageAdapter

    with tempfile.TemporaryDirectory() as temp_dir:
      adapter = GitHubActionsTransitStorageAdapter(base_dir=temp_dir)
      
      # Create sample file to upload
      src_file = os.path.join(temp_dir, "sample.txt")
      with open(src_file, "w") as f:
        f.write("hello gha")

      # Upload to base
      self.assertTrue(adapter.upload_file(src_file, "base/sample.txt"))
      self.assertTrue(os.path.exists(os.path.join(temp_dir, ".codemender_transit", "base", "sample.txt")))

      # List blobs
      blobs = adapter.list_blobs(prefix="base")
      self.assertIn("base/sample.txt", blobs)

      # Download file
      dest_file = os.path.join(temp_dir, "downloaded.txt")
      self.assertTrue(adapter.download_file(dest_file, "base/sample.txt"))
      with open(dest_file, "r") as f:
        self.assertEqual(f.read(), "hello gha")

      # Signed URL
      url = adapter.generate_signed_url("base/sample.txt")
      self.assertTrue(url.startswith("file://"))

  def test_get_storage_adapter_factory(self):
    """Test get_storage_adapter returns correct adapter instance for each mode."""
    from codemender_agent.storage import (
        GCSTransitStorageAdapter,
        GitHubActionsTransitStorageAdapter,
        LocalStorageAdapter,
        get_storage_adapter,
    )

    with tempfile.TemporaryDirectory() as temp_dir:
      gcs_adapter = get_storage_adapter("gcs", bucket_name="test-bkt", base_dir=temp_dir)
      self.assertIsInstance(gcs_adapter, GCSTransitStorageAdapter)

      gha_adapter = get_storage_adapter("github_actions", base_dir=temp_dir)
      self.assertIsInstance(gha_adapter, GitHubActionsTransitStorageAdapter)

      local_adapter = get_storage_adapter("local", base_dir=temp_dir)
      self.assertIsInstance(local_adapter, LocalStorageAdapter)


if __name__ == "__main__":
  unittest.main()
