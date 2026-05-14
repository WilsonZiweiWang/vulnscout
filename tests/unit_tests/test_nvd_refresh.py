# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import datetime
import uuid
from unittest.mock import MagicMock, patch

from src.controllers.nvd_refresh import (
    build_cpe_map,
    apply_nvd_update,
    collect_target_cve_ids,
    _update_cvss_metrics,
)


# ---------------------------------------------------------------------------
# build_cpe_map
# ---------------------------------------------------------------------------

def test_build_cpe_map_groups_cves_by_cpe():
    """Multiple CVEs sharing a CPE are all mapped to that CPE."""
    packages = [
        MagicMock(id=uuid.uuid4(), cpe=["cpe:2.3:a:vendor:lib:1.0:*:*:*:*:*:*:*"]),
        MagicMock(id=uuid.uuid4(), cpe=["cpe:2.3:a:vendor:lib:1.0:*:*:*:*:*:*:*"]),
    ]
    findings = [
        MagicMock(vulnerability_id="CVE-2024-0001", package_id=packages[0].id),
        MagicMock(vulnerability_id="CVE-2024-0002", package_id=packages[1].id),
    ]
    result = build_cpe_map(
        {"CVE-2024-0001", "CVE-2024-0002"},
        findings,
        {p.id: p for p in packages},
    )
    assert "cpe:2.3:a:vendor:lib:1.0:*:*:*:*:*:*:*" in result
    assert result["cpe:2.3:a:vendor:lib:1.0:*:*:*:*:*:*:*"] == {"CVE-2024-0001", "CVE-2024-0002"}


def test_build_cpe_map_skips_wildcard_vendor():
    """CPEs with wildcard in the vendor (parts[3]) position are excluded from batch map."""
    pkg = MagicMock(id=uuid.uuid4(), cpe=["cpe:2.3:a:*:lib:1.0:*:*:*:*:*:*:*"])
    finding = MagicMock(vulnerability_id="CVE-2024-9999", package_id=pkg.id)
    result = build_cpe_map(
        {"CVE-2024-9999"},
        [finding],
        {pkg.id: pkg},
    )
    assert result == {}


def test_build_cpe_map_skips_packages_without_cpe():
    pkg = MagicMock(id=uuid.uuid4(), cpe=None)
    finding = MagicMock(vulnerability_id="CVE-2024-1111", package_id=pkg.id)
    result = build_cpe_map({"CVE-2024-1111"}, [finding], {pkg.id: pkg})
    assert result == {}


# ---------------------------------------------------------------------------
# apply_nvd_update
# ---------------------------------------------------------------------------

def _make_vuln(description="old desc", status="medium", links=None,
               weaknesses=None, publish_date=None, attack_vector="NETWORK",
               nvd_last_modified="2024-01-01T00:00:00.000"):
    v = MagicMock()
    v.description = description
    v.status = status
    v.links = links or ["https://nvd.nist.gov/vuln/detail/CVE-2024-0001"]
    v.weaknesses = weaknesses or ["CWE-79"]
    v.publish_date = publish_date or datetime.date(2024, 1, 1)
    v.attack_vector = attack_vector
    v.nvd_last_modified = nvd_last_modified
    v.update_record = MagicMock(return_value=v)
    return v


def test_apply_nvd_update_sets_nvd_data_updated_at_when_field_changes():
    vuln = _make_vuln(description="old")
    now = datetime.datetime.now(datetime.timezone.utc)
    details = {
        "description": "new description",
        "status": "medium",
        "links": vuln.links,
        "weaknesses": vuln.weaknesses,
        "publish_date": vuln.publish_date,
        "attack_vector": vuln.attack_vector,
        "nvd_last_modified": vuln.nvd_last_modified,
    }
    changed = apply_nvd_update(vuln, details, now)
    assert changed is True
    vuln.update_record.assert_called_once()
    call_kwargs = vuln.update_record.call_args[1]
    assert call_kwargs["description"] == "new description"
    assert call_kwargs["nvd_data_updated_at"] == now
    assert call_kwargs["nvd_fetched_at"] == now


def test_apply_nvd_update_does_not_set_nvd_data_updated_at_when_nothing_changes():
    vuln = _make_vuln()
    now = datetime.datetime.now(datetime.timezone.utc)
    details = {
        "description": vuln.description,
        "status": vuln.status,
        "links": vuln.links,
        "weaknesses": vuln.weaknesses,
        "publish_date": vuln.publish_date,
        "attack_vector": vuln.attack_vector,
        "nvd_last_modified": vuln.nvd_last_modified,
    }
    changed = apply_nvd_update(vuln, details, now)
    assert changed is False
    # nvd_fetched_at must always be stamped, nvd_data_updated_at must NOT be set
    vuln.update_record.assert_called_once_with(nvd_fetched_at=now, commit=False)
    call_kwargs = vuln.update_record.call_args[1]
    assert "nvd_data_updated_at" not in call_kwargs


def test_apply_nvd_update_always_sets_nvd_fetched_at_on_change():
    vuln = _make_vuln(status="low")
    now = datetime.datetime.now(datetime.timezone.utc)
    details = {
        "description": vuln.description,
        "status": "critical",   # changed
        "links": vuln.links,
        "weaknesses": vuln.weaknesses,
        "publish_date": vuln.publish_date,
        "attack_vector": vuln.attack_vector,
        "nvd_last_modified": vuln.nvd_last_modified,
    }
    changed = apply_nvd_update(vuln, details, now)
    assert changed is True
    kwargs = vuln.update_record.call_args[1]
    assert kwargs["nvd_fetched_at"] == now
    assert kwargs["nvd_data_updated_at"] == now


def test_apply_nvd_update_handles_none_details_fields_gracefully():
    """None values in details do not overwrite existing data; nvd_fetched_at is still stamped."""
    vuln = _make_vuln(description="keep me")
    now = datetime.datetime.now(datetime.timezone.utc)
    details = {
        "description": None,
        "status": None,
        "links": None,
        "weaknesses": None,
        "publish_date": None,
        "attack_vector": None,
        "nvd_last_modified": None,
    }
    changed = apply_nvd_update(vuln, details, now)
    assert changed is False
    vuln.update_record.assert_called_once_with(nvd_fetched_at=now, commit=False)


# ---------------------------------------------------------------------------
# build_cpe_map — line 32: continue when vuln_id not in target set
# ---------------------------------------------------------------------------

def test_build_cpe_map_skips_finding_not_in_target():
    """Findings whose CVE is not in target_cve_ids are excluded (line 32 continue)."""
    pkg = MagicMock(id=uuid.uuid4(), cpe=["cpe:2.3:a:vendor:lib:1.0:*:*:*:*:*:*:*"])
    finding_in = MagicMock(vulnerability_id="CVE-2024-0001", package_id=pkg.id)
    finding_out = MagicMock(vulnerability_id="CVE-2024-9999", package_id=pkg.id)
    result = build_cpe_map(
        {"CVE-2024-0001"},   # only this CVE is targeted
        [finding_in, finding_out],
        {pkg.id: pkg},
    )
    assert "cpe:2.3:a:vendor:lib:1.0:*:*:*:*:*:*:*" in result
    assert "CVE-2024-0001" in result["cpe:2.3:a:vendor:lib:1.0:*:*:*:*:*:*:*"]
    # CVE-2024-9999 was skipped — not in target_cve_ids
    assert "CVE-2024-9999" not in result["cpe:2.3:a:vendor:lib:1.0:*:*:*:*:*:*:*"]


# ---------------------------------------------------------------------------
# collect_target_cve_ids — explicit list path (no DB needed, lines 89-90)
# ---------------------------------------------------------------------------

def test_collect_target_cve_ids_explicit_list_uppercases_and_filters():
    """Explicit list: empty strings are removed, IDs are uppercased."""
    result = collect_target_cve_ids(None, None, ["cve-2024-0001", "", "cve-2024-0002"])
    assert result == ["CVE-2024-0001", "CVE-2024-0002"]


def test_collect_target_cve_ids_explicit_empty_list():
    """Explicit empty list returns []."""
    result = collect_target_cve_ids(None, None, [])
    assert result == []


def test_collect_target_cve_ids_explicit_list_already_uppercase():
    """Already-uppercased IDs pass through unchanged."""
    result = collect_target_cve_ids(None, None, ["CVE-2024-1234"])
    assert result == ["CVE-2024-1234"]


# ---------------------------------------------------------------------------
# _update_cvss_metrics
# ---------------------------------------------------------------------------

@patch("src.models.metrics.Metrics.get_by_vulnerability", return_value=[])
@patch("src.extensions.db")
def test_update_cvss_metrics_creates_new_record_when_none_exists(mock_db, mock_get):
    """When no Metrics row exists for the version, a new one is added to the session."""
    details = {"base_score": 7.4, "cvss_version": "3.1", "cvss_vector": "CVSS:3.1/AV:N/AC:H"}
    result = _update_cvss_metrics("CVE-2024-0001", details)
    assert result is True
    mock_db.session.add.assert_called_once()


@patch("src.extensions.db")
def test_update_cvss_metrics_updates_score_when_different(mock_db):
    """Existing Metrics row with a different score is updated in place."""
    existing = MagicMock(version="3.1", score=5.0, vector="CVSS:3.1/AV:L/AC:L", author="unknown")
    with patch("src.models.metrics.Metrics.get_by_vulnerability", return_value=[existing]):
        details = {"base_score": 7.4, "cvss_version": "3.1", "cvss_vector": "CVSS:3.1/AV:N/AC:H"}
        result = _update_cvss_metrics("CVE-2024-0001", details)
    assert result is True
    assert existing.score == 7.4
    assert existing.vector == "CVSS:3.1/AV:N/AC:H"
    assert existing.author == "NVD"


@patch("src.extensions.db")
def test_update_cvss_metrics_returns_false_when_score_unchanged(mock_db):
    """No change when score and vector already match NVD data."""
    existing = MagicMock(version="3.1", score=7.4, vector="CVSS:3.1/AV:N/AC:H", author="NVD")
    with patch("src.models.metrics.Metrics.get_by_vulnerability", return_value=[existing]):
        details = {"base_score": 7.4, "cvss_version": "3.1", "cvss_vector": "CVSS:3.1/AV:N/AC:H"}
        result = _update_cvss_metrics("CVE-2024-0001", details)
    assert result is False
    mock_db.session.add.assert_not_called()


def test_update_cvss_metrics_returns_false_when_no_score_in_details():
    """Missing base_score/cvss_version in details → skip without touching DB."""
    result = _update_cvss_metrics("CVE-2024-0001", {"description": "no score here"})
    assert result is False


# ---------------------------------------------------------------------------
# apply_nvd_update — CVSS integration
# ---------------------------------------------------------------------------

@patch("src.controllers.nvd_refresh._update_cvss_metrics", return_value=True)
def test_apply_nvd_update_returns_true_when_only_cvss_changes(mock_cvss):
    """When only CVSS score changed (all scalar fields equal), result is True
    and nvd_data_updated_at is stamped."""
    vuln = _make_vuln()
    now = datetime.datetime.now(datetime.timezone.utc)
    details = {
        "description": vuln.description,
        "status": vuln.status,
        "links": vuln.links,
        "weaknesses": vuln.weaknesses,
        "publish_date": vuln.publish_date,
        "attack_vector": vuln.attack_vector,
        "nvd_last_modified": vuln.nvd_last_modified,
        "base_score": 9.8,
        "cvss_version": "3.1",
    }
    changed = apply_nvd_update(vuln, details, now)
    assert changed is True
    kwargs = vuln.update_record.call_args[1]
    assert kwargs["nvd_data_updated_at"] == now
    assert kwargs["nvd_fetched_at"] == now


@patch("src.controllers.nvd_refresh._update_cvss_metrics", return_value=False)
def test_apply_nvd_update_returns_false_when_cvss_unchanged(mock_cvss):
    """When no scalar fields and no CVSS changed, result is False."""
    vuln = _make_vuln()
    now = datetime.datetime.now(datetime.timezone.utc)
    details = {
        "description": vuln.description,
        "status": vuln.status,
        "links": vuln.links,
        "weaknesses": vuln.weaknesses,
        "publish_date": vuln.publish_date,
        "attack_vector": vuln.attack_vector,
        "nvd_last_modified": vuln.nvd_last_modified,
    }
    changed = apply_nvd_update(vuln, details, now)
    assert changed is False
    vuln.update_record.assert_called_once_with(nvd_fetched_at=now, commit=False)
