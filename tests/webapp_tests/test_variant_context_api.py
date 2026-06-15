# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Integration tests for GET/PUT /api/variants/<id>/context."""

import os
import uuid
import pytest
from src.bin.webapp import create_app
from . import write_demo_files, setup_demo_db


@pytest.fixture()
def init_files(tmp_path):
    files = {
        "status": tmp_path / "status.txt",
        "packages": tmp_path / "packages-merged.json",
        "vulnerabilities": tmp_path / "vulnerabilities-merged.json",
        "assessments": tmp_path / "assessments-merged.json",
        "openvex": tmp_path / "openvex.json",
        "time_estimates": tmp_path / "time_estimates.json",
    }
    write_demo_files(files)
    return files


@pytest.fixture()
def app(init_files):
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": init_files["status"],
            "OPENVEX_FILE": init_files["openvex"],
            "NVD_DB_PATH": "webapp_tests/mini_nvd.db",
        })
        setup_demo_db(application)
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


def _get_default_variant_id(client) -> str:
    """Return the ID of the 'default' variant under the 'demo' project."""
    projects = client.get("/api/projects").get_json()
    demo = next(p for p in projects if p["name"] == "demo")
    variants = client.get(f"/api/projects/{demo['id']}/variants").get_json()
    default = next(v for v in variants if v["name"] == "default")
    return default["id"]


class TestGetVariantContext:

    def test_invalid_uuid_returns_400(self, client):
        resp = client.get("/api/variants/not-a-uuid/context")
        assert resp.status_code == 400

    def test_unknown_variant_returns_404(self, client):
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/api/variants/{fake_id}/context")
        assert resp.status_code == 404

    def test_fresh_variant_returns_null_fields(self, client):
        vid = _get_default_variant_id(client)
        resp = client.get(f"/api/variants/{vid}/context")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["variant_id"] == vid
        assert data["deployment_environment"] is None
        assert data["platform"] is None
        assert data["objectives_profile"] is None
        assert data["notes"] is None


class TestUpdateVariantContext:

    def test_invalid_uuid_returns_400(self, client):
        resp = client.put("/api/variants/not-a-uuid/context", json={"platform": "yocto"})
        assert resp.status_code == 400

    def test_unknown_variant_returns_404(self, client):
        fake_id = str(uuid.uuid4())
        resp = client.put(f"/api/variants/{fake_id}/context", json={"platform": "yocto"})
        assert resp.status_code == 404

    def test_non_json_body_returns_400(self, client):
        vid = _get_default_variant_id(client)
        resp = client.put(
            f"/api/variants/{vid}/context",
            data="not json",
            content_type="text/plain",
        )
        assert resp.status_code == 400

    def test_unknown_field_returns_400(self, client):
        vid = _get_default_variant_id(client)
        resp = client.put(f"/api/variants/{vid}/context", json={"bad_field": "value"})
        assert resp.status_code == 400

    def test_partial_update_only_changes_sent_field(self, client):
        vid = _get_default_variant_id(client)
        resp = client.put(f"/api/variants/{vid}/context", json={"platform": "yocto"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["platform"] == "yocto"
        assert data["deployment_environment"] is None

    def test_all_fields_updated(self, client):
        vid = _get_default_variant_id(client)
        payload = {
            "deployment_environment": "embedded Linux on STM32MP25",
            "platform": "yocto",
            "objectives_profile": "default",
            "notes": "runtime only",
        }
        resp = client.put(f"/api/variants/{vid}/context", json=payload)
        assert resp.status_code == 200
        data = resp.get_json()
        for key, val in payload.items():
            assert data[key] == val

    def test_round_trip_put_then_get(self, client):
        vid = _get_default_variant_id(client)
        client.put(f"/api/variants/{vid}/context", json={"platform": "npm", "notes": "web app"})
        resp = client.get(f"/api/variants/{vid}/context")
        data = resp.get_json()
        assert data["platform"] == "npm"
        assert data["notes"] == "web app"
        assert data["deployment_environment"] is None
