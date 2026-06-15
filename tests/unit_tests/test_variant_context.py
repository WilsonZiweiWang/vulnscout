# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os
import pytest
from src.bin.webapp import create_app
from src.extensions import db as _db
from src.models.project import Project
from src.models.variant import Variant
from src.controllers.variants import VariantController


@pytest.fixture()
def app():
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": "/dev/null"})
        with application.app_context():
            _db.create_all()
            yield application
            _db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def variant(app):
    project = Project.create("TestProject")
    return Variant.create("TestVariant", project.id)


def test_fresh_variant_context_fields_are_null(variant):
    assert variant.deployment_environment is None
    assert variant.platform is None
    assert variant.objectives_profile is None
    assert variant.notes is None


def test_get_context_returns_all_keys(variant):
    ctx = VariantController.get_context(variant)
    assert set(ctx.keys()) == {
        "variant_id", "deployment_environment", "platform",
        "objectives_profile", "notes",
    }


def test_get_context_variant_id_is_string(variant):
    ctx = VariantController.get_context(variant)
    assert ctx["variant_id"] == str(variant.id)


def test_get_context_fresh_variant_all_null(variant):
    ctx = VariantController.get_context(variant)
    assert ctx["deployment_environment"] is None
    assert ctx["platform"] is None
    assert ctx["objectives_profile"] is None
    assert ctx["notes"] is None


def test_update_context_sets_one_field(variant):
    VariantController.update_context(variant, {"platform": "yocto"})
    assert variant.platform == "yocto"
    assert variant.deployment_environment is None


def test_update_context_unknown_field_raises(variant):
    with pytest.raises(ValueError, match="Unknown context fields"):
        VariantController.update_context(variant, {"bad_field": "value"})


def test_update_context_all_fields(variant):
    VariantController.update_context(variant, {
        "deployment_environment": "embedded Linux on STM32MP25",
        "platform": "yocto",
        "objectives_profile": "default",
        "notes": "runtime only",
    })
    ctx = VariantController.get_context(variant)
    assert ctx["deployment_environment"] == "embedded Linux on STM32MP25"
    assert ctx["platform"] == "yocto"
    assert ctx["objectives_profile"] == "default"
    assert ctx["notes"] == "runtime only"


def test_update_context_sequential_accumulates(variant):
    VariantController.update_context(variant, {"platform": "npm"})
    VariantController.update_context(variant, {"objectives_profile": "default"})
    assert variant.platform == "npm"
    assert variant.objectives_profile == "default"
    assert variant.deployment_environment is None


def test_update_context_non_string_value_raises(variant):
    with pytest.raises(ValueError, match="must be a string or null"):
        VariantController.update_context(variant, {"platform": 123})


def test_update_context_null_value_is_allowed(variant):
    VariantController.update_context(variant, {"platform": None})
    assert variant.platform is None


def test_update_context_platform_too_long_raises(variant):
    with pytest.raises(ValueError, match="exceeds maximum length"):
        VariantController.update_context(variant, {"platform": "x" * 101})


def test_update_context_objectives_profile_too_long_raises(variant):
    with pytest.raises(ValueError, match="exceeds maximum length"):
        VariantController.update_context(variant, {"objectives_profile": "y" * 101})


def test_update_context_platform_at_max_length_succeeds(variant):
    VariantController.update_context(variant, {"platform": "a" * 100})
    assert variant.platform == "a" * 100
