# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import jsonify, request

from ..controllers.projects import ProjectController
from ..controllers.variants import VariantController


def init_app(app):

    @app.route('/api/variants/context')
    def get_variant_context_by_name():
        project_name = (request.args.get('project_name') or '').strip()
        variant_name = (request.args.get('variant_name') or '').strip()
        if not project_name:
            return jsonify({"error": "Query parameter 'project_name' is required."}), 400
        if not variant_name:
            return jsonify({"error": "Query parameter 'variant_name' is required."}), 400
        project = ProjectController.get_by_name(project_name)
        if project is None:
            return jsonify({"error": f"Project '{project_name}' not found."}), 404
        variant = VariantController.get_by_name_and_project(variant_name, project.id)
        if variant is None:
            return jsonify({"error": f"Variant '{variant_name}' not found in project '{project_name}'."}), 404
        return jsonify(VariantController.get_context(variant))

    @app.route('/api/variants')
    def list_all_variants():
        projects = ProjectController.get_all()
        all_variants = []
        for project in projects:
            all_variants.extend(VariantController.serialize_list(
                VariantController.get_by_project(project.id)
            ))
        return jsonify(all_variants)

    @app.route('/api/projects/<project_id>/variants')
    def list_variants_by_project(project_id):
        project = ProjectController.get(project_id)
        if project is None:
            return jsonify({"error": "Project not found"}), 404
        variants = VariantController.get_by_project(project_id)
        return jsonify(VariantController.serialize_list(variants))
