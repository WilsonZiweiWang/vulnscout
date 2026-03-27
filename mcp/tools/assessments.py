from typing import Optional
from client import VulnScoutClient, VulnScoutError


def _write_assessment_impl(
    client: VulnScoutClient,
    vuln_id: str,
    packages: list,
    status: str,
    justification: Optional[str] = None,
    status_notes: Optional[str] = None,
    impact_statement: Optional[str] = None,
    workaround: Optional[str] = None,
    responses: Optional[list] = None,
    timestamp: Optional[str] = None,
) -> str:
    """Core logic for write_assessment — separated for testability."""
    payload: dict = {"packages": packages, "status": status}
    if justification is not None:
        payload["justification"] = justification
    if status_notes is not None:
        payload["status_notes"] = status_notes
    if impact_statement is not None:
        payload["impact_statement"] = impact_statement
    if workaround is not None:
        payload["workaround"] = workaround
    if responses is not None:
        payload["responses"] = responses
    if timestamp is not None:
        payload["timestamp"] = timestamp

    try:
        result = client.write_assessment(vuln_id, payload)
        a = result.get("assessment", {})
        return (
            f"Assessment created: id={a.get('id')}, "
            f"status={a.get('status')}, "
            f"packages={a.get('packages')}"
        )
    except VulnScoutError as e:
        return f"Error: {e}"


def register_tools(server, client: VulnScoutClient) -> None:
    """Register all assessment tools on the given FastMCP server."""

    @server.tool()
    def write_assessment(
        vuln_id: str,
        packages: list,
        status: str,
        justification: Optional[str] = None,
        status_notes: Optional[str] = None,
        impact_statement: Optional[str] = None,
        workaround: Optional[str] = None,
        responses: Optional[list] = None,
        timestamp: Optional[str] = None,
    ) -> str:
        """Write a VEX assessment for a CVE on one or more packages in VulnScout.

        Args:
            vuln_id: CVE identifier, e.g. CVE-2024-1234
            packages: List of affected package strings in 'name@version' format, e.g. ['openssl@1.0.0']
            status: Assessment status. OpenVEX values: under_investigation, not_affected, affected, fixed.
                    CycloneDX VEX values: in_triage, false_positive, not_affected, exploitable,
                    resolved, resolved_with_pedigree.
            justification: Required when status is 'not_affected'. OpenVEX values:
                    component_not_present, vulnerable_code_not_present,
                    vulnerable_code_not_in_execute_path,
                    vulnerable_code_cannot_be_controlled_by_adversary,
                    inline_mitigations_already_exist. CycloneDX VEX values: code_not_present,
                    code_not_reachable, requires_configuration, requires_dependency,
                    requires_environment, protected_by_compiler, protected_at_runtime,
                    protected_at_perimeter, protected_by_mitigating_control.
            status_notes: Free-text notes about the assessment.
            impact_statement: Free-text description of impact.
            workaround: Workaround description.
            responses: CycloneDX response tags. Valid values: can_not_fix, will_not_fix,
                    update, rollback, workaround_available.
            timestamp: ISO 8601 datetime string, e.g. 2024-01-15T10:30:00Z.
        """
        return _write_assessment_impl(
            client,
            vuln_id=vuln_id,
            packages=packages,
            status=status,
            justification=justification,
            status_notes=status_notes,
            impact_statement=impact_statement,
            workaround=workaround,
            responses=responses,
            timestamp=timestamp,
        )
