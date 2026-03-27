import httpx


class VulnScoutError(Exception):
    """Raised when VulnScout API returns an error or is unreachable."""
    pass


class VulnScoutClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def write_assessment(self, vuln_id: str, payload: dict) -> dict:
        """POST /api/vulnerabilities/<vuln_id>/assessments.

        Returns the parsed JSON response on success.
        Raises VulnScoutError on non-2xx response or connection failure.
        """
        url = f"{self.base_url}/api/vulnerabilities/{vuln_id}/assessments"
        try:
            with httpx.Client() as http:
                response = http.post(url, json=payload)
        except httpx.ConnectError:
            raise VulnScoutError(f"Could not connect to VulnScout at {self.base_url}")
        if not response.is_success:
            try:
                error_msg = response.json().get("error", response.text)
            except Exception:
                error_msg = response.text
            raise VulnScoutError(error_msg)
        return response.json()
