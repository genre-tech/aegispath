"""
Trivy / Vulnerability Scanner Ingestor
Parses standard Trivy / Grype / Nuclei JSON scan reports, enriches vulnerabilities
against live FIRST.org EPSS and CISA KEV feeds, and connects them into the attack graph.
"""

from typing import Dict, List, Any
from ..adaptive_engine import AdaptiveAttackPathEngine


class TrivyIngestor:
    def __init__(self, engine: AdaptiveAttackPathEngine):
        self.engine = engine

    def ingest_trivy_report(self, target_host_id: str, trivy_json: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parses a Trivy scan report and binds detected CVEs to the target host.
        """
        if not self.engine.graph.has_node(target_host_id):
            self.engine.add_node(target_host_id, "Host", f"Host: {target_host_id}")

        vulns_added = 0
        enriched_details = []

        results = trivy_json.get("Results", [])
        for r in results:
            for v in r.get("Vulnerabilities", []):
                cve_id = v.get("VulnerabilityID")
                pkg_name = v.get("PkgName", "")
                installed_ver = v.get("InstalledVersion", "")
                title = v.get("Title") or f"{pkg_name} {installed_ver} vulnerability"

                # Extract CVSS
                cvss_data = v.get("CVSS", {})
                cvss_score = 7.5
                for provider in ("nvd", "redhat", "ghsa"):
                    if provider in cvss_data and "V3Score" in cvss_data[provider]:
                        cvss_score = float(cvss_data[provider]["V3Score"])
                        break

                # Add to attack graph
                self.engine.add_node(
                    node_id=cve_id,
                    node_type="Vulnerability",
                    name=f"{cve_id} ({pkg_name})",
                    cvss=cvss_score,
                    package=pkg_name,
                    version=installed_ver
                )

                # Link Host -> CVE
                self.engine.add_edge(target_host_id, cve_id, "VULNERABLE_TO", base_probability=0.90)
                vulns_added += 1

                # Enrich via CTI client
                enriched = self.engine.cti.enrich_vulnerability(cve_id, cvss_score=cvss_score)
                enriched_details.append(enriched)

        return {
            "target_host": target_host_id,
            "vulnerabilities_ingested": vulns_added,
            "enriched": enriched_details
        }
