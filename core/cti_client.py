"""
Free Cyber Threat Intelligence (CTI) Client
Integrates with:
- FIRST.org EPSS (Exploit Prediction Scoring System) API (Free REST endpoint)
- CISA KEV (Known Exploited Vulnerabilities) JSON Catalog (Free government feed)
"""

import json
import os
import urllib.request
import urllib.error
from typing import Dict, Any, List

CACHE_FILE = os.path.join(os.path.dirname(__file__), "cti_cache.json")


class CTIClient:
    def __init__(self, cache_file: str = CACHE_FILE):
        self.cache_file = cache_file
        self.cache = self._load_cache()
        self.kev_set = set(self.cache.get("cisa_kev_cves", []))

    def _load_cache(self) -> Dict[str, Any]:
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_cache(self) -> None:
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            print(f"[!] Warning: Unable to save CTI cache: {e}")

    def sync_cisa_kev(self, force: bool = False) -> int:
        """
        Pulls the 100% free CISA KEV catalog (Known Exploited Vulnerabilities).
        Returns the total count of known exploited CVEs.
        """
        if self.kev_set and not force:
            return len(self.kev_set)

        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AdaptiveAttackPathEngine/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                vulns = data.get("vulnerabilities", [])
                self.kev_set = {v["cveID"] for v in vulns if "cveID" in v}
                self.cache["cisa_kev_cves"] = list(self.kev_set)
                self._save_cache()
                return len(self.kev_set)
        except Exception as e:
            print(f"[!] Error syncing CISA KEV: {e}. Falling back to cached catalog.")
            return len(self.kev_set)

    def is_in_cisa_kev(self, cve_id: str) -> bool:
        if not self.kev_set:
            self.sync_cisa_kev()
        return cve_id in self.kev_set

    def get_epss_score(self, cve_id: str) -> Dict[str, float]:
        """
        Fetches live EPSS score from FIRST.org.
        Returns:
            {"epss": float (0.0 - 1.0), "percentile": float (0.0 - 1.0)}
        """
        epss_cache = self.cache.setdefault("epss_scores", {})
        if cve_id in epss_cache:
            return epss_cache[cve_id]

        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AdaptiveAttackPathEngine/1.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                records = data.get("data", [])
                if records:
                    res = {
                        "epss": float(records[0].get("epss", 0.01)),
                        "percentile": float(records[0].get("percentile", 0.10)),
                    }
                    epss_cache[cve_id] = res
                    self._save_cache()
                    return res
        except Exception as e:
            print(f"[!] Error fetching EPSS for {cve_id}: {e}. Using baseline estimate.")

        # Default fallback if offline
        fallback = {"epss": 0.05, "percentile": 0.30}
        return fallback

    def enrich_vulnerability(self, cve_id: str, cvss_score: float = 7.5) -> Dict[str, Any]:
        """
        Combines EPSS, CISA KEV, and CVSS into a composite dynamic exploitability metric.
        """
        epss_data = self.get_epss_score(cve_id)
        is_kev = self.is_in_cisa_kev(cve_id)

        # Composite Exploitability: 0.0 to 1.0
        # If in CISA KEV, weaponization is confirmed in the wild (floor of 0.85)
        epss_val = epss_data["epss"]
        if is_kev:
            composite_exploitability = max(0.85, epss_val)
        else:
            composite_exploitability = min(1.0, (epss_val * 0.7) + ((cvss_score / 10.0) * 0.3))

        return {
            "cve_id": cve_id,
            "cvss": cvss_score,
            "epss": epss_val,
            "epss_percentile": epss_data["percentile"],
            "in_cisa_kev": is_kev,
            "composite_exploitability": round(composite_exploitability, 4),
        }
