"""OpenCTI adapter (GraphQL API, read-only).

Used in FULL mode (docker-compose.full.yml) or against any reachable OpenCTI instance by setting
OPENCTI_URL and OPENCTI_TOKEN. OpenCTI is self-hosted, so internal indicators may be queried.
"""
from __future__ import annotations

from typing import Any

import httpx

from app.cti.base import CTIProvider, ProviderError, freshness

OBSERVABLES_QUERY = """
query SfumatoLookup($search: String!) {
  stixCyberObservables(search: $search, first: 5) {
    edges { node { id entity_type observable_value x_opencti_score created_at updated_at
      objectLabel { value }
      createdBy { name }
      stixCoreRelationships(first: 20) { edges { node {
        relationship_type
        to { ... on BasicObject { id entity_type } ... on StixDomainObject { created } ... on Malware { name }
             ... on ThreatActor { name } ... on IntrusionSet { name } ... on AttackPattern { name x_mitre_id } }
      } } }
    } }
  }
  indicators(search: $search, first: 5) {
    edges { node { id name pattern x_opencti_score confidence valid_from valid_until revoked
      objectLabel { value } createdBy { name } } }
  }
}
"""


class OpenCTI(CTIProvider):
    key = "opencti"
    name = "OpenCTI"
    homepage = "https://filigran.io/solutions/open-cti/"
    supports = {"ipv4", "ipv6", "domain", "hostname", "url", "md5", "sha1", "sha256", "cve", "email"}
    local = True
    credential_names = ("opencti_url", "opencti_token")

    def config_hint(self) -> str:
        return "Start FULL mode (docker-compose.full.yml) or set OPENCTI_URL and OPENCTI_TOKEN."

    async def fetch_raw(self, client: httpx.AsyncClient, itype: str, value: str) -> tuple[Any, int]:
        url = self.credentials["opencti_url"].rstrip("/") + "/graphql"
        resp = await client.post(url, json={"query": OBSERVABLES_QUERY, "variables": {"search": value}},
                                 headers={"Authorization": f"Bearer {self.credentials['opencti_token']}"})
        self.check_http(resp)
        body = resp.json()
        if body.get("errors") and not body.get("data"):
            raise ProviderError("error", f"OpenCTI GraphQL error: {body['errors'][0].get('message')}", resp.status_code)
        return body, resp.status_code

    def parse(self, itype: str, value: str, raw: Any) -> dict:
        data = (raw or {}).get("data") or {}
        obs = [e["node"] for e in (data.get("stixCyberObservables") or {}).get("edges", [])
               if e.get("node", {}).get("observable_value", "").lower() == value.lower()]
        inds = [e["node"] for e in (data.get("indicators") or {}).get("edges", []) if not e["node"].get("revoked")]
        if not obs and not inds:
            return {"status": "no_results", "verdict": "not_found", "summary": "Not present in OpenCTI"}
        scores = [n.get("x_opencti_score") for n in obs + inds if n.get("x_opencti_score") is not None]
        score = max(scores) if scores else None
        labels = sorted({lab["value"] for n in obs + inds for lab in (n.get("objectLabel") or []) if lab.get("value")})
        rels, malware, actors, mitre = [], set(), set(), set()
        for o in obs:
            for e in (o.get("stixCoreRelationships") or {}).get("edges", []):
                n = e["node"]
                to = n.get("to") or {}
                rels.append({"type": n.get("relationship_type"), "target": to.get("name") or to.get("id"),
                             "target_type": to.get("entity_type")})
                if to.get("entity_type") == "Malware" and to.get("name"):
                    malware.add(to["name"])
                if to.get("entity_type") in ("Threat-Actor-Group", "Threat-Actor-Individual", "Intrusion-Set") and to.get("name"):
                    actors.add(to["name"])
                if to.get("x_mitre_id"):
                    mitre.add(to["x_mitre_id"])
        if "allowlist" in [lab.lower() for lab in labels] or "whitelist" in [lab.lower() for lab in labels]:
            verdict = "allowlisted"
        elif score is None:
            verdict = "unknown"
        else:
            verdict = "malicious" if score >= 70 else "suspicious" if score >= 40 else "unknown"
        last = max((n.get("updated_at") or n.get("valid_from") or "" for n in obs + inds), default=None) or None
        return {
            "status": "ok", "verdict": verdict, "confidence": score, "tags": labels, "malware": sorted(malware),
            "threat_actors": sorted(actors), "mitre": sorted(mitre), "relationships": rels,
            "first_seen": min((n.get("created_at") or n.get("valid_from") or "" for n in obs + inds), default=None) or None,
            "last_seen": last, "freshness_days": freshness(last), "threat_type": "opencti_knowledge",
            "summary": f"{len(obs)} observable(s), {len(inds)} indicator(s) in OpenCTI (max score {score})",
        }
