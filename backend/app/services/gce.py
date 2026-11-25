"""Live view of the project's virtual machines for the Architecture page: state, machine type, GPU, addresses and the quotas that limit the layout.

Read-only. It uses the token of the VM's own service account (metadata server) against the Compute API; that account needs
roles/compute.viewer and the compute.readonly scope (set by scripts/gcp_vm.ps1). Off Google Cloud, or without that right, it returns
{"live": false, "reason": ...} and the page falls back to the static description. Nothing is cached for more than 15 seconds.
"""
from __future__ import annotations

import re
import time
from typing import Any

import httpx

MD = "http://metadata.google.internal/computeMetadata/v1"
_cache: dict[str, Any] = {"at": 0.0, "value": None}
# vCPU of the shared-core and the predefined types we use (the API returns the type name, not its size)
_SHARED = {"e2-micro": 2, "e2-small": 2, "e2-medium": 2}


def vcpus(machine_type: str) -> int | None:
    if machine_type in _SHARED:
        return _SHARED[machine_type]
    m = re.search(r"-(\d+)$", machine_type)
    return int(m.group(1)) if m else None


def _get(c: httpx.Client, url: str, token: str) -> dict:
    r = c.get(url, headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    return r.json()


def snapshot() -> dict:
    now = time.time()
    if _cache["value"] is not None and now - _cache["at"] < 15:
        return _cache["value"]
    out = _fetch()
    _cache.update(at=now, value=out)
    return out


def _fetch() -> dict:
    try:
        with httpx.Client(timeout=6.0) as c:
            h = {"Metadata-Flavor": "Google"}
            project = c.get(f"{MD}/project/project-id", headers=h).text.strip()
            token = c.get(f"{MD}/instance/service-accounts/default/token", headers=h).json()["access_token"]
            base = f"https://compute.googleapis.com/compute/v1/projects/{project}"
            agg = _get(c, f"{base}/aggregated/instances?maxResults=200", token)
            info = _get(c, base, token)
            region = _get(c, f"{base}/regions/us-central1", token)
    except Exception as e:  # noqa: BLE001 - any failure means "not live", never an error page
        return {"live": False, "reason": f"{type(e).__name__}: the Compute API could not be read from this machine (not on GCP, or the service account lacks roles/compute.viewer)"}
    vms = []
    for scope in agg.get("items", {}).values():
        for i in scope.get("instances", []):
            mt = i["machineType"].rsplit("/", 1)[-1]
            acc = [f"{a.get('acceleratorCount', 1)}x {a['acceleratorType'].rsplit('/', 1)[-1]}" for a in i.get("guestAccelerators", [])]
            vms.append({"name": i["name"], "zone": i["zone"].rsplit("/", 1)[-1], "status": i["status"], "machine_type": mt, "vcpus": vcpus(mt),
                        "gpu": acc, "provisioning": i.get("scheduling", {}).get("provisioningModel", "STANDARD"),
                        "internal_ip": (i.get("networkInterfaces") or [{}])[0].get("networkIP"),
                        "has_external_ip": bool((i.get("networkInterfaces") or [{}])[0].get("accessConfigs")),
                        "disks_gb": sum(int(d.get("diskSizeGb", 0)) for d in i.get("disks", []))})
    vms.sort(key=lambda v: v["name"])
    q = {x["metric"]: x for x in info.get("quotas", []) if x["metric"] in ("CPUS_ALL_REGIONS", "GPUS_ALL_REGIONS")}
    q.update({x["metric"]: x for x in region.get("quotas", []) if x["metric"] in ("IN_USE_ADDRESSES", "NVIDIA_T4_GPUS", "SSD_TOTAL_GB")})
    quotas = {k: {"limit": v["limit"], "usage": v["usage"]} for k, v in q.items()}
    running = [v for v in vms if v["status"] == "RUNNING"]
    return {"live": True, "project": project, "read_at": int(time.time()), "vms": vms, "quotas": quotas,
            "running_vcpus": sum(v["vcpus"] or 0 for v in running), "running_count": len(running)}
