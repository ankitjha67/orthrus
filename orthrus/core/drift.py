"""Attack-surface drift detection (ASM).

Compares a fresh recon snapshot against a stored baseline and reports what
*changed* about the attack surface: hosts that appeared or vanished, new IP
addresses behind a host, and newly-observed open ports. Drift is the signal
that turns ORTHRUS from a point-in-time scanner into continuous monitoring — a
new subdomain or a freshly-exposed port is exactly what a defender wants paged
about.

Pure and deterministic: ``compute_asset_drift`` takes two asset lists and
returns a structured diff, with no I/O — so it is trivially unit-testable and
reusable by the ``monitor`` command, the API, and alert webhooks.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from orthrus.core import schemas


@dataclass
class HostChange:
    """A host present in both snapshots whose IPs or ports moved."""

    fqdn: str
    new_ips: list[str] = field(default_factory=list)
    removed_ips: list[str] = field(default_factory=list)
    new_ports: list[int] = field(default_factory=list)
    removed_ports: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "fqdn": self.fqdn,
            "new_ips": self.new_ips,
            "removed_ips": self.removed_ips,
            "new_ports": self.new_ports,
            "removed_ports": self.removed_ports,
        }


@dataclass
class AssetDrift:
    """The structured difference between a baseline and a current snapshot."""

    new_hosts: list[schemas.Asset] = field(default_factory=list)
    removed_hosts: list[str] = field(default_factory=list)
    changed_hosts: list[HostChange] = field(default_factory=list)
    unchanged: int = 0
    baseline_count: int = 0
    current_count: int = 0
    is_baseline: bool = False  # True when there was no prior snapshot to compare

    @property
    def has_changes(self) -> bool:
        return bool(self.new_hosts or self.removed_hosts or self.changed_hosts)

    def summary(self) -> str:
        if self.is_baseline:
            return f"baseline established: {self.current_count} host(s) recorded"
        if not self.has_changes:
            return f"no drift — {self.unchanged} host(s) unchanged"
        return (
            f"{len(self.new_hosts)} new, {len(self.removed_hosts)} removed, "
            f"{len(self.changed_hosts)} changed host(s)"
        )

    def to_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "has_changes": self.has_changes,
            "is_baseline": self.is_baseline,
            "baseline_count": self.baseline_count,
            "current_count": self.current_count,
            "unchanged": self.unchanged,
            "new_hosts": [{"fqdn": a.fqdn, "ips": list(a.ips),
                           "discovery_method": a.discovery_method} for a in self.new_hosts],
            "removed_hosts": list(self.removed_hosts),
            "changed_hosts": [c.to_dict() for c in self.changed_hosts],
        }


def compute_asset_drift(
    baseline: list[schemas.Asset],
    current: list[schemas.Asset],
    *,
    is_baseline: bool = False,
) -> AssetDrift:
    """Diff two asset snapshots by FQDN.

    ``is_baseline=True`` (or an empty baseline) marks the run as the first
    snapshot — everything in ``current`` is recorded without raising new-host
    noise, since there is nothing to compare against.
    """
    base = {a.fqdn: a for a in baseline}
    cur = {a.fqdn: a for a in current}
    first_run = is_baseline or not base

    new_hosts = [cur[f] for f in sorted(cur) if f not in base]
    removed_hosts = sorted(f for f in base if f not in cur)

    changed: list[HostChange] = []
    unchanged = 0
    for fqdn in sorted(set(base) & set(cur)):
        b, c = base[fqdn], cur[fqdn]
        new_ips = sorted(set(c.ips) - set(b.ips))
        removed_ips = sorted(set(b.ips) - set(c.ips))
        new_ports = sorted(set(c.ports) - set(b.ports))
        removed_ports = sorted(set(b.ports) - set(c.ports))
        if new_ips or removed_ips or new_ports or removed_ports:
            changed.append(HostChange(fqdn, new_ips, removed_ips, new_ports, removed_ports))
        else:
            unchanged += 1

    return AssetDrift(
        new_hosts=[] if first_run else new_hosts,
        removed_hosts=[] if first_run else removed_hosts,
        changed_hosts=[] if first_run else changed,
        unchanged=unchanged,
        baseline_count=len(base),
        current_count=len(cur),
        is_baseline=first_run,
    )


__all__ = ["AssetDrift", "HostChange", "compute_asset_drift"]
