#!/usr/bin/env python3
"""Review Kubernetes NetworkPolicy YAML scope without connecting to a cluster."""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path

import yaml

MAX_BYTES = 1_000_000
MAX_POLICIES = 200
SEVERITIES = {"high": 3, "medium": 2, "low": 1}
RULES = {
    "NP001": ("medium", "Targets every pod in namespace", "Confirm a namespace-wide policy is intentional."),
    "NP002": ("low", "policyTypes inferred", "Specify Ingress and/or Egress explicitly for review clarity."),
    "NP003": ("high", "All peers allowed by this rule", "Add a bounded from/to selector or IP range if unrestricted peers are unintended."),
    "NP004": ("high", "Peer matches every namespace", "Scope namespaceSelector using labels to avoid all-namespace matching."),
    "NP005": ("high", "Peer IP block covers every address", "Restrict CIDR; verify NAT and CNI behavior for IP-based policies."),
    "NP006": ("medium", "Rule matches all ports", "If this is unintended, specify the allowed port/protocol list."),
    "NP007": ("medium", "Separate peers are OR, not AND", "Put namespaceSelector and podSelector into the SAME peer object to combine them."),
    "NP008": ("low", "Direction has no allow rules", "Confirm this default-deny direction is intentional for selected pods."),
}


def label(value: object) -> str:
    if not isinstance(value, str):
        return "unnamed"
    return re.sub(r"[^A-Za-z0-9_.:/-]", "?", value[:100]) or "unnamed"


def finding(rule: str, location: str) -> dict[str, str]:
    severity, title, advice = RULES[rule]
    return {"rule": rule, "severity": severity, "location": location, "title": title, "review": advice}


def empty_selector(selector: object) -> bool:
    if not isinstance(selector, dict):
        raise ValueError("selector must be a mapping")
    if not selector:
        return True
    return selector.get("matchLabels", None) == {} and not selector.get("matchExpressions") or (
        selector.get("matchLabels") is None and selector.get("matchExpressions") == []
    )


def all_cidr(cidr: object) -> bool:
    if not isinstance(cidr, str):
        return False
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return net.prefixlen == 0


def policy_types(spec: dict) -> tuple[set[str], bool]:
    types = spec.get("policyTypes")
    if types is None:
        return {"Ingress"} | ({"Egress"} if spec.get("egress") else set()), True
    if not isinstance(types, list) or not types or any(v not in ("Ingress", "Egress") for v in types):
        raise ValueError("policyTypes must be non-empty list of Ingress/Egress")
    return set(types), False


def assess_policy(policy: dict) -> list[dict[str, str]]:
    if not isinstance(policy, dict) or policy.get("kind") != "NetworkPolicy":
        raise ValueError("expected NetworkPolicy mapping")
    spec = policy.get("spec")
    if not isinstance(spec, dict) or "podSelector" not in spec:
        raise ValueError("NetworkPolicy missing spec.podSelector")
    metadata = policy.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be mapping")
    location = f"{label(metadata.get('namespace', 'default'))}/{label(metadata.get('name'))}"
    findings: list[dict[str, str]] = []
    if empty_selector(spec["podSelector"]):
        findings.append(finding("NP001", location))
    types, inferred = policy_types(spec)
    if inferred:
        findings.append(finding("NP002", location))
    for direction, field, peer_key in (("Ingress", "ingress", "from"), ("Egress", "egress", "to")):
        if direction not in types:
            continue
        rules = spec.get(field)
        if rules is None:
            rules = []
        if not isinstance(rules, list):
            raise ValueError(f"spec.{field} must be a list")
        if not rules:
            findings.append(finding("NP008", location + "/" + field))
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise ValueError(f"spec.{field}[{i}] must be a mapping")
            here = f"{location}/{field}[{i}]"
            peers = rule.get(peer_key)
            # Kubernetes: missing/empty from/to matches all peers; [] is not a deny-all.
            if peers is None or peers == []:
                findings.append(finding("NP003", here))
                peers = []
            if not isinstance(peers, list):
                raise ValueError(f"{here}/{peer_key} must be a list")
            if rule.get("ports") is None or rule.get("ports") == []:
                findings.append(finding("NP006", here))
            elif not isinstance(rule.get("ports"), list):
                raise ValueError(f"{here}/ports must be a list")
            saw_ns_only = saw_pod_only = False
            for j, peer in enumerate(peers):
                if not isinstance(peer, dict):
                    raise ValueError(f"{here}/{peer_key}[{j}] must be a mapping")
                p_here = f"{here}/{peer_key}[{j}]"
                ns = peer.get("namespaceSelector")
                pod = peer.get("podSelector")
                if ns is not None:
                    if empty_selector(ns):
                        findings.append(finding("NP004", p_here))
                    if pod is None:
                        saw_ns_only = True
                if pod is not None:
                    empty_selector(pod)
                    if ns is None:
                        saw_pod_only = True
                block = peer.get("ipBlock")
                if block is not None:
                    if not isinstance(block, dict) or not isinstance(block.get("cidr"), str):
                        raise ValueError(f"{p_here}/ipBlock requires CIDR")
                    if all_cidr(block["cidr"]):
                        findings.append(finding("NP005", p_here))
            if saw_ns_only and saw_pod_only:
                findings.append(finding("NP007", here))
    return findings


def collect_policies(documents: list[object]) -> tuple[list[dict], int]:
    policies = []
    skipped = 0
    for doc in documents:
        if doc is None:
            continue
        if not isinstance(doc, dict):
            raise ValueError("YAML document is not an object")
        if doc.get("kind") == "List":
            items = doc.get("items")
            if not isinstance(items, list):
                raise ValueError("List.items must be a list")
        else:
            items = [doc]
        for item in items:
            if not isinstance(item, dict):
                raise ValueError("non-object manifest entry")
            if item.get("kind") == "NetworkPolicy":
                policies.append(item)
            else:
                skipped += 1
            if len(policies) > MAX_POLICIES:
                raise ValueError("too many NetworkPolicy manifests")
    return policies, skipped


def analyze(documents: list[object]) -> dict:
    policies, skipped = collect_policies(documents)
    if not policies:
        raise ValueError("no NetworkPolicy resources found")
    findings = [f for p in policies for f in assess_policy(p)]
    levels = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (levels[f["severity"]], f["rule"], f["location"]))
    return {"tool": "k8s-netpol-scope-audit", "policy_count": len(policies),
            "skipped_non_networkpolicies": skipped, "findings": findings,
            "limits": "Static manifest review only; policy union, workloads, namespace labels, CNI/NAT, service translation and live traffic are not evaluated."}


def load_documents(path: Path) -> list[object]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("expected regular non-symlink YAML/JSON file")
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("manifest exceeds 1 MB cap")
    with path.open("r", encoding="utf-8") as src:
        docs = list(yaml.safe_load_all(src))
    if len(docs) > MAX_POLICIES:
        raise ValueError("too many YAML documents")
    return docs


def render_markdown(result: dict) -> str:
    lines = ["# Kubernetes NetworkPolicy scope review", "", f"Policies: {result['policy_count']} | Findings: {len(result['findings'])}", "",
             "| Severity | Rule | Scope | Human review |", "|---|---|---|---|"]
    for f in result["findings"]:
        lines.append(f"| {f['severity']} | {f['rule']} | `{f['location']}` | {f['review']} |")
    return "\n".join(lines + ["", result["limits"]])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("manifest", type=Path)
    p.add_argument("--format", choices=("json", "markdown"), default="markdown")
    p.add_argument("--fail-on", choices=("high", "medium", "low", "none"), default="high")
    args = p.parse_args(argv)
    try:
        result = analyze(load_documents(args.manifest))
    except yaml.YAMLError:
        print("Invalid manifest: YAML parser rejected this input (details withheld to protect values)", file=sys.stderr)
        return 1
    except (OSError, ValueError, UnicodeError, RecursionError) as error:
        print(f"Invalid manifest: {type(error).__name__}: {str(error)[:140]}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2) if args.format == "json" else render_markdown(result))
    if args.fail_on != "none" and any(SEVERITIES[f["severity"]] >= SEVERITIES[args.fail_on] for f in result["findings"]):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
