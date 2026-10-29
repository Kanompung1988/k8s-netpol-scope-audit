---
name: k8s-netpol-scope-audit
description: Review Kubernetes NetworkPolicy manifests offline for unexpectedly broad pod, namespace, peer, CIDR and port selectors; explain default isolation and OR-versus-AND peer semantics before deployment. Use for PR reviews of local YAML/JSON policies, not live cluster enforcement tests.
license: MIT
compatibility: Python 3.10+ with PyYAML 6.0.3. Local YAML/JSON NetworkPolicy documents only; no kubectl, cluster credentials or network access.
metadata:
  author: AREAZERO Skill Lab
  version: "1.0.0"
---

# Explain NetworkPolicy scope before deploy

## Trigger
Use during Kubernetes manifest or Helm-rendered policy review, when a developer asks what pod, namespace, peer, IP and port scopes the policy appears to select. Works offline on *rendered* NetworkPolicy YAML/JSON including multi-document streams and Kubernetes `List` items.

## Non-trigger
Do not use to prove live reachability, enumerate running Pods, account for full additive effects across a cluster, evaluate CNI behavior, validate service NAT, or replace server-side Kubernetes API validation. Never contact a cluster, deploy manifests or request credentials.

## Procedure
1. Render Helm/Kustomize manifests in a trusted workspace if applicable; save them locally. The scanner itself only reads YAML/JSON files.
2. `python -m pip install -r requirements.txt`, then `python scripts/audit.py path/to/rendered.yaml --format markdown --fail-on high`.
3. Review NP001–NP008 in [rule reference](references/RULES.md). A missing `from`/`to` list in a rule means **all peers**, not deny-all; absence of entire `ingress`/`egress` rule list with that direction selected instead means default deny in that direction.
4. Distinguish separate peer list entries (OR) from a **single** entry containing both namespaceSelector and podSelector (AND). Verify label availability and unintended namespaces with a human operator before deployment.
5. Explain the difference between YAML static scope and real enforcement: multiple NetworkPolicies are **additive**, pod ingress and egress isolation both matter, CNI support is required, and node/service NAT may affect IP-based policies. Do not state a static green result proves secure network isolation.

## Examples and exit codes
`python scripts/audit.py examples/safe-policy.yaml --format json --fail-on high` exits **0**; `python scripts/audit.py examples/review-policy.yaml --format markdown --fail-on high` exits **2**. `--fail-on none` exits **0** for readable inputs, but still reports findings. Exit **1** means invalid or unsafe input. Test with `python -m unittest discover -s tests -v`.

## Safety boundaries
Static read-only review, with 1 MB file and 200-policy caps, safe YAML loading and no network. Findings can be *intentional* (namespace-wide policy, all-port access or default deny). Policies combine additively; this tool never says an individual policy is an effective deny for all traffic. Names and namespace labels may reveal environment information; review generated reports before sharing. Technical basis: [Kubernetes NetworkPolicy](references/SOURCES.md).
