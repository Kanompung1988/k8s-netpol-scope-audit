# NetworkPolicy scope review rules

| Rule | Level | Supported signal | Human context |
|---|---|---|---|
| NP001 | MEDIUM | `spec.podSelector: {}` or empty selector expressions | Policy targets all pods in its namespace; can be intentional. |
| NP002 | LOW | `policyTypes` omitted | Defaults to Ingress; additionally Egress when egress list has entries. |
| NP003 | HIGH | Rule with missing/empty `from` (ingress) or `to` (egress) | All peers match for that rule; can be intentionally broad. |
| NP004 | HIGH | Peer `namespaceSelector: {}` | Selects all namespaces (subject to any combined pod selector). |
| NP005 | HIGH | `ipBlock.cidr` equals IPv4 or IPv6 `0/0` | Matches entire address family; NAT/CNI semantics require review. |
| NP006 | MEDIUM | Rule `ports` absent or empty | All ports match for peers selected by that rule. |
| NP007 | MEDIUM | Separate namespace-only and pod-only peer entries in same rule | OR semantics; combine in the same list element for AND. |
| NP008 | LOW | `policyTypes` includes direction but corresponding rules absent | Selected pods default-deny the direction (subject to union with other policies). |

**Out of scope:** resource schema validation, selector `matchExpressions` satisfiability, aggregated effective policy across manifests and cluster, CNI behavior, label inventory, pod-node traffic and service NAT. The scanner never claims enforcement and does not inspect workload secrets.
