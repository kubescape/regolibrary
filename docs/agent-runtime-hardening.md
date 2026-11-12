# Agent Runtime Hardening

The framework scans Kubernetes resources that Kubescape can discover: Agent
Sandbox `Sandbox` and `SandboxTemplate`, and Agent Substrate `WorkerPool`.

| Control | Evidence |
| --- | --- |
| C-0297 | Sandbox/Template `spec.podTemplate.spec.runtimeClassName` |
| C-0309 | Sandbox/Template service account token automounting |
| C-0311 | Sandbox/Template CPU and memory limits, including init containers |
| C-0312 | Sandbox/Template container images and WorkerPool `spec.workerImage`, pinned to lowercase SHA-256 digests |
| C-0313 | Registries of the same image fields |
| C-0314 | SandboxTemplate managed networking |
| C-0315 | Opt-in, explicit empty SandboxTemplate egress list |
| C-0316 | SandboxTemplate claim override policies |
| C-0317 | WorkerPool `spec.template.resources.limits` ceilings |

Runtime isolation reuses C-0297 and its `hardenedSandboxRuntimeClasses` input
(default: `gvisor`); there is no second runtime-class control or allowlist.
An absent or empty list disables the rule. Add `kata` to this shared list if
that RuntimeClass is approved in your cluster.

`imageRepositoryAllowList` is also disabled when absent or empty. When it
contains `docker.io`, unqualified images such as `nginx`, `nginx:1.27`,
`nginx@sha256:...`, and `library/nginx` are treated as Docker Hub references.
Explicit registry hosts and ports are not treated as Docker Hub.

C-0314 checks only controller management. It intentionally permits the managed
default, which allows public internet. The existing C-0301 egress control is
stronger: it requires an explicitly scoped policy. C-0315 is stricter still
when `agentSandboxEgressMode: ["strict"]` is enabled: it requires an explicit
`networkPolicy.egress: []` and permits no destinations. These are separate
posture requirements; managed networking alone does not establish strict egress.

Worker Pod ceilings use all configured `cpu_limit_max` and `memory_limit_max`
values, so limits must satisfy every configured maximum. They describe Worker
Pod resources, not per-actor limits.

## OWASP LLM and MITRE ATLAS mapping

This table relates each control to the
[OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
and to [MITRE ATLAS](https://atlas.mitre.org/) v5.6.0 (atlas-data release
v2026.10). It is guidance for reading findings, not a compliance claim, and it
is not encoded in the control JSON. A control appears only where it limits the
listed risk directly. These are posture checks: they reduce the impact of an
attack on the agent's runtime configuration, but they do not detect the attack
or prevent the prompt-level cause (for example LLM01 prompt injection).

| Control | OWASP LLM 2025 | ATLAS technique it constrains | ATLAS mitigation it implements |
| --- | --- | --- | --- |
| C-0297 hardened runtime class | LLM05 Improper Output Handling | AML.T0105 Escape to Host | AML.M0032 Segmentation of AI Agent Components |
| C-0309 service account token automounting | LLM06 Excessive Agency | AML.T0055 Unsecured Credentials (automounted token only) | AML.M0026 Privileged AI Agent Permissions Configuration |
| C-0311 container resource limits | LLM10 Unbounded Consumption (Pod CPU and memory only) | AML.T0029 Denial of AI Service; AML.T0034.002 Agentic Resource Consumption (local compute only) | AML.M0032 Segmentation of AI Agent Components |
| C-0312 image digest pinning | LLM03 Supply Chain | AML.T0010.004 Container Registry (pinned references do not follow a changed tag) | — |
| C-0313 image registries | LLM03 Supply Chain | AML.T0010.004 Container Registry | — |
| C-0314 managed network policy | — | — | — |
| C-0315 strict egress policy | LLM02 Sensitive Information Disclosure; LLM06 Excessive Agency (template policy only) | AML.T0025 Exfiltration via Cyber Means; AML.T0086 Exfiltration via AI Agent Tool Invocation (template policy only) | AML.M0032 Segmentation of AI Agent Components (template policy only) |
| C-0316 claim override restrictions | — | — | — |
| C-0317 Worker Pod resource ceilings | LLM10 Unbounded Consumption (Worker Pod CPU and memory only) | AML.T0029 Denial of AI Service; AML.T0034.002 Agentic Resource Consumption (local compute only) | AML.M0032 Segmentation of AI Agent Components |

Notes on the choices:

- **C-0297** maps to LLM05 because Agent Sandbox runs model-generated code,
  which is LLM output executed without review; gVisor or Kata limits what that
  code can reach. AML.M0032 names container isolation and code execution
  sandboxing directly.
- **C-0309** checks only `automountServiceAccountToken` on Sandbox and
  SandboxTemplate resources. It stops the automatically mounted token, but not
  a token the Pod mounts explicitly, for example through a projected volume.
- **C-0311 and C-0317** cap CPU and memory per Pod. They do not limit external
  API calls, token budgets or other spend outside the Pod, which is part of
  what AML.T0034.002 covers, and they do not cap per-actor use inside a shared
  Worker Pod (see above). They limit, not prevent, one actor starving others.
- **C-0312** checks only that each image reference has the form
  `@sha256:` followed by 64 lowercase hex characters. A pinned reference keeps
  pointing at the same image if a registry tag is later overwritten, which
  limits the effect of AML.T0010.004 on that workload. It does not stop the tag
  from being overwritten, and it does not check that the digest belongs to a
  trusted image: a malicious image also has a valid digest. It is therefore not
  mapped to AML.M0014 Verify AI Artifacts. Trusted-digest or signature
  verification is a separate control that this framework does not provide.
  **C-0313** only restricts which registries are trusted, so it has no
  mitigation entry either; it is not image signing (AML.M0013).
- **C-0314** checks only that SandboxTemplate networking is controller-managed.
  The managed default still allows public internet, so a passing result does
  not show segmentation or constrained egress, and the control is left
  unmapped.
- **C-0315** checks the SandboxTemplate's own policy: managed networking with
  an explicit empty `networkPolicy.egress` list. Kubernetes NetworkPolicies are
  additive, so another policy that selects the same Pod can still allow egress,
  and enforcement depends on the cluster's network plugin. A passing result
  constrains exfiltration only if no other policy opens egress for that Pod and
  the plugin enforces NetworkPolicy; check the effective policy in the cluster.
  The existing C-0301, outside this framework, requires an explicitly scoped
  policy as well.
- **C-0316** stops claims from replacing template environment variables or
  volume claim templates. No OWASP entry or ATLAS technique describes this
  Kubernetes-level override cleanly, so it is left unmapped.

## API scope

The WorkerPool field and resource ceilings were checked against
[WorkerPoolSpec at a9c1bd3](https://github.com/agent-substrate/substrate/blob/a9c1bd389403af59520e419d3884d447cf40edd2/pkg/api/v1alpha1/workerpool_types.go).
ActorTemplate is an [ATE protobuf resource](https://github.com/agent-substrate/substrate/blob/a9c1bd389403af59520e419d3884d447cf40edd2/pkg/proto/ateapipb/ateapi.proto),
not a Kubernetes CRD. Its environment variables carry literal name/value pairs,
not Kubernetes `secretKeyRef` fields. ActorTemplate image, secret-reference,
and snapshot-location checks are excluded until the scanner has a supported
source of that evidence. This framework makes no claims about actor snapshot
security or encryption.

The CEL companion policies use the same six self-contained controls: C-0297,
C-0309, and C-0311 through C-0314. Their missing/empty allowlist behavior and
Docker Hub resolution match the corresponding Rego rules.

## Validation

The focused framework contract check verifies that the published framework
contains the intended controls, that each control targets file and cluster
scans, and that its rule matches only the supported Agent Sandbox and Agent
Substrate resources:

```shell
go test ./gitregostore -run TestAgentRuntimeFrameworkContract -count=1
```

The individual rule fixture suite remains the source of truth for policy
behavior:

```shell
cd testrunner
go test -tags=static rego_test.go -run TestAllRules
```
