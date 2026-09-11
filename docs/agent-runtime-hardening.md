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
