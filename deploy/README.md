# Local Kubernetes deployment (kind)

Containerize the audit-triage service and run it on a local [kind](https://kind.sigs.k8s.io/)
cluster with a **deliberately minimal** security posture: a dedicated ServiceAccount with no API
token, an empty RBAC Role, a default-deny NetworkPolicy with a single whitelisted client, and the
Pod Security "restricted" profile enforced on the namespace.

The point isn't "it runs" — it's a concrete, verifiable story about least privilege.

## Prerequisites

Not installed by default on this machine. Install first:

```bash
# Docker Desktop (or colima) — provides the docker daemon
brew install --cask docker      # then launch it once so the daemon is running
# kind + kubectl
brew install kind kubectl
```

You also need the DeepSeek key available (the same one the app uses):

```bash
set -a; . ../.env; set +a        # loads TRIAGE_API_KEY / TRIAGE_BASE_URL / TRIAGE_MODEL
```

## Run it

From this `deploy/` directory:

```bash
make cluster-up      # kind cluster with default CNI off + Calico (so NetworkPolicy is enforced)
make build           # docker build the image (context is the repo root)
make load            # side-load the image into the cluster (no registry)
make secret          # create the API-key Secret from $TRIAGE_API_KEY (never written to a file)
make deploy          # namespace, SA, RBAC, config, service, netpol, deployment
```

Then check it:

```bash
make verify-rbac     # expect: no    (the SA cannot touch the K8s API)
make test-pods       # launch the two probe pods
make verify-netpol   # allowed-client -> 200, denied-client -> blocked
make logs
make clean           # delete the cluster
```

To hit the API yourself: `kubectl -n audit-triage port-forward svc/audit-triage 8000:8000`, then
`curl localhost:8000/health`.

## What each piece is doing — and why

| Object | Choice | Why (the talking point) |
|---|---|---|
| `ServiceAccount` | `automountServiceAccountToken: false` | The app never calls the K8s API, so it shouldn't carry an API token at all. No token = nothing to steal. |
| `Role` | `rules: []` (empty) + `RoleBinding` | Least privilege taken literally: the right permission set for this workload is **none**. Writing the empty Role documents the decision instead of leaving it implicit. |
| `Namespace` | `pod-security…/enforce: restricted` | The API server rejects any pod that runs as root, allows privilege escalation, or keeps Linux capabilities. Security is enforced at admission, not by convention. |
| `Deployment` securityContext | non-root uid 10001, drop ALL caps, no priv-esc, seccomp RuntimeDefault | The concrete settings that satisfy "restricted". The image is built non-root to match. |
| `Secret` | created imperatively from env, `secret.example.yaml` is a shape-only template | A key committed in a manifest is only base64 in etcd, not encrypted. Keep it out of git entirely. |
| `NetworkPolicy` | default-deny ingress + one labelled whitelist | Pod-to-pod traffic is open by default; this closes it and opens exactly one hole (`role=triage-client` → `:8000`). |

## Gotchas worth knowing (and mentioning)

- **kind's default CNI doesn't enforce NetworkPolicy.** kindnet applies the objects but ignores
  them, so a policy can look "applied" while doing nothing. `kind-cluster.yaml` disables the default
  CNI and `make cluster-up` installs Calico so the policy is real. This is the single most common
  way people are fooled into thinking their NetworkPolicy works.
- **NetworkPolicy is a whitelist, and empty ingress means deny-all** — not allow-all. The
  `default-deny-ingress` object has no `ingress:` rules on purpose.
- **`restricted` PSS does not require `readOnlyRootFilesystem`.** It's left off here so the app can
  write `report.md` and libraries can use `/tmp`. Turning it on is a good next hardening step, but it
  needs an `emptyDir` mount for `/tmp` (and the report path) — otherwise the container can't start.
- **Least privilege usually means *no* RBAC.** The instinct to grant a Role with some read verbs is
  often wrong: most application workloads never call the API server, so the correct Role is empty.

## If an interviewer asks "why is the Role empty?"

Because the service doesn't operate the cluster — it parses logs, calls an LLM, and returns a
report. Least privilege means granting exactly what the workload needs, and this one needs nothing
from the Kubernetes API. So the token is turned off and the Role grants nothing; `kubectl auth
can-i list pods --as=…audit-triage-sa` returns `no`, which is the verifiable proof.
