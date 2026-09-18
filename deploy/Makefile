# Local kind deployment for the audit-triage service.
# Run from the deploy/ directory: `make cluster-up build load secret deploy`.
# Prereqs: docker, kind, kubectl. See README.md.

IMG      ?= audit-triage:local
CLUSTER  ?= audit-triage
NS       ?= audit-triage
CALICO   ?= https://raw.githubusercontent.com/projectcalico/calico/v3.28.2/manifests/calico.yaml

.PHONY: help build cluster-up calico load secret deploy verify-rbac verify-netpol test-pods logs clean

help:
	@echo "Targets: cluster-up  build  load  secret  deploy  verify-rbac  verify-netpol  clean"
	@echo "Typical: make cluster-up build load secret deploy verify-rbac test-pods verify-netpol"

# Build the image (context is the repo root, one level up).
build:
	docker build -f ../Dockerfile -t $(IMG) ..

# Create a kind cluster with the default CNI disabled, then install Calico (enforces NetworkPolicy).
cluster-up:
	kind create cluster --name $(CLUSTER) --config kind-cluster.yaml
	$(MAKE) calico

calico:
	kubectl apply -f $(CALICO)
	kubectl -n kube-system rollout status deploy/calico-kube-controllers --timeout=180s

# Side-load the locally built image into the cluster (no registry needed).
load:
	kind load docker-image $(IMG) --name $(CLUSTER)

# Create the API-key Secret from your environment (never committed to a file).
# Requires TRIAGE_API_KEY to be set: `export TRIAGE_API_KEY=sk-...` or `set -a; . ../.env; set +a`.
secret:
	@test -n "$(TRIAGE_API_KEY)" || (echo "ERROR: export TRIAGE_API_KEY first (or: set -a; . ../.env; set +a)"; exit 1)
	kubectl apply -f k8s/namespace.yaml
	kubectl -n $(NS) create secret generic audit-triage-secret \
	  --from-literal=TRIAGE_API_KEY="$(TRIAGE_API_KEY)" \
	  --dry-run=client -o yaml | kubectl apply -f -

# Apply everything (namespace first so PSS labels exist before pods are admitted).
deploy:
	kubectl apply -f k8s/namespace.yaml
	kubectl apply -f k8s/serviceaccount.yaml
	kubectl apply -f k8s/rbac.yaml
	kubectl apply -f k8s/configmap.yaml
	kubectl apply -f k8s/service.yaml
	kubectl apply -f k8s/networkpolicy.yaml
	kubectl apply -f k8s/deployment.yaml
	kubectl -n $(NS) rollout status deploy/audit-triage --timeout=180s

# Least privilege: the service account must NOT be able to touch the API. Expect "no".
verify-rbac:
	@echo -n "can the SA list pods? "; \
	kubectl auth can-i list pods --as=system:serviceaccount:$(NS):audit-triage-sa -n $(NS)

test-pods:
	kubectl apply -f k8s/test-client.yaml
	kubectl -n $(NS) wait --for=condition=Ready pod/allowed-client pod/denied-client --timeout=120s

# Whitelist check: allowed-client (labelled) reaches the service, denied-client times out.
verify-netpol:
	@echo "== allowed-client (role=triage-client) -> expect HTTP 200 =="; \
	kubectl -n $(NS) exec allowed-client -- \
	  curl -s -o /dev/null -w "%{http_code}\n" --max-time 5 http://audit-triage:8000/health || true
	@echo "== denied-client (no label) -> expect a timeout / failure =="; \
	kubectl -n $(NS) exec denied-client -- \
	  curl -s -o /dev/null -w "%{http_code}\n" --max-time 5 http://audit-triage:8000/health || echo "blocked (as expected)"

logs:
	kubectl -n $(NS) logs deploy/audit-triage --tail=50

clean:
	kind delete cluster --name $(CLUSTER)
