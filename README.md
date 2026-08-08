# 📘 OmniBioAI Policy Engine

**Policy Engine is the authorization brain of the OmniBioAI ecosystem.**
It evaluates *who can do what*, *on which resource*, under *what conditions*.

It enforces RBAC + ABAC rules across distributed systems like TES, Workbench, Studio, and future HPC services.

---

## 🧠 What this service does

The Policy Engine answers a single question:

> **"Is this user allowed to perform this action on this resource?"**

It evaluates:

* Role-Based Access Control (RBAC)
* Attribute-Based Access Control (ABAC)
* Custom business rules
* HPC constraints (GPU / cluster / quota)
* Dataset-level access policies

---

## 🧬 Architecture Role

```
                 ┌────────────────────┐
                 │  Auth Service      │
                 │  (Identity)        │
                 └─────────┬──────────┘
                           │
                 ┌─────────▼──────────┐
                 │ IAM Client         │
                 │ (Fast cache layer) │
                 └─────────┬──────────┘
                           │
                 ┌─────────▼──────────┐
                 │ Policy Engine      │
                 │ (Decision layer)   │
                 └─────────┬──────────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
      TES             Workbench           Studio
```

---

## ⚙️ Core Features

### 🔐 RBAC (Role-Based Access Control)

* Admin, researcher, data scientist roles
* Action-level restrictions

### 🧠 ABAC (Attribute-Based Access Control)

* GPU usage restrictions
* HPC node access control
* Dataset sensitivity rules

### 📜 Rule Engine

* Domain-specific policies
* Bioinformatics dataset protection rules
* Model registry immutability rules

### 🔑 Permission-aware authorization

A second, additive gate alongside role-name/action-string RBAC
(`app/core/rbac.py`): `app/core/permissions.py`'s `ACTION_PERMISSION_MAP`
checks the requester's `permissions` claim (forwarded by
`omnibioai-api-gateway`'s `PolicyMiddleware` on every `/policy/evaluate`
call) against the same permission-registry strings `omnibioai-auth`
reserves (`workflow.execute`, `model.use`, `dataset.read`, etc.) —
this is the receiving end of the gateway's own
`SERVICE_PERMISSION_MAP` (see
[omnibioai-api-gateway's README](../omnibioai-api-gateway#authentication-pipeline)).
Deliberately opt-in: a caller with `permissions=[]` falls back to the
pre-existing role-based check, so nothing changes for traffic that
predates permission-awareness.

### 🏢 Org-tenancy scoping

`app/core/tenancy.py` adds an opt-in tenancy gate: if a request names
which organization owns the resource being acted on
(`context["resource_org_id"]`), the requester's own `org_id` must match
it. This service has no database of its own to look resource ownership
up in, so it can only enforce this when a caller explicitly supplies it
— a no-op for every caller today (no real caller populates
`resource_org_id` yet). See [Roadmap](#roadmap) below.

---

## 🚀 API Overview

### Evaluate Policy

```http
POST /policy/evaluate
```

---

### Request

```json
{
  "user_id": "123",
  "roles": ["researcher"],
  "permissions": [],
  "action": "tes.run_workflow",
  "resource": "rnaseq_pipeline",
  "context": {
    "gpu_required": true,
    "node": "hpc"
  }
}
```

---

### Response

```json
{
  "allowed": true,
  "reason": "access granted",
  "policy_source": "ALL_PASSED"
}
```

---

## Running

### Via OmniBioAI Studio (recommended)

```bash
cd ~/Desktop/machine/omnibioai-studio
docker compose up -d policy-engine
```

Access (internal only — not exposed externally):
`http://policy-engine:8001` (Docker internal network)

### Standalone (development)

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```

### Health check

```bash
curl http://localhost:8001/health
# {"status": "ok"}
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://redis:6379` | Redis for policy cache |
| `OPA_URL` | — | Optional OPA backend URL |

---

## Repository Structure

```text
app/
├── main.py
├── api/
│   ├── routes_policy.py   # POST /policy/evaluate — the only route
│   └── deps.py
├── core/
│   ├── engine.py          # Orchestrates RBAC → ABAC → permissions → tenancy → rules
│   ├── rbac.py             # Role-name/action-string check
│   ├── abac.py              # Attribute-based checks (GPU, HPC node, dataset sensitivity)
│   ├── permissions.py       # ACTION_PERMISSION_MAP — see "Permission-aware authorization" above
│   ├── tenancy.py            # Opt-in org_id scoping gate — see "Org-tenancy scoping" above
│   └── rules.py               # Domain-specific policy rules
├── services/
│   ├── policy_service.py      # Service-layer orchestration
│   └── cache.py                # Redis-backed decision cache
├── models/
│   ├── request.py, policy.py, decision.py   # Pydantic request/response models
└── db/                          # Present but unused today — this service has no
                                   # database of its own (see "Org-tenancy scoping")
```

---

## 🧠 Policy Evaluation Flow

1. **RBAC check**

   * Validates user roles

2. **ABAC check**

   * Evaluates runtime context (GPU, HPC, etc.)

3. **Rule engine**

   * Applies domain-specific constraints

4. **Decision returned**

   * ALLOW / DENY + reason

---

## 🧩 Integration Points

This service is used by:

* TES (workflow execution authorization)
* Workbench (dataset access control)
* Studio (pipeline execution control)
* IAM Client (future cached policy decisions)

---

## Testing

```bash
cd ~/Desktop/machine/omnibioai-policy-engine
pytest tests/ -v --cov=.

# 90 tests passing
# 95% coverage
# Covers: RBAC, ABAC, rule engine, cache, policy service, routes
```

---

## ⚡ Design Philosophy

* Stateless API
* Deterministic decisions
* Fast evaluation (<10ms target)
* Extendable rule system
* HPC-aware security model

---

## 🧪 Example Use Cases

### 1. Prevent GPU abuse

* Only GPU-enabled users can run ML pipelines

### 2. Protect genomic datasets

* Human genome datasets require elevated permissions

### 3. Control HPC usage

* Cluster-specific access control

### 4. Secure model registry

* Prevent deletion of production models

---

## Roadmap

| Feature | Status |
|---------|--------|
| Redis caching for policy decisions | ✓ Implemented |
| RBAC/ABAC evaluation | ✓ Stable |
| Custom rule engine | ✓ Stable |
| Permission-aware authorization (`app/core/permissions.py`) | ✓ Implemented — see [Permission-aware authorization](#permission-aware-authorization) below |
| Org-tenancy scoping gate (`app/core/tenancy.py`) | ✓ Implemented, opt-in — activates only once a caller supplies `context["resource_org_id"]`; no real caller does yet |
| OPA (Open Policy Agent) backend | Planned |
| Policy versioning system | Planned |
| Org-level multi-tenancy enforced by default | Planned v0.5 |

---

## 🛠 Tech Stack

* FastAPI
* Python 3.11+
* Pydantic models
* Pluggable RBAC/ABAC engine
* Redis caching (implemented)

---

## Related Services

| Service | Role |
|---------|------|
| `omnibioai-api-gateway` | Calls `/policy/evaluate` on every request |
| `omnibioai-auth` | Provides identity (roles/permissions) to policy engine |
| `omnibioai-hpc-policy-engine` | Handles compute-specific governance |
| `omnibioai-security-audit` | Receives policy decision audit events |
| `omnibioai-studio` | Manages policy-engine container lifecycle |

---

## 🧬 Why this exists

In a distributed bioinformatics + AI system, you need:

* Compute governance
* Data protection
* Reproducibility control
* Multi-user safety

This service ensures **every action is explicitly authorized**.

---

## 🧠 Summary

The Policy Engine is the **decision-making layer** of OmniBioAI.

If Auth says:

> “Who are you?”

Then Policy Engine says:

> “What are you allowed to do?”

