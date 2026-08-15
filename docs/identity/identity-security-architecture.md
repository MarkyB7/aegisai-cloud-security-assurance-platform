# AegisAI Identity Security Architecture

## Purpose

AegisAI implements a Zero Trust identity security architecture that
combines authentication, fine-grained authorization, policy-as-code,
authorization evidence, identity governance, and identity lifecycle
management.

The architecture follows a simple security flow:

**WHO → PROVE → ASK → DECIDE → ENFORCE → RECORD → REVIEW**

---

## 1. WHO — Identity

AegisAI uses a normalized identity model so downstream security
components operate on consistent identity information.

Identity attributes can include:

- User ID
- Username
- Role
- Department
- Clearance
- Authentication state

---

## 2. PROVE — Authentication

AegisAI validates signed JWTs before establishing a trusted identity
context.

Validation includes:

- Signature validation
- Trusted issuer
- Expected audience
- Token expiration
- Token use
- Required identity claims

Authentication failures fail closed.

---

## 3. ASK — Authorization Request

Access requests are represented using:

**Principal + Action + Resource + Context (PARC)**

Example:

- Principal: Finance Analyst
- Action: Read
- Resource: Finance Knowledge Base
- Context: Production

---

## 4. DECIDE — Authorization

AegisAI maintains a provider-neutral authorization contract.

For AWS deployments, the Amazon Verified Permissions adapter translates
AegisAI authorization requests into the principal, action, resource,
entities, and context expected by Amazon Verified Permissions.

Cedar policies provide externalized policy-as-code for fine-grained
authorization.

Authorization uses explicit ALLOW or DENY decisions and defaults to
DENY when authorization cannot be established.

---

## 5. ENFORCE — Access Decision

Authorization results are normalized into an AegisAI
AuthorizationDecision.

The decision contains:

- Effect
- Reason
- Policy ID
- Request ID
- Decision ID

Denied decisions are blocked from proceeding.

Provider failures and unknown authorization conditions fail closed.

---

## 6. RECORD — Authorization Evidence

Authorization decisions generate security evidence for investigation,
audit, and compliance use cases.

Before persistence, evidence is:

1. Sanitized
2. Assigned retention metadata
3. Protected with a deterministic SHA-256 integrity digest
4. Persisted through the audit sink
5. Available for later integrity verification

This provides tamper-evidence while minimizing unnecessary sensitive
data collection.

---

## 7. REVIEW — Identity Governance

AegisAI evaluates whether existing access should continue to exist.

Governance checks include:

- Stale entitlements
- Privileged access
- Separation-of-Duties conflicts
- Risk-based access review

Access review produces:

- KEEP
- REVIEW
- REMOVE

---

## Joiner-Mover-Leaver Lifecycle

AegisAI also governs identity lifecycle changes.

### Joiner

Grant access required for the new role.

### Mover

Calculate the entitlement delta between current and target access:

- Revoke access no longer required
- Preserve shared access
- Grant newly required access
- Revoke existing sessions

This helps prevent privilege creep.

### Leaver

- Revoke existing access
- Revoke sessions
- Disable the identity

---

## Lifecycle Governance

Joiner and Mover target access is evaluated through the access-review
layer before being treated as safe.

The lifecycle engine answers:

**What access changes?**

The governance engine answers:

**Is the resulting access safe?**

Privileged access or Separation-of-Duties conflicts can require
additional approval before access changes proceed.

---

## Security Principles

The Identity Security architecture demonstrates:

- Zero Trust
- Least Privilege
- Default Deny
- Fail-Closed Security
- Fine-Grained Authorization
- Attribute-Based Access Control
- Policy-as-Code
- Separation of Duties
- Identity Governance
- Access Certification
- Joiner-Mover-Leaver Governance
- Privilege Creep Prevention
- Auditability
- Evidence Integrity
- Data Minimization
