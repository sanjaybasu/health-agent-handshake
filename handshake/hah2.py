"""Reference implementation of the Health Agent Handshake (HAH), version 2.

Version 1 (hah.py) is hash-locked as the verifier used by the pre-registered benchmark backend. Version 2
closes defects found in adversarial review (2026-10-05):
  - consent binds operator, agent, subject commitment, purpose of use and expiry, and carries the elements of
    a 45 CFR 164.508 authorization; the identity-provider certificate binds the key to the same subject
  - tier 3 approvals are verified under the root (identity-provider-certified) patient key and bind the
    action parameters (for example, the destination pharmacy), not only the action type
  - claims that cannot be narrowed (operator, subject, purpose, consent, patient key) must be equal along a
    delegation chain; self-delegation is rejected; actions, fields, classes, tier and expiry may only narrow
  - action names, field names and the per-counterparty subject pseudonym are selectively disclosed (salted
    hashes), so a request reveals only the names and values it uses
  - revocation is published both by the operator (mandates, agent keys) and by the identity provider
    (consent, controlled by the patient); status snapshots must be fresh
  - nonces and request timestamps expire; unknown actions and mismatched disclosure lists are rejected
  - the counterparty assigns the tier: the highest of the action's base tier, the tier the patient bound to the action
    in the consent, and its own classification of the named drug or service (controlled, protected, time-sensitive;
    unknown drugs and unknown cancelled services count as tier 3); agent-supplied flags are ignored
  - parent attestations in a delegation chain must be unexpired and may not override the presenting agent
  - consent revocation at the identity provider requires the patient's signature
  - the counterparty checks that the certified subject is the person named in the request (the request opens the
    identity provider's salted commitment to name and date of birth); drug names must match exactly one registry entry
    with no unexplained tokens, and services take the most protective of all matched entries
  - the receipt log is an RFC 9162-style Merkle tree (leaf/node domain separation) over receipt hashes,
    with signed tree heads, inclusion proofs and consistency proofs; receipts themselves go only to the
    operator and patient
  - telephone codes are issued only to the mandate's agent (signed registration over a fresh operator nonce), only for
    actions and counterparty classes in the mandate and consent, with tier 3 approvals checked under the
    identity-provider-certified key; codes are consumed only after the subject matches; lookups are rate-limited
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

NONCE_TTL = 300
TIER3_TRANSACTION_TTL = 24 * 3600   # a tier 3 transaction challenge stays open long enough for the patient to approve
REQUEST_SKEW = 300
STATUS_MAX_AGE = 300

# ---------------------------------------------------------------- encoding helpers


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def pub_bytes(pk: Ed25519PublicKey) -> str:
    return b64u(pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def pub_from(s: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(b64u_dec(s))


def sign_token(sk: Ed25519PrivateKey, typ: str, payload: dict) -> str:
    head = b64u(canon({"alg": "EdDSA", "typ": typ}))
    body = b64u(canon(payload))
    return f"{head}.{body}.{b64u(sk.sign(f'{head}.{body}'.encode()))}"


def verify_token(pk: Ed25519PublicKey, token: str, typ: str) -> dict:
    head, body, sig = token.split(".")
    if json.loads(b64u_dec(head)).get("typ") != typ:
        raise ValueError("wrong token type")
    pk.verify(b64u_dec(sig), f"{head}.{body}".encode())
    return json.loads(b64u_dec(body))


def peek(token: str) -> dict:
    return json.loads(b64u_dec(token.split(".")[1]))


def disclosure(name: str, value) -> str:
    """Salted-hash disclosure in the style of SD-JWT: [salt, name, value]."""
    return b64u(canon([b64u(secrets.token_bytes(16)), name, value]))


def digest(d: str) -> str:
    return sha256(d.encode())


def open_disclosure(d: str) -> tuple[str, object]:
    _, name, value = json.loads(b64u_dec(d))
    return name, value


# ---------------------------------------------------------------- health risk tiers

PROTECTED_FIELDS = {"sud_treatment", "hiv_status", "reproductive_health", "psychotherapy_notes", "genetic",
                    "protected_attribute", "gender_affirming_care", "minor_confidential_services", "mental_health"}
# Counterparty-owned reference data. In practice a pharmacy classifies a drug by its NDC and schedule, and a broker or
# clinic knows its own service types; the agent's own flags are never trusted for tier assignment.
DRUG_REGISTRY = {
    "metformin": {}, "lisinopril": {}, "atorvastatin": {}, "albuterol": {}, "amlodipine": {}, "levothyroxine": {},
    "gabapentin": {}, "omeprazole": {}, "sertraline": {"protected": True}, "furosemide": {},
    "oxycodone": {"controlled": True}, "hydrocodone": {"controlled": True}, "alprazolam": {"controlled": True},
    "buprenorphine": {"controlled": True, "protected": True}, "suboxone": {"controlled": True, "protected": True},
    "sublocade": {"controlled": True, "protected": True}, "methadone": {"controlled": True, "protected": True},
    "naltrexone": {"protected": True}, "vivitrol": {"protected": True},
    "biktarvy": {"protected": True}, "descovy": {"protected": True}, "truvada": {"protected": True},
    "cabenuva": {"protected": True}, "mifepristone": {"protected": True},
    "lithium": {"protected": True}, "clozapine": {"protected": True},
}
SERVICE_REGISTRY = {
    "primary care": {}, "routine follow-up": {}, "dialysis": {"time_sensitive": True},
    "chemotherapy": {"time_sensitive": True}, "prenatal": {"time_sensitive": True, "protected": True},
    "behavioral health": {"time_sensitive": True, "protected": True}, "opioid treatment program": {"time_sensitive": True, "protected": True},
    "abortion": {"protected": True}, "gender-affirming care": {"protected": True},
}

ACTION_TIER = {
    "info_hours": 0,
    "pa_status_inquiry": 1,
    "ride_status_inquiry": 1,
    "refill_status_inquiry": 1,
    "refill_request": 2,
    "nemt_ride_booking": 2,
    "appointment_booking": 2,
    "appointment_reschedule": 2,
    "appointment_cancel": 2,
    "nemt_ride_cancel": 2,
    "pharmacy_change": 3,
    "medication_cancel": 3,
    "records_release_protected": 3,
}

REQUIRED_PROOFS = {
    0: {"P1"},
    1: {"P1", "P2", "P3", "P4", "P6"},
    2: {"P1", "P2", "P3", "P4", "P6"},
    3: {"P1", "P2", "P3", "P4", "P5", "P6"},
}


def _tokens(value) -> set:
    """Lower-case word tokens; every non-alphanumeric character except a decimal point separates tokens."""
    return set(t for t in re.split(r"[^a-z0-9.]+", str(value).lower()) if t and t != ".")


def _lookup(registry: dict, value) -> dict | None:
    """Service classification: the most protective attributes over ALL registry entries named in the value, so a benign
    entry cannot mask a protected or time-sensitive one. None if the value is absent; {"unknown": True} if no entry."""
    if not value:
        return None
    toks = _tokens(value)
    matches = [attrs for name, attrs in registry.items() if _tokens(name) <= toks]
    if not matches:
        return {"unknown": True}
    merged = {}
    for a in matches:
        for k, v in a.items():
            merged[k] = merged.get(k, False) or v
    return merged


# Parameter schema per action. Unknown keys are rejected, so a drug cannot be hidden under another key.
ACTION_PARAMS = {
    "info_hours": set(), "pa_status_inquiry": {"drug"}, "ride_status_inquiry": {"ride_id"},
    "refill_status_inquiry": {"drug"}, "refill_request": {"drug"}, "nemt_ride_booking": {"destination", "time", "return_ride"},
    "appointment_booking": {"service", "time"}, "appointment_reschedule": {"service", "time", "appointment_id"},
    "appointment_cancel": {"service", "appointment_id"}, "nemt_ride_cancel": {"service", "ride_id"},
    "pharmacy_change": {"drug", "to_pharmacy", "from_pharmacy"}, "medication_cancel": {"drug"},
    "records_release_protected": {"recipient"},
}
DRUG_ACTIONS = {"pa_status_inquiry", "refill_status_inquiry", "refill_request", "pharmacy_change", "medication_cancel"}


DOSE_TOKENS = {"mg", "mcg", "g", "ml", "unit", "units", "tablet", "tablets", "tab", "capsule", "capsules", "film", "films",
               "injection", "inhaler", "er", "xr", "sr", "dr", "hcl", "oral", "solution", "patch"}


def drug_key(value) -> str | None:
    """Registry name of a drug only if the value names exactly one registry entry and every other token is a dose or
    form token; otherwise None (unknown, which counts as tier 3)."""
    if not value:
        return None
    toks = _tokens(value)
    matches = [name for name in DRUG_REGISTRY if set(name.split()) <= toks]
    if len(matches) != 1:
        return None
    rest = toks - set(matches[0].split())
    if any(not (t in DOSE_TOKENS or t.replace(".", "").isdigit() or t.rstrip("mgcl").replace(".", "").isdigit()) for t in rest):
        return None
    return matches[0]


OBJECT_ACTIONS = {"appointment_cancel": "appointment_id", "appointment_reschedule": "appointment_id",
                  "nemt_ride_cancel": "ride_id"}


def protected_content(values, holds=lambda drug: False) -> bool:
    """True if any disclosed value names a controlled drug, a protected drug the counterparty does not already hold, or
    a protected service. Field values are classified by content, not only by field name."""
    for v in values:
        toks = _tokens(v)
        for name, attrs in DRUG_REGISTRY.items():
            if _tokens(name) <= toks and (attrs.get("controlled") or (attrs.get("protected") and not holds(name))):
                return True
        for name, attrs in SERVICE_REGISTRY.items():
            if _tokens(name) <= toks and attrs.get("protected"):
                return True
    return False


def tier_of(action: str, fields: list[str], params: dict | None = None, consent_tier: int = 0,
            counterparty_holds_rx: bool = False, object_service: str | None = None,
            protected_values: bool = False) -> int:
    """Tier assigned by the counterparty: the highest of the action's base tier, the tier the patient bound to this
    action in the consent, and the counterparty's own classification of the drug or service named in the request.
    Agent-supplied flags are ignored. A drug action without a recognised drug, an unknown drug, or the cancellation of an
    unknown or time-sensitive service is tier 3. A protected (non-controlled) drug raises the tier only when the
    counterparty does not already hold the prescription, because the request then discloses nothing new.
    Raises KeyError for an unknown action and ValueError for an unknown parameter (the verifier rejects both)."""
    params = params or {}
    t = max(ACTION_TIER[action], consent_tier)
    unknown = set(params) - ACTION_PARAMS[action]
    if unknown:
        raise ValueError(f"unknown parameter {sorted(unknown)}")
    if any(f in PROTECTED_FIELDS for f in fields) or protected_values:
        t = 3
    if action in DRUG_ACTIONS:
        dk = drug_key(params.get("drug"))
        if dk is None:
            t = 3
        else:
            attrs = DRUG_REGISTRY[dk]
            if attrs.get("controlled") or (attrs.get("protected") and not counterparty_holds_rx):
                t = 3
    if action in OBJECT_ACTIONS:
        # An action on an existing appointment or ride is classified from the counterparty's own record of it
        # (object_service); if the counterparty cannot resolve the identifier, the action counts as tier 3.
        if object_service is None:
            return 3
        svc = _lookup(SERVICE_REGISTRY, object_service)
    else:
        svc = _lookup(SERVICE_REGISTRY, params.get("service") or params.get("destination"))
    if svc and svc.get("protected"):
        t = 3
    if action.endswith("_cancel") and (svc is None or svc.get("unknown") or svc.get("time_sensitive")):
        t = 3
    return t


# ---------------------------------------------------------------- trust framework

OPERATOR_ROLES = {"covered_entity", "business_associate", "patient_designee"}


@dataclass
class OperatorEntry:
    operator_id: str
    legal_name: str
    role: str
    public_key: str
    revoked: bool = False


@dataclass
class Directory:
    entries: dict = field(default_factory=dict)

    def register(self, e: OperatorEntry):
        if e.role not in OPERATOR_ROLES:
            raise ValueError("unknown operator role")
        self.entries[e.operator_id] = e

    def get(self, operator_id: str) -> OperatorEntry | None:
        e = self.entries.get(operator_id)
        return None if e is None or e.revoked else e


class IdentityProvider:
    """IAL2 credential service provider. Certifies a patient key for a subject commitment, and publishes
    the patient's own consent revocations, independently of any operator."""

    def __init__(self):
        self.sk = Ed25519PrivateKey.generate()
        self.pk = self.sk.public_key()
        self.revoked_consents: set = set()

    def certify(self, patient: "Patient") -> str:
        return sign_token(self.sk, "idp-cert+jwt", {"patient_pub": pub_bytes(patient.pk),
                                                    "subject_commitment": patient.subject_commitment, "ial": 2})

    def revoke_consent(self, revocation_token: str, consent_token: str):
        """Accepts only a revocation that the patient signed with the key named in the consent."""
        c = peek(consent_token)
        r = verify_token(pub_from(c["patient_pub"]), revocation_token, "consent-revocation+jwt")
        if r["consent_hash"] != sha256(consent_token.encode()):
            raise ValueError("revocation does not name this consent")
        self.revoked_consents.add(r["consent_hash"])

    def snapshot(self) -> str:
        return sign_token(self.sk, "consent-status+jwt", {"revoked": sorted(self.revoked_consents), "iat": time.time()})


def identity_commitment(salt: str, name: str, dob: str) -> str:
    return sha256(f"{salt}|{str(name).strip().lower()}|{str(dob).strip()}".encode())


class Patient:
    def __init__(self, patient_id: str, name: str, dob: str):
        """The identity provider certifies the key for a salted commitment to the name and date of birth that it proofed.
        A request opens the commitment so the counterparty can check it against the identity it is acting on."""
        self.patient_id = patient_id
        self.sk = Ed25519PrivateKey.generate()
        self.pk = self.sk.public_key()
        self._commit_salt = secrets.token_hex(16)
        self.subject_commitment = identity_commitment(self._commit_salt, name, dob)

    def revoke(self, consent_token: str) -> str:
        return sign_token(self.sk, "consent-revocation+jwt", {"consent_hash": sha256(consent_token.encode()), "iat": time.time()})

    def consent(self, operator_id: str, agent_id: str, purpose: str, actions, fields: list[str],
                counterparty_classes: list[str], ttl: float = 30 * 86400) -> tuple[str, dict]:
        """Patient-signed consent with fields for the elements of a 164.508 authorization. `actions` maps each
        action to the minimum tier the patient sets for it (a list means base tiers). Action entries (with tier)
        and field names are selectively disclosable. Returns (token, disclosures by name)."""
        if not isinstance(actions, dict):
            actions = {a: ACTION_TIER.get(a, 3) for a in actions}
        disc = {("action", a): disclosure("action", [a, int(t)]) for a, t in actions.items()}
        disc.update({("field", f): disclosure("field", f) for f in fields})
        disc[("opening",)] = self._commit_salt
        now = time.time()
        tok = sign_token(self.sk, "consent+jwt", {
            "patient_pub": pub_bytes(self.pk), "subject_commitment": self.subject_commitment,
            "operator_id": operator_id, "agent_id": agent_id, "purpose_of_use": purpose,
            "_sd": sorted(digest(d) for k, d in disc.items() if k != ("opening",)), "counterparty_classes": sorted(counterparty_classes),
            "authorization": {"description": "actions and fields as disclosed", "recipients": sorted(counterparty_classes),
                              "disclosers": sorted(counterparty_classes) + [operator_id],
                              "right_to_revoke": True, "not_a_condition_of_treatment_or_payment": True,
                              "redisclosure_notice": True},
            "iat": now, "exp": now + ttl})
        return tok, disc

    def approve(self, root_mandate_id: str, action: str, params: dict, counterparty_id: str, fields: list[str],
                nonce: str) -> str:
        tx = {"mandate_id": root_mandate_id, "action": action, "params_hash": sha256(canon(params)),
              "counterparty_id": counterparty_id, "fields": sorted(fields), "nonce": nonce}
        return sign_token(self.sk, "approval+jwt", {"tx_hash": sha256(canon(tx)), **tx})


@dataclass
class StatusList:
    """Operator-published status for mandates and agent keys."""
    sk: Ed25519PrivateKey
    revoked_mandates: set = field(default_factory=set)
    revoked_agents: set = field(default_factory=set)

    def snapshot(self) -> str:
        return sign_token(self.sk, "status+jwt", {"mandates": sorted(self.revoked_mandates),
                                                  "agents": sorted(self.revoked_agents), "iat": time.time()})


class Operator:
    def __init__(self, operator_id: str, legal_name: str, role: str, directory: Directory):
        self.operator_id = operator_id
        self.sk = Ed25519PrivateKey.generate()
        self.pk = self.sk.public_key()
        self.status = StatusList(self.sk)
        self.pseudonym_key = secrets.token_bytes(32)
        directory.register(OperatorEntry(operator_id, legal_name, role, pub_bytes(self.pk)))

    def pseudonym(self, patient: "Patient", counterparty_class: str) -> str:
        """Pairwise pseudonym: a different keyed hash for each class of counterparty."""
        return hmac.new(self.pseudonym_key, f"{patient.patient_id}|{counterparty_class}".encode(),
                        hashlib.sha256).hexdigest()[:24]

    def attest(self, agent: "Agent", model: str, version: str, policy_text: str, tier_ceiling: int,
               ttl: float = 3600) -> str:
        now = time.time()
        return sign_token(self.sk, "attest+jwt", {
            "operator_id": self.operator_id, "agent_id": agent.agent_id, "agent_pub": pub_bytes(agent.pk),
            "model": model, "version": version, "policy_hash": sha256(policy_text.encode()),
            "tier_ceiling": tier_ceiling, "iat": now, "exp": now + ttl})

    def issue_mandate(self, patient: "Patient", idp_cert: str, idp_pub: Ed25519PublicKey, consent_token: str,
                      consent_disc: dict, agent: "Agent", record: dict, actions: list[str], fields: list[str],
                      counterparty_classes: list[str], tier_ceiling: int, ttl: float = 7 * 86400) -> tuple[str, dict]:
        cert = verify_token(idp_pub, idp_cert, "idp-cert+jwt")
        c = verify_token(pub_from(cert["patient_pub"]), consent_token, "consent+jwt")
        if (c["operator_id"] != self.operator_id or c["agent_id"] != agent.agent_id
                or c["subject_commitment"] != cert["subject_commitment"]
                or record.get("subject_commitment") != c["subject_commitment"]):
            raise ValueError("consent does not name this operator, agent and subject")
        if not (all(("action", a) in consent_disc for a in actions) and all(("field", f) in consent_disc for f in fields)
                and set(counterparty_classes) <= set(c["counterparty_classes"])):
            raise ValueError("mandate exceeds consent")
        ctier = {open_disclosure(v)[1][0]: open_disclosure(v)[1][1] for k, v in consent_disc.items() if k[0] == "action"}
        disc = {("action", a): disclosure("action", [a, ctier[a]]) for a in actions}
        disc.update({("field", f): disclosure(f, record[f]) for f in fields})
        disc.update({("subject", cc): disclosure(f"subject:{cc}", self.pseudonym(patient, cc)) for cc in counterparty_classes})
        now = time.time()
        tok = sign_token(self.sk, "mandate+sd-jwt", {
            "mandate_id": "m-" + secrets.token_hex(8), "operator_id": self.operator_id, "agent_id": agent.agent_id,
            "purpose_of_use": c["purpose_of_use"], "_sd": sorted(digest(d) for d in disc.values()),
            "counterparty_classes": sorted(counterparty_classes), "tier_ceiling": tier_ceiling,
            "consent_hash": sha256(consent_token.encode()), "patient_pub": cert["patient_pub"],
            "parent": None, "iat": now, "exp": min(now + ttl, c["exp"])})
        return tok, {**disc, **{("consent", k): v for k, v in consent_disc.items()}}


def operator_gate(action: str, fields: list[str], params: dict, field_values: list, consent_tier: int) -> int:
    """Operator-side classification before anything is sent. The operator cannot see the counterparty's records, so it
    assumes the counterparty does not hold the prescription and cannot resolve object identifiers; the result is never
    lower than the counterparty's tier. A tier 3 result means: obtain the patient's approval before sending."""
    return tier_of(action, fields, params, consent_tier=consent_tier, counterparty_holds_rx=False, object_service=None,
                   protected_values=protected_content(field_values))


class Agent:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.sk = Ed25519PrivateKey.generate()
        self.pk = self.sk.public_key()

    def sign_code_registration(self, reg_nonce: str, mandate: str, action: str, params: dict, counterparty_id: str,
                               subject_check: str) -> str:
        """subject_check: the patient's full proofed name and date of birth, as the agent will state them on the call."""
        body = {"reg_nonce": reg_nonce, "mandate_id": peek(mandate)["mandate_id"], "action": action,
                "params_hash": sha256(canon(params)), "counterparty_id": counterparty_id,
                "subject_hash": sha256(subject_check.strip().lower().encode())}
        return b64u(self.sk.sign(canon(body)))

    def attenuate(self, parent_mandate: str, parent_disc: dict, child: "Agent", actions: list[str], fields: list[str],
                  counterparty_classes: list[str], tier_ceiling: int, ttl: float) -> tuple[str, dict]:
        if child.agent_id == self.agent_id:
            raise ValueError("self-delegation")
        p = peek(parent_mandate)
        keep = {k: v for k, v in parent_disc.items()
                if (k[0] == "action" and k[1] in actions) or (k[0] == "field" and k[1] in fields)
                or (k[0] == "subject" and k[1] in counterparty_classes)
                or (k[0] == "consent")}
        now = time.time()
        tok = sign_token(self.sk, "mandate+sd-jwt", {
            "mandate_id": "m-" + secrets.token_hex(8), "operator_id": p["operator_id"], "agent_id": child.agent_id,
            "purpose_of_use": p["purpose_of_use"],
            "_sd": sorted(digest(v) for k, v in keep.items() if k[0] != "consent"),
            "counterparty_classes": sorted(counterparty_classes), "tier_ceiling": tier_ceiling,
            "consent_hash": p["consent_hash"], "patient_pub": p["patient_pub"],
            "parent": {"token": parent_mandate, "hash": sha256(parent_mandate.encode())},
            "iat": now, "exp": min(p["exp"], now + ttl)})
        return tok, keep

    def request(self, attestation: str, mandate: str, disc: dict, consent: str, idp_cert: str, action: str,
                params: dict, counterparty_id: str, counterparty_class: str, fields: list[str], nonce: str,
                approval: str | None = None, chain_attestations=None) -> dict:
        f = sorted(fields)
        req = {"attestation": attestation, "mandate": mandate, "consent": consent, "idp_cert": idp_cert,
               "action": action, "params": params, "counterparty_id": counterparty_id, "fields": f,
               "disclosures": [disc[("field", x)] for x in f if ("field", x) in disc],
               "action_disclosure": disc.get(("action", action)),
               "subject_disclosure": disc.get(("subject", counterparty_class)),
               "subject_opening": disc.get(("consent", ("opening",))),
               "consent_disclosures": [disc[("consent", ("action", action))] if ("consent", ("action", action)) in disc else None]
               + [disc.get(("consent", ("field", x))) for x in f],
               "nonce": nonce, "approval": approval, "chain_attestations": chain_attestations or [], "ts": time.time()}
        req["sig"] = b64u(self.sk.sign(canon({k: v for k, v in req.items() if k != "sig"})))
        return req


# ---------------------------------------------------------------- transparency log (RFC 9162 style)

def _leaf(h: str) -> bytes:
    return hashlib.sha256(b"\x00" + bytes.fromhex(h)).digest()


def _node(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + a + b).digest()


def _mth(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = 1 << ((n - 1).bit_length() - 1)
    return _node(_mth(leaves[:k]), _mth(leaves[k:]))


def _path(m: int, leaves: list[bytes]) -> list[bytes]:
    n = len(leaves)
    if n <= 1:
        return []
    k = 1 << ((n - 1).bit_length() - 1)
    return _path(m, leaves[:k]) + [_mth(leaves[k:])] if m < k else _path(m - k, leaves[k:]) + [_mth(leaves[:k])]


def _subproof(m: int, leaves: list[bytes], b: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if b else [_mth(leaves)]
    k = 1 << ((n - 1).bit_length() - 1)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [_mth(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [_mth(leaves[:k])]


class TransparencyLog:
    """Merkle log of receipt hashes (not receipts) with signed tree heads, inclusion and consistency proofs."""

    def __init__(self):
        self.sk = Ed25519PrivateKey.generate()
        self.pk = self.sk.public_key()
        self.leaves: list[bytes] = []

    def append(self, receipt_hash: str) -> int:
        self.leaves.append(_leaf(receipt_hash))
        return len(self.leaves) - 1

    def sth(self) -> str:
        return sign_token(self.sk, "sth+jwt", {"size": len(self.leaves), "root": _mth(self.leaves).hex(),
                                               "ts": time.time()})

    def inclusion_proof(self, idx: int, size: int | None = None) -> list[str]:
        return [h.hex() for h in _path(idx, self.leaves[:size or len(self.leaves)])]

    def consistency_proof(self, old_size: int, new_size: int | None = None) -> list[str]:
        return [h.hex() for h in _subproof(old_size, self.leaves[:new_size or len(self.leaves)], True)]

    @staticmethod
    def verify_inclusion(receipt_hash: str, idx: int, size: int, proof: list[str], root: str) -> bool:
        # RFC 9162 section 2.1.3.2
        if idx >= size:
            return False
        fn, sn, r = idx, size - 1, _leaf(receipt_hash)
        for p in map(bytes.fromhex, proof):
            if sn == 0:
                return False
            if fn & 1 or fn == sn:
                r = _node(p, r)
                if not fn & 1:
                    while fn and not fn & 1:
                        fn >>= 1
                        sn >>= 1
            else:
                r = _node(r, p)
            fn >>= 1
            sn >>= 1
        return sn == 0 and r.hex() == root

    @staticmethod
    def verify_consistency(old_size: int, new_size: int, proof: list[str], old_root: str, new_root: str) -> bool:
        # RFC 9162 section 2.1.4.2
        if old_size == new_size:
            return not proof and old_root == new_root
        if old_size == 0 or old_size > new_size:
            return False
        p = [bytes.fromhex(x) for x in proof]
        if old_size & (old_size - 1) == 0:
            p = [bytes.fromhex(old_root)] + p
        if not p:
            return False
        fn, sn = old_size - 1, new_size - 1
        while fn & 1:
            fn >>= 1
            sn >>= 1
        fr = sr = p[0]
        for c in p[1:]:
            if sn == 0:
                return False
            if fn & 1 or fn == sn:
                fr, sr = _node(c, fr), _node(c, sr)
                if not fn & 1:
                    while fn and not fn & 1:
                        fn >>= 1
                        sn >>= 1
            else:
                sr = _node(sr, c)
            fn >>= 1
            sn >>= 1
        return sn == 0 and fr.hex() == old_root and sr.hex() == new_root


# ---------------------------------------------------------------- counterparty verifier

LEVELS = {
    "L0_name_dob": set(),
    "L1_operator": {"P1"},
    "L2_operator_mandate": {"P1", "P2", "P3"},
    "L3_plus_fresh_status": {"P1", "P2", "P3", "P4", "P6"},
    "L4_full_hah": {"P1", "P2", "P3", "P4", "P5", "P6"},
}


class Counterparty:
    def __init__(self, counterparty_id: str, counterparty_class: str, directory: Directory, operator_status: dict,
                 idp: IdentityProvider, log: TransparencyLog, level: str = "L4_full_hah", held_prescriptions: set | None = None,
                 identity_counts: dict | None = None, object_records: dict | None = None):
        self.counterparty_id = counterparty_id
        self.held_prescriptions = held_prescriptions or set()   # (name lower-case, dob, drug registry name), from own records
        # Number of the counterparty's own records per (name lower-case, dob). More than one match means the certified
        # identity does not single out a record; the request is refused for manual verification and operator-supplied
        # identifiers are never used to choose between records.
        self.identity_counts = identity_counts or {}
        # The counterparty's own records of existing appointments and rides: identifier -> (name lower-case, dob, service).
        self.object_records = object_records or {}
        self.cls = counterparty_class
        self.directory = directory
        self.operator_status = operator_status
        self.idp = idp
        self.log = log
        self.sk = Ed25519PrivateKey.generate()
        self.pk = self.sk.public_key()
        self.level = level
        self.issued_nonces: dict = {}
        self.used_nonces: set = set()

    def challenge(self, ttl: float = NONCE_TTL) -> str:
        """Nonce for one request. For a tier 3 request, the agent asks for a transaction challenge with a longer ttl
        (TIER3_TRANSACTION_TTL); the patient's approval binds it, so the patient has time to approve."""
        n = secrets.token_hex(16)
        self.issued_nonces[n] = (time.time(), ttl)
        return n

    def verify(self, req: dict, name_dob_ok: bool = True):
        """Wraps the checks. A rejected request whose agent signature verified gets a counterparty-signed refusal
        receipt in the log (no field values), so the patient's record shows what was attempted and refused."""
        ok, why, receipt = self._verify(req, name_dob_ok)
        if not ok and LEVELS[self.level] and not why.startswith(("P1_", "name_dob")):
            body = {"counterparty_id": self.counterparty_id, "refused": why, "action": req.get("action"),
                    "fields": req.get("fields"), "request_hash": sha256(canon({k: v for k, v in req.items() if k != "sig"})),
                    "ts": time.time()}
            r = sign_token(self.sk, "refusal-receipt+jwt", body)
            idx = self.log.append(sha256(r.encode()))
            receipt = {"refusal_receipt": r, "index": idx, "sth": self.log.sth()}
        return ok, why, receipt

    def _verify(self, req: dict, name_dob_ok: bool = True):
        on = LEVELS[self.level]
        if not on:
            return (name_dob_ok, "accepted_name_dob" if name_dob_ok else "name_dob_mismatch", None)
        try:
            att = peek(req["attestation"])
            op = self.directory.get(att["operator_id"])
            if op is None:
                return False, "P1_unknown_or_revoked_operator", None
            att = verify_token(pub_from(op.public_key), req["attestation"], "attest+jwt")
            if time.time() > att["exp"]:
                return False, "P2_attestation_expired", None
            pub_from(att["agent_pub"]).verify(b64u_dec(req["sig"]), canon({k: v for k, v in req.items() if k != "sig"}))
        except (InvalidSignature, ValueError, KeyError, TypeError):
            return False, "P1_P2_bad_signature", None
        if req["counterparty_id"] != self.counterparty_id:
            return False, "P1_wrong_audience", None
        if abs(time.time() - req["ts"]) > REQUEST_SKEW:
            return False, "P4_stale_request", None
        if on == {"P1"}:
            return True, "accepted_operator_only", None
        # Tier 0 (no protected health information): operator accountability (P1) is the only proof required.
        if ACTION_TIER.get(req["action"]) == 0 and not req["fields"] and not req.get("params"):
            return True, "accepted_tier0", None

        ok, why, m, root = self._verify_chain(req, op, att)
        if not ok:
            return False, why, None
        # Consent: patient signature under the identity-provider-certified key; names operator, root agent, subject.
        try:
            cert = verify_token(self.idp.pk, req["idp_cert"], "idp-cert+jwt")
            c = verify_token(pub_from(cert["patient_pub"]), req["consent"], "consent+jwt")
        except (InvalidSignature, ValueError, KeyError, TypeError, AttributeError):
            return False, "P3_consent_missing_or_invalid", None
        if (sha256(req["consent"].encode()) != root["consent_hash"] or root["patient_pub"] != cert["patient_pub"]
                or c["subject_commitment"] != cert["subject_commitment"] or c["operator_id"] != root["operator_id"]
                or c["agent_id"] != root["agent_id"] or c["purpose_of_use"] != root["purpose_of_use"]):
            return False, "P3_consent_not_bound_to_mandate", None
        if time.time() > c["exp"]:
            return False, "P3_consent_expired", None
        # Action, fields and subject: each must be selectively disclosed and bound in both mandate and consent.
        if req["action"] not in ACTION_TIER:
            return False, "P3_unknown_action", None
        ad = req.get("action_disclosure")
        if not ad or digest(ad) not in m["_sd"] or open_disclosure(ad)[0] != "action" or open_disclosure(ad)[1][0] != req["action"]:
            return False, "P3_action_not_in_mandate", None
        if len(req["disclosures"]) != len(req["fields"]) or len(set(req["fields"])) != len(req["fields"]):
            return False, "P3_field_not_in_mandate", None
        for d, f in zip(req["disclosures"], req["fields"]):
            if digest(d) not in m["_sd"] or open_disclosure(d)[0] != f:
                return False, "P3_field_not_in_mandate", None
        # Identity binding: the certified subject must be the person named in this request. The request opens the
        # identity-provider commitment, and the counterparty checks it against the disclosed name and date of birth.
        vals = {open_disclosure(d)[0]: open_disclosure(d)[1] for d in req["disclosures"]}
        if ("name" not in vals or "dob" not in vals or not req.get("subject_opening")
                or identity_commitment(req["subject_opening"], vals["name"], vals["dob"]) != cert["subject_commitment"]):
            return False, "P3_subject_not_bound_to_certified_identity", None
        cds = req.get("consent_disclosures") or []
        if (len(cds) != 1 + len(req["fields"]) or any(x is None or digest(x) not in c["_sd"] for x in cds)
                or open_disclosure(cds[0])[0] != "action" or open_disclosure(cds[0])[1][0] != req["action"]
                or [open_disclosure(x) for x in cds[1:]] != [("field", f) for f in req["fields"]]):
            return False, "P3_mandate_exceeds_consent", None
        consent_tier = int(open_disclosure(cds[0])[1][1])
        sd = req.get("subject_disclosure")
        if not sd or digest(sd) not in m["_sd"] or open_disclosure(sd)[0] != f"subject:{self.cls}":
            return False, "P3_subject_not_disclosed", None
        if self.identity_counts.get((str(vals["name"]).strip().lower(), str(vals["dob"]).strip()), 1) > 1:
            return False, "P3_identity_ambiguous_manual_verification", None
        # Records are matched on the certified identity (opened name and date of birth), never on the operator-chosen
        # pseudonym, which is not bound to the certified person.
        holds = (str(vals["name"]).strip().lower(), str(vals["dob"]).strip(),
                 drug_key((req.get("params") or {}).get("drug"))) in self.held_prescriptions
        object_service = None
        if req["action"] in OBJECT_ACTIONS:
            rec = self.object_records.get((req.get("params") or {}).get(OBJECT_ACTIONS[req["action"]]))
            if rec is not None:
                if rec[:2] != (str(vals["name"]).strip().lower(), str(vals["dob"]).strip()):
                    return False, "P3_object_belongs_to_another_patient", None
                stated = (req.get("params") or {}).get("service")
                if stated is not None and _lookup(SERVICE_REGISTRY, stated) != _lookup(SERVICE_REGISTRY, rec[2]):
                    return False, "P3_stated_service_contradicts_record", None
                object_service = rec[2]
        ident = (str(vals["name"]).strip().lower(), str(vals["dob"]).strip())
        pv = protected_content([v for k, v in vals.items() if k not in ("name", "dob")],
                               holds=lambda drug: ident + (drug,) in self.held_prescriptions)
        try:
            tier = tier_of(req["action"], req["fields"], req.get("params"), consent_tier=consent_tier,
                           counterparty_holds_rx=holds, object_service=object_service, protected_values=pv)
        except ValueError:
            return False, "P3_unknown_parameter", None
        if self.cls not in m["counterparty_classes"] or self.cls not in c["counterparty_classes"]:
            return False, "P3_counterparty_class_not_in_mandate", None
        if tier > min(m["tier_ceiling"], att["tier_ceiling"]):
            return False, "P3_tier_above_ceiling", None
        if time.time() > m["exp"]:
            return False, "P3_mandate_expired", None

        if "P4" in on:
            issued = self.issued_nonces.get(req["nonce"])
            if issued is None or req["nonce"] in self.used_nonces or time.time() - issued[0] > issued[1]:
                return False, "P4_nonce_replay_unknown_or_expired", None
            st = verify_token(pub_from(op.public_key), self.operator_status[op.operator_id].snapshot(), "status+jwt")
            cs = verify_token(self.idp.pk, self.idp.snapshot(), "consent-status+jwt")
            if time.time() - st["iat"] > STATUS_MAX_AGE or time.time() - cs["iat"] > STATUS_MAX_AGE:
                return False, "P4_status_stale", None
            if any(x in st["mandates"] for x in self._chain_ids(req["mandate"])):
                return False, "P4_mandate_revoked", None
            if any(a in st["agents"] for a in self._chain_agents(req["mandate"])):
                return False, "P4_agent_revoked", None
            if root["consent_hash"] in cs["revoked"]:
                return False, "P4_consent_revoked_by_patient", None

        if "P5" in on and tier == 3:
            if not req.get("approval"):
                return False, "P5_stepup_required", None
            try:
                a = verify_token(pub_from(cert["patient_pub"]), req["approval"], "approval+jwt")
            except (InvalidSignature, ValueError):
                return False, "P5_bad_approval_signature", None
            tx = {"mandate_id": root["mandate_id"], "action": req["action"], "params_hash": sha256(canon(req.get("params") or {})),
                  "counterparty_id": self.counterparty_id, "fields": sorted(req["fields"]), "nonce": req["nonce"]}
            if a["tx_hash"] != sha256(canon(tx)) or {k: a.get(k) for k in tx} != tx:
                return False, "P5_approval_not_bound_to_tx", None

        if "P4" in on:
            self.used_nonces.add(req["nonce"])
        receipt = self._receipt(req, m, open_disclosure(sd)[1], cert["subject_commitment"]) if "P6" in on else None
        return True, "accepted_full" if "P5" in on else "accepted", receipt

    def _chain(self, mandate: str) -> list[dict]:
        out, tok = [], mandate
        while tok:
            p = peek(tok)
            out.append(p)
            tok = p["parent"]["token"] if p["parent"] else None
        return out

    def _chain_ids(self, mandate: str) -> list[str]:
        return [p["mandate_id"] for p in self._chain(mandate)]

    def _chain_agents(self, mandate: str) -> list[str]:
        return [p["agent_id"] for p in self._chain(mandate)]

    def _verify_chain(self, req, op, att):
        attest_by_agent = {att["agent_id"]: att}
        for t in req.get("chain_attestations", []):
            try:
                a = verify_token(pub_from(op.public_key), t, "attest+jwt")
            except (InvalidSignature, ValueError):
                return False, "P2_bad_chain_attestation", None, None
            if time.time() > a["exp"]:
                return False, "P2_chain_attestation_expired", None, None
            if a["agent_id"] in attest_by_agent:
                return False, "P2_chain_attestation_overrides_agent", None, None
            attest_by_agent[a["agent_id"]] = a
        tok, child, presented = req["mandate"], None, None
        while True:
            p = peek(tok)
            if p["parent"] is None:
                signer = pub_from(op.public_key)
            else:
                parent_agent = peek(p["parent"]["token"])["agent_id"]
                if parent_agent == p["agent_id"]:
                    return False, "P3_self_delegation", None, None
                if parent_agent not in attest_by_agent:
                    return False, "P2_missing_chain_attestation", None, None
                if sha256(p["parent"]["token"].encode()) != p["parent"]["hash"]:
                    return False, "P3_parent_hash_mismatch", None, None
                signer = pub_from(attest_by_agent[parent_agent]["agent_pub"])
            try:
                m = verify_token(signer, tok, "mandate+sd-jwt")
            except (InvalidSignature, ValueError):
                return False, "P3_bad_mandate_signature", None, None
            if presented is None:
                presented = m
                if m["agent_id"] != att["agent_id"]:
                    return False, "P3_mandate_not_for_this_agent", None, None
            if m["operator_id"] != op.operator_id:
                return False, "P3_operator_mismatch", None, None
            if child is not None:
                fixed = ("operator_id", "purpose_of_use", "consent_hash", "patient_pub")
                if any(child[k] != m[k] for k in fixed):
                    return False, "P3_chain_fixed_claim_changed", None, None
                if not (set(child["_sd"]) <= set(m["_sd"])
                        and set(child["counterparty_classes"]) <= set(m["counterparty_classes"])
                        and child["tier_ceiling"] <= m["tier_ceiling"] and child["exp"] <= m["exp"]):
                    return False, "P3_attenuation_violation", None, None
            child = m
            if m["parent"] is None:
                return True, "", presented, m
            tok = m["parent"]["token"]

    def _receipt(self, req, m, pseudonym, subject_commitment) -> dict:
        body = {"counterparty_id": self.counterparty_id, "mandate_id": m["mandate_id"],
                "subject_commitment": subject_commitment, "pseudonym": pseudonym,
                "action": req["action"], "params_hash": sha256(canon(req.get("params") or {})), "fields": req["fields"],
                "disclosed_hashes": [digest(d) for d in req["disclosures"]],
                "request_hash": sha256(canon({k: v for k, v in req.items() if k != "sig"})), "ts": time.time()}
        receipt = sign_token(self.sk, "receipt+jwt", body)
        rh = sha256(receipt.encode())
        idx = self.log.append(rh)
        sth = self.log.sth()
        size = peek(sth)["size"]
        return {"receipt": receipt, "receipt_hash": rh, "index": idx, "sth": sth,
                "proof": self.log.inclusion_proof(idx, size), "counterparty_pub": pub_bytes(self.pk)}


# ---------------------------------------------------------------- telephone fallback

class VerificationService:
    """Operator-run code lookup for calls. The operator issues a code only for an action in an unexpired, unrevoked
    mandate whose consent the patient has not revoked; tier 3 needs a patient approval over a fresh operator-issued
    nonce, usable once. Lookups must be signed by a counterparty key in the directory, re-check status, are
    rate-limited, and return a hash of the parameters rather than the parameters. Calls produce an operator log entry,
    not a counterparty-signed receipt."""
    ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
    MAX_LOOKUPS_PER_MINUTE = 20

    def __init__(self, operator: Operator, idp: IdentityProvider, counterparty_keys: dict, counterparty_classes: dict | None = None):
        self.operator = operator
        self.counterparty_classes = counterparty_classes or {}  # counterparty_id -> class, from the directory
        self.idp = idp
        self.counterparty_keys = counterparty_keys      # counterparty_id -> public key (trust-framework directory)
        self.codes: dict = {}
        self.lookups: dict = {}
        self.phone_nonces: dict = {}
        self.log: list = []

    def registration_challenge(self) -> str:
        """Fresh nonce that the agent signs into a code registration request."""
        n = "reg-" + secrets.token_hex(12)
        self.phone_nonces[n] = time.time()
        return n

    def phone_challenge(self) -> str:
        n = "phone-" + secrets.token_hex(12)
        self.phone_nonces[n] = time.time()
        return n

    def _status_ok(self, mandate_payload: dict, consent_hash: str) -> str | None:
        if time.time() > mandate_payload["exp"]:
            return "mandate expired"
        st = self.operator.status
        if mandate_payload["mandate_id"] in st.revoked_mandates or mandate_payload["agent_id"] in st.revoked_agents:
            return "mandate or agent revoked"
        if consent_hash in self.idp.revoked_consents:
            return "consent revoked by patient"
        return None

    def register(self, mandate: str, disc: dict, consent: str, idp_cert: str, attestation: str, action: str, params: dict,
                 counterparty_id: str, reg_nonce: str, reg_sig: str, approval: str | None = None,
                 phone_nonce: str | None = None, ttl: float = 900) -> str:
        """The agent that the mandate names must sign the registration over a fresh operator nonce, so a party that only
        holds copies of the mandate and consent cannot obtain a code."""
        p = verify_token(self.operator.pk, mandate, "mandate+sd-jwt")
        att = verify_token(self.operator.pk, attestation, "attest+jwt")
        if att["agent_id"] != p["agent_id"] or time.time() > att["exp"]:
            raise ValueError("attestation does not match the mandate's agent")
        t0 = self.phone_nonces.pop(reg_nonce, None) if str(reg_nonce).startswith("reg-") else None
        if t0 is None or time.time() - t0 > NONCE_TTL:
            raise ValueError("registration nonce unknown or expired")
        # The subject is the certified person: name and date of birth must be disclosed in the mandate and open the
        # identity provider's commitment; the operator derives the telephone subject check from them.
        nd, dd, opening = disc.get(("field", "name")), disc.get(("field", "dob")), disc.get(("consent", ("opening",)))
        if (not nd or not dd or not opening or digest(nd) not in p["_sd"] or digest(dd) not in p["_sd"]
                or open_disclosure(nd)[0] != "name" or open_disclosure(dd)[0] != "dob"):
            raise ValueError("mandate does not disclose the patient's name and date of birth")
        name, dob = open_disclosure(nd)[1], open_disclosure(dd)[1]
        subject_check = f"{str(name).strip()} {dob}"
        body = {"reg_nonce": reg_nonce, "mandate_id": p["mandate_id"], "action": action, "params_hash": sha256(canon(params)),
                "counterparty_id": counterparty_id, "subject_hash": sha256(subject_check.strip().lower().encode())}
        try:
            pub_from(att["agent_pub"]).verify(b64u_dec(reg_sig), canon(body))
        except InvalidSignature:
            raise ValueError("registration not signed by the mandate's agent")
        try:
            cert = verify_token(self.idp.pk, idp_cert, "idp-cert+jwt")
            c = verify_token(pub_from(cert["patient_pub"]), consent, "consent+jwt")
        except InvalidSignature:
            raise ValueError("consent or identity certificate invalid")
        if (sha256(consent.encode()) != p["consent_hash"] or p["patient_pub"] != cert["patient_pub"]
                or c["subject_commitment"] != cert["subject_commitment"] or c["operator_id"] != p["operator_id"]
                or c["agent_id"] != p["agent_id"] or c["purpose_of_use"] != p["purpose_of_use"]):
            raise ValueError("consent does not match mandate")
        if identity_commitment(opening, name, dob) != cert["subject_commitment"]:
            raise ValueError("mandate subject is not the certified person")
        if time.time() > c["exp"]:
            raise ValueError("consent expired")
        cls = self.counterparty_classes.get(counterparty_id)
        if cls is None or cls not in p["counterparty_classes"] or cls not in c["counterparty_classes"]:
            raise ValueError("counterparty class not permitted")
        why = self._status_ok(p, p["consent_hash"])
        if why:
            raise ValueError(why)
        if action not in ACTION_TIER:
            raise ValueError("unknown action")
        # Same disclosure checks as the structured verifier: each disclosure must name what it is filed under, and the
        # action, name and date of birth must also be bound in the patient-signed consent, which sets the tier.
        ad = disc.get(("action", action))
        if not ad or digest(ad) not in p["_sd"] or open_disclosure(ad)[0] != "action" or open_disclosure(ad)[1][0] != action:
            raise ValueError("action not in mandate")
        cad = disc.get(("consent", ("action", action)))
        if not cad or digest(cad) not in c["_sd"] or open_disclosure(cad)[0] != "action" or open_disclosure(cad)[1][0] != action:
            raise ValueError("action not in consent")
        for fld in ("name", "dob"):
            cfd = disc.get(("consent", ("field", fld)))
            if not cfd or digest(cfd) not in c["_sd"] or open_disclosure(cfd) != ("field", fld):
                raise ValueError("name and date of birth not permitted by the consent")
        tier = tier_of(action, [], params, consent_tier=int(open_disclosure(cad)[1][1]))
        if tier > min(p["tier_ceiling"], att["tier_ceiling"]):
            raise ValueError("tier above the mandate or attestation ceiling")
        approved = False
        if tier == 3:
            t0 = self.phone_nonces.pop(phone_nonce, None) if phone_nonce and str(phone_nonce).startswith("phone-") else None
            if not approval or t0 is None or time.time() - t0 > NONCE_TTL:
                raise ValueError("tier 3 by telephone needs a patient approval over a fresh operator nonce")
            try:
                a = verify_token(pub_from(cert["patient_pub"]), approval, "approval+jwt")
            except InvalidSignature:
                raise ValueError("approval not signed by the certified patient key")
            tx = {"mandate_id": p["mandate_id"], "action": action, "params_hash": sha256(canon(params)),
                  "counterparty_id": counterparty_id, "fields": [], "nonce": phone_nonce}
            if a["tx_hash"] != sha256(canon(tx)):
                raise ValueError("approval not bound to this telephone request")
            approved = True
        code = "".join(secrets.choice(self.ALPHABET) for _ in range(8))
        self.codes[code] = {"operator": self.operator.operator_id, "agent": p["agent_id"], "purpose_of_use": p["purpose_of_use"],
                            "action": action, "params_hash": sha256(canon(params)), "patient_approval_verified": approved,
                            "counterparty_id": counterparty_id, "mandate_exp": p["exp"], "code_exp": time.time() + ttl,
                            "subject_check": sha256(subject_check.strip().lower().encode()), "used": False,
                            "_mandate": p, "_consent_hash": p["consent_hash"]}
        self.log.append({"code_hash": sha256(code.encode()), "action": action, "counterparty_id": counterparty_id, "ts": time.time()})
        return code

    def lookup_challenge(self) -> str:
        n = "look-" + secrets.token_hex(12)
        self.phone_nonces[n] = time.time()
        return n

    def lookup(self, code: str, counterparty_id: str, stated_subject_check: str, stated_params: dict, nonce: str,
               signature: str) -> dict | None:
        """The counterparty signs a fresh service nonce, the code, its identifier, and hashes of the stated subject and
        parameters with its directory key, so a captured lookup cannot be replayed with other values."""
        pk = self.counterparty_keys.get(counterparty_id)
        t0 = self.phone_nonces.pop(nonce, None) if str(nonce).startswith("look-") else None
        body = {"nonce": nonce, "code": code, "counterparty_id": counterparty_id,
                "subject_hash": sha256(stated_subject_check.strip().lower().encode()), "params_hash": sha256(canon(stated_params))}
        try:
            if pk is None or t0 is None or time.time() - t0 > NONCE_TTL:
                raise ValueError
            pk.verify(b64u_dec(signature), canon(body))
        except (InvalidSignature, ValueError):
            return {"error": "counterparty_not_authenticated"}
        now = time.time()
        recent = [t for t in self.lookups.get(counterparty_id, []) if now - t < 60]
        if len(recent) >= self.MAX_LOOKUPS_PER_MINUTE:
            return {"error": "rate_limited"}
        self.lookups[counterparty_id] = recent + [now]
        r = self.codes.get(code)
        if r is None or r["used"] or now > r["code_exp"] or r["counterparty_id"] != counterparty_id:
            return None
        if self._status_ok(r["_mandate"], r["_consent_hash"]):
            return {"error": "revoked_or_expired"}
        if sha256(stated_subject_check.strip().lower().encode()) != r["subject_check"]:
            return {"subject_match": False}
        if sha256(canon(stated_params)) != r["params_hash"]:
            return {"subject_match": True, "params_match": False}
        r["used"] = True
        out = {k: v for k, v in r.items() if k not in ("used", "subject_check", "params_hash") and not k.startswith("_")}
        out["subject_match"] = True
        out["params_match"] = sha256(canon(stated_params)) == r["params_hash"]
        return out
