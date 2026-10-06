"""Reference implementation of the Health Agent Handshake (HAH) profile.

Primitives: Ed25519 signatures (cryptography), canonical JSON, SHA-256, HMAC-SHA-256.
The token formats mirror JWS / SD-JWT structure (header.payload.signature, salted-hash
disclosures) without claiming wire compatibility with any IETF draft.

Proofs (see SPEC.md section 2):
  P1 operator accountability   -> Directory + signed request (agent key certified by operator)
  P2 agent attestation         -> operator-signed attestation carrying agent public key
  P3 mandate                   -> operator-signed mandate with salted-hash field disclosures,
                                  bound to a patient-signed consent record
  P4 freshness and status      -> counterparty nonce, status list
  P5 transaction-bound approval-> patient signature over (action, counterparty, fields, nonce)
  P6 receipt                   -> counterparty-signed receipt appended to a hash-chained log
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

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
    sig = b64u(sk.sign(f"{head}.{body}".encode()))
    return f"{head}.{body}.{sig}"


def verify_token(pk: Ed25519PublicKey, token: str, typ: str) -> dict:
    head, body, sig = token.split(".")
    if json.loads(b64u_dec(head)).get("typ") != typ:
        raise ValueError("wrong token type")
    pk.verify(b64u_dec(sig), f"{head}.{body}".encode())
    return json.loads(b64u_dec(body))


def peek(token: str) -> dict:
    return json.loads(b64u_dec(token.split(".")[1]))


# ---------------------------------------------------------------- health risk tiers

PROTECTED_FIELDS = {"sud_treatment", "hiv_status", "reproductive_health", "psychotherapy_notes", "genetic"}

ACTION_TIER = {
    "info_hours": 0,
    "pa_status_inquiry": 1,
    "ride_status_inquiry": 1,
    "refill_status_inquiry": 1,
    "refill_request": 2,
    "nemt_ride_booking": 2,
    "appointment_booking": 2,
    "appointment_reschedule": 2,
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


def tier_of(action: str, fields: list[str]) -> int:
    t = ACTION_TIER[action]
    if any(f in PROTECTED_FIELDS for f in fields):
        t = 3
    return t


# ---------------------------------------------------------------- trust framework

@dataclass
class OperatorEntry:
    operator_id: str
    legal_name: str
    hipaa_role: str          # "covered_entity" | "business_associate"
    public_key: str
    revoked: bool = False


@dataclass
class Directory:
    """Trust-framework directory (UDAP-style). Maps operator ids to keys and HIPAA role."""
    entries: dict = field(default_factory=dict)

    def register(self, e: OperatorEntry):
        self.entries[e.operator_id] = e

    def get(self, operator_id: str) -> OperatorEntry | None:
        e = self.entries.get(operator_id)
        return None if e is None or e.revoked else e


@dataclass
class StatusList:
    """Operator-published mandate status (revocation). Signed snapshot on each fetch."""
    sk: Ed25519PrivateKey
    revoked: set = field(default_factory=set)

    def revoke(self, mandate_id: str):
        self.revoked.add(mandate_id)

    def snapshot(self) -> str:
        return sign_token(self.sk, "status+jwt", {"revoked": sorted(self.revoked), "iat": time.time()})


@dataclass
class IdentityProvider:
    """IAL2 credential service provider (e.g., the provider used for TEFCA IAS). Certifies a
    patient's device key independently of the agent operator, so consent binding does not rest
    on operator honesty."""
    sk: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)

    def certify(self, patient: "Patient") -> str:
        return sign_token(self.sk, "idp-cert+jwt", {"patient_pub": pub_bytes(patient.pk), "ial": 2})


# ---------------------------------------------------------------- patient, operator, agent

class Patient:
    def __init__(self, patient_id: str):
        self.patient_id = patient_id
        self.sk = Ed25519PrivateKey.generate()
        self.pk = self.sk.public_key()

    def consent(self, scope: dict) -> str:
        """Patient-signed consent record (P3 input). Captured by SMS or app after teach-back."""
        return sign_token(self.sk, "consent+jwt", {"patient_pub": pub_bytes(self.pk), **scope, "iat": time.time()})

    def approve(self, mandate_id: str, action: str, counterparty_id: str, fields: list[str], nonce: str) -> str:
        """P5: approval bound to one transaction."""
        tx = {"mandate_id": mandate_id, "action": action, "counterparty_id": counterparty_id,
              "fields": sorted(fields), "nonce": nonce}
        return sign_token(self.sk, "approval+jwt", {"tx_hash": sha256(canon(tx)), **tx})


class Operator:
    def __init__(self, operator_id: str, legal_name: str, hipaa_role: str, directory: Directory):
        self.operator_id = operator_id
        self.sk = Ed25519PrivateKey.generate()
        self.pk = self.sk.public_key()
        self.status = StatusList(self.sk)
        self.pseudonym_key = secrets.token_bytes(32)
        directory.register(OperatorEntry(operator_id, legal_name, hipaa_role, pub_bytes(self.pk)))

    def pseudonym(self, patient_id: str) -> str:
        return hmac.new(self.pseudonym_key, patient_id.encode(), hashlib.sha256).hexdigest()[:24]

    def attest(self, agent: "Agent", model: str, version: str, policy_text: str, tier_ceiling: int,
               ttl: float = 3600) -> str:
        now = time.time()
        return sign_token(self.sk, "attest+jwt", {
            "operator_id": self.operator_id, "agent_id": agent.agent_id, "agent_pub": pub_bytes(agent.pk),
            "model": model, "version": version, "policy_hash": sha256(policy_text.encode()),
            "tier_ceiling": tier_ceiling, "iat": now, "exp": now + ttl})

    def issue_mandate(self, patient: Patient, consent_token: str, agent: "Agent", record: dict,
                      purpose: str, actions: list[str], fields: list[str], counterparty_classes: list[str],
                      tier_ceiling: int, ttl: float = 7 * 86400) -> tuple[str, dict]:
        """Returns (mandate token, disclosures). Disclosures stay with the agent; only the
        ones needed for a request are presented (selective disclosure)."""
        c = verify_token(patient.pk, consent_token, "consent+jwt")
        # The mandate may not exceed what the patient consented to.
        if not (set(actions) <= set(c["actions"]) and set(fields) <= set(c["fields"])
                and set(counterparty_classes) <= set(c["counterparty_classes"])):
            raise ValueError("mandate exceeds consent")
        disclosures, digests = {}, []
        for f in fields:
            salt = b64u(secrets.token_bytes(16))
            d = b64u(canon([salt, f, record[f]]))
            disclosures[f] = d
            digests.append(sha256(d.encode()))
        now = time.time()
        mandate_id = "m-" + secrets.token_hex(8)
        tok = sign_token(self.sk, "mandate+sd-jwt", {
            "mandate_id": mandate_id, "operator_id": self.operator_id, "agent_id": agent.agent_id,
            "subject": self.pseudonym(patient.patient_id), "purpose_of_use": purpose,
            "actions": sorted(actions), "allowed_fields": sorted(fields), "_sd": sorted(digests),
            "counterparty_classes": sorted(counterparty_classes), "tier_ceiling": tier_ceiling,
            "consent_hash": sha256(consent_token.encode()), "patient_pub": c["patient_pub"],
            "parent": None, "iat": now, "exp": now + ttl})
        return tok, disclosures


class Agent:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.sk = Ed25519PrivateKey.generate()
        self.pk = self.sk.public_key()

    def attenuate(self, parent_mandate: str, parent_disclosures: dict, child: "Agent", actions: list[str],
                  fields: list[str], counterparty_classes: list[str], tier_ceiling: int, ttl: float) -> tuple[str, dict]:
        """Child mandate signed by this agent; scope must be a subset of the parent."""
        p = peek(parent_mandate)
        now = time.time()
        tok = sign_token(self.sk, "mandate+sd-jwt", {
            "mandate_id": "m-" + secrets.token_hex(8), "operator_id": p["operator_id"], "agent_id": child.agent_id,
            "subject": p["subject"], "purpose_of_use": p["purpose_of_use"], "actions": sorted(actions),
            "allowed_fields": sorted(fields), "_sd": p["_sd"], "counterparty_classes": sorted(counterparty_classes),
            "tier_ceiling": tier_ceiling, "consent_hash": p["consent_hash"], "patient_pub": p["patient_pub"],
            "parent": {"token": parent_mandate, "hash": sha256(parent_mandate.encode())},
            "iat": now, "exp": min(p["exp"], now + ttl)})
        return tok, {f: parent_disclosures[f] for f in fields}

    def request(self, attestation: str, mandate: str, disclosures: dict, action: str, counterparty_id: str,
                fields: list[str], nonce: str, approval: str | None = None, chain_attestations=None,
                consent: str = "", idp_cert: str = "") -> dict:
        req = {"attestation": attestation, "mandate": mandate, "consent": consent, "idp_cert": idp_cert,
               "action": action,
               "counterparty_id": counterparty_id, "fields": sorted(fields),
               "disclosures": [disclosures[f] for f in sorted(fields)], "nonce": nonce,
               "approval": approval, "chain_attestations": chain_attestations or [], "ts": time.time()}
        req["sig"] = b64u(self.sk.sign(canon({k: v for k, v in req.items() if k != "sig"})))
        return req


# ---------------------------------------------------------------- transparency log (P6)

class TransparencyLog:
    """Append-only hash chain with Merkle root checkpoints and inclusion proofs."""

    def __init__(self):
        self.leaves: list[str] = []
        self.chain: list[str] = []

    def append(self, entry: str) -> int:
        prev = self.chain[-1] if self.chain else "0" * 64
        leaf = sha256(entry.encode())
        self.leaves.append(leaf)
        self.chain.append(sha256((prev + leaf).encode()))
        return len(self.leaves) - 1

    @staticmethod
    def _root(level: list[str]) -> str:
        if not level:
            return "0" * 64
        while len(level) > 1:
            if len(level) % 2:
                level = level + [level[-1]]
            level = [sha256((level[i] + level[i + 1]).encode()) for i in range(0, len(level), 2)]
        return level[0]

    def root(self) -> str:
        return self._root(list(self.leaves))

    def inclusion_proof(self, idx: int) -> list[tuple[str, str]]:
        proof, level, i = [], list(self.leaves), idx
        while len(level) > 1:
            if len(level) % 2:
                level = level + [level[-1]]
            sib = i ^ 1
            proof.append(("L" if sib < i else "R", level[sib]))
            level = [sha256((level[j] + level[j + 1]).encode()) for j in range(0, len(level), 2)]
            i //= 2
        return proof

    @staticmethod
    def verify_inclusion(entry: str, proof, root: str) -> bool:
        h = sha256(entry.encode())
        for side, sib in proof:
            h = sha256((sib + h).encode()) if side == "L" else sha256((h + sib).encode())
        return h == root

    def verify_chain(self) -> bool:
        prev = "0" * 64
        for leaf, c in zip(self.leaves, self.chain):
            if sha256((prev + leaf).encode()) != c:
                return False
            prev = c
        return True


# ---------------------------------------------------------------- counterparty verifier

LEVELS = {
    # Verification configurations used in the conformance matrix (SPEC section 4).
    "L0_name_dob": set(),
    "L1_operator": {"P1"},
    "L2_operator_mandate": {"P1", "P2", "P3"},
    "L3_plus_fresh_status": {"P1", "P2", "P3", "P4", "P6"},
    "L4_full_hah": {"P1", "P2", "P3", "P4", "P5", "P6"},
}


class Counterparty:
    def __init__(self, counterparty_id: str, counterparty_class: str, directory: Directory,
                 status_sources: dict, log: TransparencyLog, level: str = "L4_full_hah",
                 idp_pub: Ed25519PublicKey | None = None):
        self.counterparty_id = counterparty_id
        self.idp_pub = idp_pub
        self.cls = counterparty_class
        self.directory = directory
        self.status_sources = status_sources     # operator_id -> StatusList
        self.log = log
        self.sk = Ed25519PrivateKey.generate()
        self.pk = self.sk.public_key()
        self.level = level
        self.issued_nonces: set = set()
        self.used_nonces: set = set()

    def challenge(self) -> str:
        n = secrets.token_hex(16)
        self.issued_nonces.add(n)
        return n

    # Each check returns None if passed, or a reason code.
    def verify(self, req: dict, name_dob_ok: bool = True) -> tuple[bool, str, dict | None]:
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
            agent_pk = pub_from(att["agent_pub"])
            body = {k: v for k, v in req.items() if k != "sig"}
            agent_pk.verify(b64u_dec(req["sig"]), canon(body))
        except (InvalidSignature, ValueError, KeyError):
            return False, "P1_P2_bad_signature", None
        if req["counterparty_id"] != self.counterparty_id:
            return False, "P1_wrong_audience", None
        if on == {"P1"}:
            return True, "accepted_operator_only", None

        # P3 mandate and its delegation chain
        ok, why, m = self._verify_mandate_chain(req, op, att)
        if not ok:
            return False, why, None
        # P3 consent binding: patient-signed consent, key certified by the identity provider.
        try:
            cert = verify_token(self.idp_pub, req["idp_cert"], "idp-cert+jwt")
            c = verify_token(pub_from(cert["patient_pub"]), req["consent"], "consent+jwt")
        except (InvalidSignature, ValueError, KeyError, AttributeError, TypeError):
            return False, "P3_consent_missing_or_invalid", None
        root = self._root_mandate(req["mandate"])
        if (sha256(req["consent"].encode()) != root["consent_hash"] or root["patient_pub"] != cert["patient_pub"]
                or not set(root["actions"]) <= set(c["actions"])
                or not set(root["allowed_fields"]) <= set(c["fields"])
                or not set(root["counterparty_classes"]) <= set(c["counterparty_classes"])):
            return False, "P3_mandate_exceeds_consent", None
        tier = tier_of(req["action"], req["fields"])
        if req["action"] not in m["actions"]:
            return False, "P3_action_not_in_mandate", None
        if not set(req["fields"]) <= set(m["allowed_fields"]):
            return False, "P3_field_not_in_mandate", None
        if self.cls not in m["counterparty_classes"]:
            return False, "P3_counterparty_class_not_in_mandate", None
        if tier > min(m["tier_ceiling"], att["tier_ceiling"]):
            return False, "P3_tier_above_ceiling", None
        for d, f in zip(req["disclosures"], req["fields"]):
            if sha256(d.encode()) not in m["_sd"] or json.loads(b64u_dec(d))[1] != f:
                return False, "P3_disclosure_not_bound", None
        if time.time() > m["exp"]:
            return False, "P3_mandate_expired", None

        if "P4" in on:
            if req["nonce"] not in self.issued_nonces or req["nonce"] in self.used_nonces:
                return False, "P4_nonce_replay_or_unknown", None
            snap = verify_token(pub_from(op.public_key), self.status_sources[op.operator_id].snapshot(), "status+jwt")
            if any(x in snap["revoked"] for x in self._chain_ids(req["mandate"])):
                return False, "P4_mandate_revoked", None

        if "P5" in on and tier == 3:
            if not req.get("approval"):
                return False, "P5_stepup_required", None
            try:
                a = verify_token(pub_from(m["patient_pub"]), req["approval"], "approval+jwt")
            except (InvalidSignature, ValueError):
                return False, "P5_bad_approval_signature", None
            tx = {"mandate_id": self._root_mandate_id(req["mandate"]), "action": req["action"],
                  "counterparty_id": self.counterparty_id, "fields": sorted(req["fields"]), "nonce": req["nonce"]}
            if a["tx_hash"] != sha256(canon(tx)):
                return False, "P5_approval_not_bound_to_tx", None

        if "P4" in on:
            self.used_nonces.add(req["nonce"])
        receipt = None
        if "P6" in on:
            receipt = self._receipt(req, m)
        return True, "accepted_full" if "P5" in on else "accepted", receipt

    def _chain_ids(self, mandate: str) -> list[str]:
        ids, tok = [], mandate
        while tok:
            p = peek(tok)
            ids.append(p["mandate_id"])
            tok = p["parent"]["token"] if p["parent"] else None
        return ids

    def _root_mandate_id(self, mandate: str) -> str:
        return self._chain_ids(mandate)[-1]

    def _root_mandate(self, mandate: str) -> dict:
        p = peek(mandate)
        while p["parent"]:
            p = peek(p["parent"]["token"])
        return p

    def _verify_mandate_chain(self, req, op, att):
        """Walk from the presented mandate to the operator-issued root. Each child must be
        signed by the agent named in its parent and be a subset of its parent."""
        tok = req["mandate"]
        child = None
        attest_by_agent = {att["agent_id"]: att}
        for t in req.get("chain_attestations", []):
            try:
                a = verify_token(pub_from(op.public_key), t, "attest+jwt")
                attest_by_agent[a["agent_id"]] = a
            except (InvalidSignature, ValueError):
                return False, "P2_bad_chain_attestation", None
        presented = None
        while True:
            p = peek(tok)
            if p["parent"] is None:
                signer = pub_from(op.public_key)
            else:
                parent_agent = peek(p["parent"]["token"])["agent_id"]
                if parent_agent not in attest_by_agent:
                    return False, "P2_missing_chain_attestation", None
                signer = pub_from(attest_by_agent[parent_agent]["agent_pub"])
                if sha256(p["parent"]["token"].encode()) != p["parent"]["hash"]:
                    return False, "P3_parent_hash_mismatch", None
            try:
                m = verify_token(signer, tok, "mandate+sd-jwt")
            except (InvalidSignature, ValueError):
                return False, "P3_bad_mandate_signature", None
            if presented is None:
                presented = m
                if m["agent_id"] != att["agent_id"]:
                    return False, "P3_mandate_not_for_this_agent", None
            if child is not None:
                if not (set(child["actions"]) <= set(m["actions"])
                        and set(child["allowed_fields"]) <= set(m["allowed_fields"])
                        and set(child["counterparty_classes"]) <= set(m["counterparty_classes"])
                        and child["tier_ceiling"] <= m["tier_ceiling"] and child["exp"] <= m["exp"]
                        and child["_sd"] == m["_sd"]):
                    return False, "P3_attenuation_violation", None
            if m["operator_id"] != op.operator_id:
                return False, "P3_operator_mismatch", None
            child = m
            if m["parent"] is None:
                break
            tok = m["parent"]["token"]
        return True, "", presented

    def _receipt(self, req, m) -> dict:
        entry = sign_token(self.sk, "receipt+jwt", {
            "counterparty_id": self.counterparty_id, "mandate_id": m["mandate_id"], "subject": m["subject"],
            "action": req["action"], "fields": req["fields"],
            "disclosed_hashes": [sha256(d.encode()) for d in req["disclosures"]],
            "request_hash": sha256(canon({k: v for k, v in req.items() if k != "sig"})), "ts": time.time()})
        idx = self.log.append(entry)
        return {"entry": entry, "index": idx, "root": self.log.root(), "proof": self.log.inclusion_proof(idx),
                "counterparty_pub": pub_bytes(self.pk)}


# ---------------------------------------------------------------- voice-channel fallback

class VerificationService:
    """Operator-run lookup for the PSTN fallback. The agent states a short code on the call; a
    human verifier looks it up over an authentic channel (directory-listed URL or callback)."""
    ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

    def __init__(self, operator: Operator):
        self.operator = operator
        self.codes: dict = {}

    def register(self, mandate: str, action: str, counterparty_id: str, ttl: float = 900) -> str:
        code = "".join(secrets.choice(self.ALPHABET) for _ in range(8))
        p = peek(mandate)
        self.codes[code] = {"operator": self.operator.operator_id, "purpose_of_use": p["purpose_of_use"],
                            "action": action, "counterparty_id": counterparty_id, "tier_ceiling": p["tier_ceiling"],
                            "mandate_exp": p["exp"], "code_exp": time.time() + ttl, "used": False}
        return code

    def lookup(self, code: str, counterparty_id: str) -> dict | None:
        r = self.codes.get(code)
        if r is None or r["used"] or time.time() > r["code_exp"] or r["counterparty_id"] != counterparty_id:
            return None
        r["used"] = True
        return {k: v for k, v in r.items() if k not in ("used",)}
