"""Permission-carrying (redemption) mode for the Health Agent Handshake, version 2.

The agent carries the patient's permission, not the patient's data. The operator issues a reference mandate whose
field disclosures name each field and the data holder that keeps it, with no value. The agent's request is the
version 2 request unchanged except that it carries no field values and no opening of the identity commitment. After the
counterparty verifies the request, it signs a redemption and sends it to the data holder (a health plan, provider, or
the patient's wallet). The data holder re-checks the evidence itself, because it carries the duty to disclose only the
minimum necessary, applies the content-based tier rules to the values it is about to release, and releases the
requested fields sealed to the counterparty's encryption key and signed by the holder, once per request and per
counterparty challenge. A hash of each signed release goes into the transparency log.

Neither the operator nor the agent holds the field values or the salt of the identity commitment, so an agent that is
manipulated, or an operator that is compromised, has nothing beyond the task's parameters to disclose and cannot recover
the patient's name and date of birth by guessing against the commitment. formal/v2/hah2_redeem.spthy models this mode.

This module adds to hah2.py without changing it. Identity binding moves to the data holder: the holder finds the record by
the identity provider's certified subject commitment and states that commitment in its signed release, and the
counterparty checks it against the certificate. A counterparty that cannot see field values before redemption cannot use
its own records to lower a tier, so actions on existing appointments or rides are tier 3 in this mode.
"""
from __future__ import annotations

import json
import math
import os
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import hah2 as H

REF_KEY = "held_by"
REDEMPTION_TYP = "hah2-redemption"
RELEASE_TYP = "hah2-release"


def _finite(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def _canon(obj) -> bytes:
    """Canonical JSON that rejects NaN and infinities (hah2.canon accepts them)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


# ---------------------------------------------------------------- sealing (X25519 + HKDF-SHA256 + AES-256-GCM)

def _x_pub_bytes(pk: X25519PublicKey) -> str:
    return H.b64u(pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def _seal_key(shared: bytes, epk: str, recipient_pub: str) -> bytes:
    # The KDF binds both public keys, as in HPKE's key schedule.
    return HKDF(hashes.SHA256(), 32, None, b"hah2-redeem-seal|" + epk.encode() + b"|" + recipient_pub.encode()).derive(shared)


def seal(recipient_pub: str, plaintext: bytes, aad: bytes) -> dict:
    eph = X25519PrivateKey.generate()
    epk = _x_pub_bytes(eph.public_key())
    shared = eph.exchange(X25519PublicKey.from_public_bytes(H.b64u_dec(recipient_pub)))
    nonce = os.urandom(12)
    return {"epk": epk, "nonce": H.b64u(nonce),
            "ct": H.b64u(AESGCM(_seal_key(shared, epk, recipient_pub)).encrypt(nonce, plaintext, aad))}


def unseal(sk: X25519PrivateKey, box: dict, aad: bytes) -> bytes:
    shared = sk.exchange(X25519PublicKey.from_public_bytes(H.b64u_dec(box["epk"])))
    key = _seal_key(shared, box["epk"], _x_pub_bytes(sk.public_key()))
    return AESGCM(key).decrypt(H.b64u_dec(box["nonce"]), H.b64u_dec(box["ct"]), aad)


def request_hash(req: dict) -> str:
    return H.sha256(_canon({k: v for k, v in req.items() if k != "sig"}))


# ---------------------------------------------------------------- trust framework additions

@dataclass
class CounterpartyEntry:
    counterparty_id: str
    counterparty_class: str
    signing_key: str        # Ed25519, authenticates redemptions
    sealing_key: str        # X25519, receives sealed releases
    revoked: bool = False


class CounterpartyDirectory:
    """Trust-framework directory of counterparties. An identifier can be registered once; entries can be revoked."""

    def __init__(self):
        self.entries: dict = {}

    def register(self, e: CounterpartyEntry):
        if e.counterparty_id in self.entries:
            raise ValueError("counterparty identifier already registered")
        self.entries[e.counterparty_id] = e

    def get(self, cid) -> CounterpartyEntry | None:
        e = self.entries.get(cid) if isinstance(cid, str) else None
        return None if e is None or e.revoked else e


def issue_reference_mandate(op: H.Operator, patient: H.Patient, idp_cert: str, idp_pub, consent_token: str,
                            consent_disc: dict, agent: H.Agent, holder_id: str, actions: list[str], fields: list[str],
                            counterparty_classes: list[str], tier_ceiling: int, ttl: float = 7 * 86400):
    """Like Operator.issue_mandate, but the operator never sees field values: each field disclosure names the data holder
    that keeps the field. The opening of the identity commitment (its salt) is withheld from the operator, and so from
    the agent, because with it name and date of birth could be recovered by guessing against the commitment."""
    record = {"subject_commitment": patient.subject_commitment, **{f: {REF_KEY: holder_id} for f in fields}}
    cdisc = {k: v for k, v in consent_disc.items() if k != ("opening",)}
    return op.issue_mandate(patient, idp_cert, idp_pub, consent_token, cdisc, agent, record, actions,
                            fields, counterparty_classes, tier_ceiling, ttl)


# ---------------------------------------------------------------- shared verification of a reference request

def _check_stepup(req: dict, cert: dict, root: dict, verifier_id: str):
    """P5: the patient's approval of exactly this transaction, under the identity-provider-certified key."""
    if not req.get("approval"):
        return False, "P5_stepup_required"
    try:
        a = H.verify_token(H.pub_from(cert["patient_pub"]), req["approval"], "approval+jwt")
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False, "P5_bad_approval_signature"
    tx = {"mandate_id": root["mandate_id"], "action": req["action"],
          "params_hash": H.sha256(H.canon(req.get("params") or {})), "counterparty_id": verifier_id,
          "fields": sorted(req["fields"]), "nonce": req["nonce"]}
    if a.get("tx_hash") != H.sha256(H.canon(tx)) or {k: a.get(k) for k in tx} != tx:
        return False, "P5_approval_not_bound_to_tx"
    return True, ""


def check_reference_request(req, *, verifier_id: str, verifier_class: str, directory: H.Directory,
                            operator_status: dict, idp: H.IdentityProvider, chain_checker) -> tuple[bool, str, dict]:
    """Checks P1 to P5 of a version 2 request whose field disclosures are references, for the verifier named in the
    request (the counterparty, or the data holder acting on the counterparty's behalf). Returns (ok, reason, context).
    Mirrors hah2.Counterparty._verify except that identity binding and the content-based tier rules move to the data
    holder, which is the only party that sees the values. Malformed input is rejected, never raised."""
    try:
        return _check_reference_request(req, verifier_id, verifier_class, directory, operator_status, idp, chain_checker)
    except Exception:  # noqa: BLE001  any malformed request is a refusal, not a crash
        return False, "malformed_request", {}


def _check_reference_request(req, verifier_id, verifier_class, directory, operator_status, idp, chain_checker):
    if not isinstance(req, dict) or not _finite(req.get("ts")) or not isinstance(req.get("nonce"), str):
        return False, "malformed_request", {}
    if not isinstance(req.get("fields"), list) or not all(isinstance(f, str) for f in req["fields"]):
        return False, "malformed_request", {}
    att = H.peek(req["attestation"])
    op = directory.get(att["operator_id"])
    if op is None:
        return False, "P1_unknown_or_revoked_operator", {}
    try:
        att = H.verify_token(H.pub_from(op.public_key), req["attestation"], "attest+jwt")
        H.pub_from(att["agent_pub"]).verify(H.b64u_dec(req["sig"]), H.canon({k: v for k, v in req.items() if k != "sig"}))
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False, "P1_P2_bad_signature", {}
    if not _finite(att.get("exp")) or time.time() > att["exp"]:
        return False, "P2_attestation_expired", {}
    if req["counterparty_id"] != verifier_id:
        return False, "P1_wrong_audience", {}
    if abs(time.time() - req["ts"]) > H.REQUEST_SKEW:
        return False, "P4_stale_request", {}
    ok, why, m, root = chain_checker(req, op, att)
    if not ok:
        return False, why, {}
    try:
        cert = H.verify_token(idp.pk, req["idp_cert"], "idp-cert+jwt")
        c = H.verify_token(H.pub_from(cert["patient_pub"]), req["consent"], "consent+jwt")
    except (InvalidSignature, ValueError, KeyError, TypeError, AttributeError):
        return False, "P3_consent_missing_or_invalid", {}
    if (H.sha256(req["consent"].encode()) != root["consent_hash"] or root["patient_pub"] != cert["patient_pub"]
            or c["subject_commitment"] != cert["subject_commitment"] or c["operator_id"] != root["operator_id"]
            or c["agent_id"] != root["agent_id"] or c["purpose_of_use"] != root["purpose_of_use"]):
        return False, "P3_consent_not_bound_to_mandate", {}
    if not (_finite(c.get("exp")) and _finite(m.get("exp"))) or time.time() > c["exp"] or time.time() > m["exp"]:
        return False, "P3_consent_or_mandate_expired", {}
    if req["action"] not in H.ACTION_TIER:
        return False, "P3_unknown_action", {}
    ad = req.get("action_disclosure")
    if not ad or H.digest(ad) not in m["_sd"] or H.open_disclosure(ad)[0] != "action" or H.open_disclosure(ad)[1][0] != req["action"]:
        return False, "P3_action_not_in_mandate", {}
    if len(req["disclosures"]) != len(req["fields"]) or len(set(req["fields"])) != len(req["fields"]):
        return False, "P3_field_not_in_mandate", {}
    holders = set()
    for d, f in zip(req["disclosures"], req["fields"]):
        if H.digest(d) not in m["_sd"] or H.open_disclosure(d)[0] != f:
            return False, "P3_field_not_in_mandate", {}
        v = H.open_disclosure(d)[1]
        if not isinstance(v, dict) or set(v) != {REF_KEY} or not isinstance(v[REF_KEY], str):
            return False, "R_field_value_carried_by_agent", {}
        holders.add(v[REF_KEY])
    if len(holders) != 1:
        return False, "R_fields_split_across_holders", {}
    if req.get("subject_opening") is not None:
        return False, "R_identity_opening_carried_by_agent", {}
    if "name" not in req["fields"] or "dob" not in req["fields"]:
        return False, "P3_subject_not_bound_to_certified_identity", {}
    cds = req.get("consent_disclosures") or []
    if (len(cds) != 1 + len(req["fields"]) or any(x is None or H.digest(x) not in c["_sd"] for x in cds)
            or H.open_disclosure(cds[0])[0] != "action" or H.open_disclosure(cds[0])[1][0] != req["action"]
            or [H.open_disclosure(x) for x in cds[1:]] != [("field", f) for f in req["fields"]]):
        return False, "P3_mandate_exceeds_consent", {}
    consent_tier = int(H.open_disclosure(cds[0])[1][1])
    sd = req.get("subject_disclosure")
    if not sd or H.digest(sd) not in m["_sd"] or H.open_disclosure(sd)[0] != f"subject:{verifier_class}":
        return False, "P3_subject_not_disclosed", {}
    if verifier_class not in m["counterparty_classes"] or verifier_class not in c["counterparty_classes"]:
        return False, "P3_counterparty_class_not_in_mandate", {}
    try:
        # Without field values the verifier cannot use its own records to lower a tier (holds=False, no object record).
        tier = H.tier_of(req["action"], req["fields"], req.get("params"), consent_tier=consent_tier,
                         counterparty_holds_rx=False, object_service=None)
    except ValueError:
        return False, "P3_unknown_parameter", {}
    if tier > min(m["tier_ceiling"], att["tier_ceiling"]):
        return False, "P3_tier_above_ceiling", {}
    st = H.verify_token(H.pub_from(op.public_key), operator_status[op.operator_id].snapshot(), "status+jwt")
    cs = H.verify_token(idp.pk, idp.snapshot(), "consent-status+jwt")
    if time.time() - st["iat"] > H.STATUS_MAX_AGE or time.time() - cs["iat"] > H.STATUS_MAX_AGE:
        return False, "P4_status_stale", {}
    chain, tok = [], req["mandate"]
    while tok:
        p = H.peek(tok)
        chain.append(p)
        tok = p["parent"]["token"] if p["parent"] else None
    if any(p["mandate_id"] in st["mandates"] for p in chain) or any(p["agent_id"] in st["agents"] for p in chain):
        return False, "P4_mandate_or_agent_revoked", {}
    if root["consent_hash"] in cs["revoked"]:
        return False, "P4_consent_revoked_by_patient", {}
    if tier == 3:
        ok, why = _check_stepup(req, cert, root, verifier_id)
        if not ok:
            return False, why, {}
    return True, "accepted_reference", {"holder_id": holders.pop(), "cert": cert, "consent": c, "mandate": m,
                                         "attestation": att, "root": root, "tier": tier, "subject_pseudonym": H.open_disclosure(sd)[1]}


# ---------------------------------------------------------------- data holder

class DataHolder:
    """Keeps patients' records and releases fields only on a verified redemption. Records are keyed by the identity
    provider's subject commitment, so the holder releases data only for the certified person."""

    def __init__(self, holder_id: str, directory: H.Directory, operator_status: dict, idp: H.IdentityProvider,
                 counterparties: CounterpartyDirectory, log: H.TransparencyLog | None = None):
        self.holder_id = holder_id
        self.directory = directory
        self.operator_status = operator_status
        self.idp = idp
        self.counterparties = counterparties
        self.transparency_log = log
        self.sk = Ed25519PrivateKey.generate()
        self.pk = self.sk.public_key()
        self.records: dict = {}
        self.redeemed: set = set()            # request hashes
        self.redeemed_challenges: set = set() # (counterparty, nonce): one release per counterparty challenge
        self.log: list = []

    def add_record(self, subject_commitment: str, record: dict):
        self.records[subject_commitment] = dict(record)

    def redeem(self, redemption) -> tuple[bool, str, dict | None]:
        try:
            return self._redeem(redemption)
        except Exception:  # noqa: BLE001  any malformed redemption is a refusal, not a crash
            return False, "malformed_redemption", None

    def _redeem(self, redemption):
        if not isinstance(redemption, dict) or not isinstance(redemption.get("request"), dict):
            return False, "malformed_redemption", None
        req = redemption["request"]
        cid = redemption.get("counterparty_id")
        entry = self.counterparties.get(cid)
        if entry is None:
            return False, "R_unknown_redeemer", None
        body = {"typ": REDEMPTION_TYP, "request_hash": request_hash(req), "counterparty_id": cid,
                "holder_id": redemption.get("holder_id")}
        try:
            H.pub_from(entry.signing_key).verify(H.b64u_dec(redemption["sig"]), _canon(body))
        except (InvalidSignature, ValueError, KeyError, TypeError):
            return False, "R_bad_redeemer_signature", None
        if redemption.get("holder_id") != self.holder_id:
            return False, "R_wrong_holder", None
        ok, why, ctx = check_reference_request(
            req, verifier_id=cid, verifier_class=entry.counterparty_class, directory=self.directory,
            operator_status=self.operator_status, idp=self.idp,
            chain_checker=lambda r, op, att: H.Counterparty._verify_chain(self, r, op, att))
        if not ok:
            return False, why, None
        if ctx["holder_id"] != self.holder_id:
            return False, "R_fields_not_held_here", None
        rh = request_hash(req)
        if rh in self.redeemed or (cid, req["nonce"]) in self.redeemed_challenges:
            return False, "R_already_redeemed", None
        subject = ctx["cert"]["subject_commitment"]
        rec = self.records.get(subject)
        if rec is None or any(f not in rec for f in req["fields"]):
            return False, "R_no_record_for_certified_subject", None
        values = {f: rec[f] for f in req["fields"]}
        # Content-based tier rules, as in hah2.Counterparty._verify: a value that names a controlled or protected drug or
        # service raises the request to tier 3. The raised tier must be within the mandate's and the attestation's
        # ceilings, as at the counterparty, and it needs the patient's approval of this transaction.
        if ctx["tier"] < 3 and H.protected_content([v for k, v in values.items() if k not in ("name", "dob")]):
            if 3 > min(ctx["mandate"]["tier_ceiling"], ctx["attestation"]["tier_ceiling"]):
                return False, "P3_tier_above_ceiling_protected_content", None
            ok, why = _check_stepup(req, ctx["cert"], ctx["root"], cid)
            if not ok:
                return False, why + "_protected_content", None
        aad = _canon({"holder_id": self.holder_id, "counterparty_id": cid, "request_hash": rh,
                      "subject_commitment": subject})
        release = {"typ": RELEASE_TYP, "holder_id": self.holder_id, "counterparty_id": cid, "request_hash": rh,
                   "subject_commitment": subject, "box": seal(entry.sealing_key, _canon(values), aad)}
        release["sig"] = H.b64u(self.sk.sign(_canon(release)))
        self.redeemed.add(rh)
        self.redeemed_challenges.add((cid, req["nonce"]))
        if self.transparency_log is not None:
            release["log_index"] = self.transparency_log.append(H.sha256(_canon(release)))
        self.log.append({"request_hash": rh, "counterparty_id": cid, "fields": sorted(req["fields"]), "ts": time.time()})
        return True, "released", release


# ---------------------------------------------------------------- redeeming counterparty

class RedeemingCounterparty(H.Counterparty):
    def __init__(self, *args, holders: dict | None = None, **kw):
        super().__init__(*args, **kw)
        self.xsk = X25519PrivateKey.generate()
        self.holders = holders or {}      # holder_id -> Ed25519 public key (trust framework)

    def directory_entry(self) -> CounterpartyEntry:
        """The entry a trust framework registers for this counterparty after vetting it."""
        return CounterpartyEntry(self.counterparty_id, self.cls, H.pub_bytes(self.pk), _x_pub_bytes(self.xsk.public_key()))

    def verify_reference(self, req):
        try:
            if not isinstance(req, dict) or not isinstance(req.get("nonce"), str):
                return False, "malformed_request", {}
            issued = self.issued_nonces.get(req["nonce"])
            if issued is None or req["nonce"] in self.used_nonces or time.time() - issued[0] > issued[1]:
                return False, "P4_nonce_replay_unknown_or_expired", {}
            ok, why, ctx = check_reference_request(
                req, verifier_id=self.counterparty_id, verifier_class=self.cls, directory=self.directory,
                operator_status=self.operator_status, idp=self.idp, chain_checker=self._verify_chain)
            if ok and ctx["holder_id"] not in self.holders:
                return False, "R_unknown_holder", {}
            if ok:
                self.used_nonces.add(req["nonce"])
            return ok, why, ctx
        except Exception:  # noqa: BLE001
            return False, "malformed_request", {}

    def redemption(self, req: dict, holder_id: str) -> dict:
        body = {"typ": REDEMPTION_TYP, "request_hash": request_hash(req), "counterparty_id": self.counterparty_id,
                "holder_id": holder_id}
        return {"request": req, **{k: v for k, v in body.items() if k != "typ"}, "sig": H.b64u(self.sk.sign(_canon(body)))}

    def open_release(self, req: dict, ctx: dict, release) -> tuple[bool, str, dict | None]:
        try:
            return self._open_release(req, ctx, release)
        except Exception:  # noqa: BLE001
            return False, "malformed_release", None

    def _open_release(self, req, ctx, release):
        hp = self.holders.get(release.get("holder_id")) if isinstance(release, dict) else None
        if hp is None or release.get("holder_id") != ctx["holder_id"] or release.get("typ") != RELEASE_TYP:
            return False, "R_unknown_holder", None
        try:
            signed = {k: v for k, v in release.items() if k not in ("sig", "log_index")}
            hp.verify(H.b64u_dec(release["sig"]), _canon(signed))
        except (InvalidSignature, ValueError, KeyError, TypeError):
            return False, "R_bad_holder_signature", None
        rh = request_hash(req)
        if release["request_hash"] != rh or release["counterparty_id"] != self.counterparty_id:
            return False, "R_release_not_for_this_request", None
        # Identity binding: the holder found the record by the certified subject commitment and says so in its signature.
        if release.get("subject_commitment") != ctx["cert"]["subject_commitment"]:
            return False, "P3_subject_not_bound_to_certified_identity", None
        aad = _canon({"holder_id": release["holder_id"], "counterparty_id": self.counterparty_id, "request_hash": rh,
                      "subject_commitment": release["subject_commitment"]})
        try:
            values = json.loads(unseal(self.xsk, release["box"], aad))
        except (InvalidTag, ValueError, KeyError):
            return False, "R_cannot_open_release", None
        if not isinstance(values, dict) or set(values) != set(req["fields"]):
            return False, "R_release_fields_mismatch", None
        if self.identity_counts.get((str(values["name"]).strip().lower(), str(values["dob"]).strip()), 1) > 1:
            return False, "P3_identity_ambiguous_manual_verification", None
        return True, "accepted_with_released_fields", values
