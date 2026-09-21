# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""SkillRegistry — Decentralized Skill Certification via Peer Attestation

> Users prove skills through peer attestations, verified by consensus.
> No central authority — skills are certified when enough peers vouch
> for a candidate at a specific level, with high-quality reasoning.

Unique patterns:
  1. Anti-sybil attestation (unique attestors required)
  2. Level-gated verification (attestation >= claimed level)
  3. LLM reasoning quality evaluation in consensus
  4. EIP-191 registration signature
"""

import json
import ast
from datetime import datetime, timezone
from dataclasses import dataclass

from genlayer import *
from genlayer.py.keccak import Keccak256

LEVEL_BEGINNER = 1
LEVEL_INTERMEDIATE = 2
LEVEL_ADVANCED = 3
LEVEL_EXPERT = 4

MIN_ATTESTATIONS = 3
MIN_UNIQUE_ATTESTORS = 3
MIN_REASONING_CHARS = 20
MAX_REASONING_CHARS = 500
MAX_SKILL_NAME = 64
MAX_CONTENT_CHARS = 10000

ERROR_LLM = "[LLM] "
ERROR_EXTERNAL = "[EXTERNAL] "
ERROR_TRANSIENT = "[TRANSIENT] "
ERROR_EXPECTED = "[EXPECTED] "


def _now_ts() -> int:
    try:
        dt = datetime.now(timezone.utc)
        return int(dt.timestamp())
    except Exception:
        pass
    try:
        raw = gl.message_raw["datetime"]
        if not raw:
            return 0
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except Exception:
        return 0


def _addr_hex(addr) -> str:
    if hasattr(addr, "as_hex"):
        return str(addr.as_hex).lower().replace("0x", "")
    if hasattr(addr, "as_bytes"):
        return bytes(addr.as_bytes).hex().lower()
    if hasattr(addr, "hex"):
        return addr.hex().lower()
    if hasattr(addr, "__bytes__"):
        return bytes(addr).hex().lower()
    return str(addr).lower().replace("0x", "")


def _addr_eq(a, b) -> bool:
    return _addr_hex(a) == _addr_hex(b)


def _secp_inv(a: int, m: int) -> int:
    return pow(a, m - 2, m)


def _secp_add(p, q):
    _SECP256K1_P = 2**256 - 2**32 - 977
    _SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    _SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    _SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _SECP256K1_P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0]) * _secp_inv(2 * p[1], _SECP256K1_P) % _SECP256K1_P
    else:
        lam = (q[1] - p[1]) * _secp_inv(q[0] - p[0], _SECP256K1_P) % _SECP256K1_P
    x = (lam * lam - p[0] - q[0]) % _SECP256K1_P
    y = (lam * (p[0] - x) - p[1]) % _SECP256K1_P
    return (x, y)


def _secp_mul(k: int, pt):
    if k == 0 or pt is None:
        return None
    if k < 0:
        return _secp_mul(-k, (pt[0], (-pt[1]) % _SECP256K1_P))
    result = None
    while k:
        if k & 1:
            result = _secp_add(result, pt)
        pt = _secp_add(pt, pt)
        k >>= 1
    return result


_SECP256K1_P = 2**256 - 2**32 - 977
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _keccak256(data) -> bytes:
    return Keccak256(data).digest()


def _eip191_digest(message: str) -> bytes:
    raw = message.encode("utf-8")
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(raw)).encode("ascii")
    return _keccak256(prefix + raw)


def _ecrecover(msg_hash: bytes, r: int, s: int, v: int):
    try:
        recid = (v - 27) & 3
        z = int.from_bytes(msg_hash, "big")
        x = r + (recid >> 1) * _SECP256K1_N
        if x >= _SECP256K1_P:
            return None
        y2 = (pow(x, 3, _SECP256K1_P) + 7) % _SECP256K1_P
        y = pow(y2, (_SECP256K1_P + 1) // 4, _SECP256K1_P)
        if (y & 1) != (recid & 1):
            y = _SECP256K1_P - y
        R = (x, y)
        rinv = _secp_inv(r, _SECP256K1_N)
        sR = _secp_mul(s, R)
        zG = _secp_mul(z % _SECP256K1_N, (_SECP256K1_GX, _SECP256K1_GY))
        neg_zG = (zG[0], (-zG[1]) % _SECP256K1_P)
        Q = _secp_mul(rinv, _secp_add(sR, neg_zG))
        if Q is None:
            return None
        if Q[0] >= _SECP256K1_P or Q[1] >= _SECP256K1_P:
            return None
        pub = bytes([4]) + Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big")
        return "0x" + _keccak256(pub[1:])[12:].hex()
    except Exception:
        return None


def _signer_of(sign_msg: str, signature: str):
    if not signature or not signature.startswith("0x"):
        return None
    try:
        sig_bytes = bytes.fromhex(signature[2:])
    except ValueError:
        return None
    if len(sig_bytes) != 65:
        return None
    r = int.from_bytes(sig_bytes[:32], "big")
    s = int.from_bytes(sig_bytes[32:64], "big")
    v = sig_bytes[64]
    msg_hash = _eip191_digest(sign_msg)
    recovered = _ecrecover(msg_hash, r, s, v)
    return recovered.lower().replace("0x", "") if recovered else None


def _validate_skill_name(name: str) -> bool:
    return bool(name) and len(name) <= MAX_SKILL_NAME and all(c.isalnum() or c in "-_" for c in name)


def _eval_reasoning_quality(reasoning: str) -> int:
    prompt = f"""Evaluate this attestation reasoning for credibility and substance. Score 0-100.

Criteria:
- Specific and concrete: 0-25
- Provides evidence or examples: 0-25
- Relevant to claimed skill level: 0-25
- Not generic or filler: 0-25

Reasoning: {reasoning}

Return ONLY JSON: {{"score": 0-100}}"""
    try:
        out = gl.nondet.exec_prompt(prompt, response_format="json")
    except Exception:
        raise gl.vm.UserError(ERROR_LLM + "Reasoning evaluation failed")
    if not isinstance(out, dict) or "score" not in out:
        raise gl.vm.UserError(ERROR_LLM + "Invalid reasoning evaluation")
    try:
        return max(0, min(100, int(out["score"])))
    except (ValueError, TypeError):
        raise gl.vm.UserError(ERROR_LLM + "Invalid score")


@allow_storage
@dataclass
class User:
    address: Address
    registered_ts: u256


@allow_storage
@dataclass
class Attestation:
    attester: Address
    target: Address
    skill_name: str
    level: u256
    reasoning: str
    submitted_ts: u256


@allow_storage
@dataclass
class SkillEntry:
    target: Address
    skill_name: str
    claimed_level: u256
    attest_count: u256
    unique_attestors: u256
    best_reasoning_score: u256
    verified: bool
    verified_level: u256
    created_ts: u256


class SkillRegistry(gl.Contract):
    users: TreeMap[str, User]
    attestations: TreeMap[str, Attestation]
    skills: TreeMap[str, SkillEntry]
    attest_seq: TreeMap[str, u256]

    def __init__(self):
        pass

    @gl.public.write
    def register(self, signature: str) -> None:
        if not signature or len(signature) > 200 or not signature.startswith("0x"):
            raise gl.vm.UserError("signature must be a 0x-prefixed hex string")
        sign_msg = f"SkillRegistry:register"
        signer = _signer_of(sign_msg, signature)
        if signer is None:
            raise gl.vm.UserError("invalid signature")
        addr_hex = signer.lower().replace("0x", "")
        if addr_hex in self.users:
            raise gl.vm.UserError("already registered")
        sender = gl.message.sender_address
        ts = _now_ts()
        self.users[addr_hex] = User(address=sender, registered_ts=ts)

    @gl.public.write
    def claim_skill(self, skill_name: str, level: int) -> None:
        if not _validate_skill_name(skill_name):
            raise gl.vm.UserError("invalid skill_name")
        if level < LEVEL_BEGINNER or level > LEVEL_EXPERT:
            raise gl.vm.UserError("invalid level")
        sender = gl.message.sender_address
        addr_hex = _addr_hex(sender)
        if addr_hex not in self.users:
            raise gl.vm.UserError("user not registered")
        key = f"{addr_hex}:{skill_name}"
        if key in self.skills:
            raise gl.vm.UserError("skill already claimed")
        ts = _now_ts()
        self.skills[key] = SkillEntry(
            target=sender,
            skill_name=skill_name,
            claimed_level=level,
            attest_count=0,
            unique_attestors=0,
            best_reasoning_score=0,
            verified=False,
            verified_level=0,
            created_ts=ts,
        )

    @gl.public.write
    def attest(self, target: Address, skill_name: str, level: int, reasoning: str, signature: str) -> None:
        if not _validate_skill_name(skill_name):
            raise gl.vm.UserError("invalid skill_name")
        if level < LEVEL_BEGINNER or level > LEVEL_EXPERT:
            raise gl.vm.UserError("invalid level")
        if not reasoning or len(reasoning) < MIN_REASONING_CHARS or len(reasoning) > MAX_REASONING_CHARS:
            raise gl.vm.UserError(f"reasoning must be {MIN_REASONING_CHARS}-{MAX_REASONING_CHARS} characters")
        if not signature or len(signature) > 200 or not signature.startswith("0x"):
            raise gl.vm.UserError("invalid signature")
        if not hasattr(target, "as_bytes"):
            target = Address(target)
        target_hex = _addr_hex(target)
        if target_hex not in self.users:
            raise gl.vm.UserError("target not registered")
        sender = gl.message.sender_address
        if _addr_eq(sender, target):
            raise gl.vm.UserError("cannot attest for yourself")
        key = f"{target_hex}:{skill_name}"
        if key not in self.skills:
            raise gl.vm.UserError("skill not claimed")
        attester_hex = _addr_hex(sender)
        att_key = f"{attester_hex}:{target_hex}:{skill_name}"
        for k, a in self.attestations.items():
            if _addr_hex(a.attester) == attester_hex and _addr_hex(a.target) == target_hex and a.skill_name == skill_name:
                raise gl.vm.UserError("already attested")
        sign_msg = f"SkillRegistry:attest:{target_hex}:{skill_name}:{level}:{reasoning[:50]}"
        signer = _signer_of(sign_msg, signature)
        if signer is None or signer.lower() != attester_hex:
            raise gl.vm.UserError("invalid attestation signature")
        ts = _now_ts()
        seq = int(self.attest_seq.get(key, 0))
        att_id = f"{key}:{seq}"
        self.attestations[att_id] = Attestation(
            attester=sender,
            target=target,
            skill_name=skill_name,
            level=level,
            reasoning=reasoning,
            submitted_ts=ts,
        )
        self.attest_seq[key] = seq + 1
        entry = self.skills[key]
        entry.attest_count = entry.attest_count + 1
        self.skills[key] = entry

    @gl.public.write
    def evaluate_skill(self, target: Address, skill_name: str) -> None:
        target_hex = _addr_hex(target)
        key = f"{target_hex}:{skill_name}"
        if key not in self.skills:
            raise gl.vm.UserError("skill not claimed")
        entry = self.skills[key]
        attestation_list = []
        for k, a in self.attestations.items():
            if a.skill_name == skill_name and _addr_hex(a.target) == target_hex:
                attestation_list.append(a)
        result = _run_skill_consensus(target_hex, skill_name, entry.claimed_level, attestation_list)
        ts = _now_ts()
        entry.verified = result["verified"]
        entry.verified_level = result["verified_level"]
        entry.best_reasoning_score = result["best_reasoning_score"]
        entry.created_ts = ts
        self.skills[key] = entry

    @gl.public.view
    def get_skill(self, target: Address, skill_name: str) -> dict:
        key = f"{_addr_hex(target)}:{skill_name}"
        if key not in self.skills:
            return {}
        s = self.skills[key]
        return {
            "target": _addr_hex(s.target),
            "skill_name": s.skill_name,
            "claimed_level": s.claimed_level,
            "attest_count": s.attest_count,
            "unique_attestors": s.unique_attestors,
            "best_reasoning_score": s.best_reasoning_score,
            "verified": s.verified,
            "verified_level": s.verified_level,
            "created_ts": s.created_ts,
        }

    @gl.public.view
    def get_attestation(self, attester: Address, target: Address, skill_name: str) -> dict:
        att_id = f"{_addr_hex(attester)}:{_addr_hex(target)}:{skill_name}"
        for k, v in self.attestations.items():
            if _addr_hex(v.attester) == _addr_hex(attester) and _addr_hex(v.target) == _addr_hex(target) and v.skill_name == skill_name:
                return {
                    "attester": _addr_hex(v.attester),
                    "target": _addr_hex(v.target),
                    "skill_name": v.skill_name,
                    "level": v.level,
                    "reasoning": v.reasoning[:MAX_CONTENT_CHARS],
                    "submitted_ts": v.submitted_ts,
                }
        return {}

    @gl.public.view
    def get_user_skills(self, user: Address) -> list:
        addr_hex = _addr_hex(user)
        skills = []
        for k, s in self.skills.items():
            if _addr_hex(s.target) == addr_hex:
                skills.append({
                    "skill_name": s.skill_name,
                    "claimed_level": s.claimed_level,
                    "attest_count": s.attest_count,
                    "verified": s.verified,
                    "verified_level": s.verified_level,
                })
        return skills


def _run_skill_consensus(target_hex: str, skill_name: str, claimed_level: int, attestations: list) -> dict:
    def leader_fn():
        unique = set()
        best_score = 0
        for a in attestations:
            unique.add(_addr_hex(a.attester))
            score = _eval_reasoning_quality(a.reasoning)
            if score > best_score:
                best_score = score
        total = len(attestations)
        unique_count = len(unique)
        highest_level = 0
        for a in attestations:
            if a.level > highest_level:
                highest_level = a.level
        if total >= MIN_ATTESTATIONS and unique_count >= MIN_UNIQUE_ATTESTORS and highest_level >= claimed_level and best_score >= 50:
            verified = True
            verified_level = claimed_level
        else:
            verified = False
            verified_level = 0
        return {
            "verified": verified,
            "verified_level": verified_level,
            "attest_count": total,
            "unique_attestors": unique_count,
            "best_reasoning_score": best_score,
        }

    def _decision_fields(data: dict) -> tuple:
        return (data.get("verified"), int(data.get("attest_count", 0)), int(data.get("best_reasoning_score", 0)))

    def validator_fn(leader_result):
        if not isinstance(leader_result, gl.vm.Return):
            return _reproduce_leader_error(leader_result, leader_fn)
        leader_data = leader_result.calldata
        if not isinstance(leader_data, dict):
            return False
        my = leader_fn()
        return _decision_fields(my) == _decision_fields(leader_data)

    return gl.vm.run_nondet_unsafe(leader_fn, validator_fn)


def _reproduce_leader_error(leader_result, leader_fn) -> bool:
    leader_msg = getattr(leader_result, "message", "") or ""
    try:
        leader_fn()
        return False
    except gl.vm.UserError as e:
        v_msg = e.message if hasattr(e, "message") else str(e)
        if v_msg.startswith(ERROR_EXPECTED) or v_msg.startswith(ERROR_EXTERNAL):
            return v_msg == leader_msg
        if v_msg.startswith(ERROR_TRANSIENT) and leader_msg.startswith(ERROR_TRANSIENT):
            return True
        return False
    except Exception:
        return False
