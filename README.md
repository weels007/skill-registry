# SkillRegistry — Decentralized Skill Certification via Peer Attestation

> **Prove your skills through peer attestations, verified by consensus.**
> Users certify skills by earning attestations from peers at matching or higher levels.
> Consensus validates reasoning quality and attestation quantity on-chain.

[![GenLayer](https://img.shields.io/badge/Built%20on-GenLayer-6366f1?style=for-the-badge&logo=genlayer)](https://genlayer.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Equivalence](https://img.shields.io/badge/Equivalence%20Principle-OK-16a34a?style=for-the-badge)](https://docs.genlayer.com/developers/intelligent-contracts/equivalence-principle)
[![Tests](https://img.shields.io/badge/tests-21%20passed-16a34a?style=for-the-badge)](https://github.com/)

---

## Table of Contents

- [How it works](#how-it-works)
- [Consensus design](#consensus-design)
- [Reusable patterns](#reusable-patterns)
- [Security & audit](#security--audit)
- [Local lint & test](#local-lint--test)
- [Deployed contract](#deployed-contract-proof-on-explorer)
- [Extension ideas](#extension-ideas)

---

## How it works

1. User registers identity by signing a message with their wallet (EIP-191).
2. User claims a skill at a chosen level (Beginner to Expert).
3. Peers attest the user's skill with reasoning evidence (signed attestations).
4. Each attestation requires the attester to be registered and sign a message binding them to the attestation.
5. Anyone triggers evaluation for a claimed skill.
6. Under consensus, validators evaluate attestation reasoning quality and check anti-sybil/level-gating criteria.
7. If validators agree, skill verification status is stored on-chain.

---

## Consensus design

SkillRegistry uses `run_nondet_unsafe` with the Equivalence Principle:
- **Leader**: evaluates attestation reasoning quality via LLM, checks attest count, unique attestors, and level gating.
- **Validator**: independently re-runs the same evaluation and compares all decision fields: `(verified, verified_level, attest_count, unique_attestors, best_reasoning_score)`.
- Consensus requires agreement on every consequential field, including `verified_level`. Mismatches trigger rotation.
- Error classification: `[EXPECTED]` for deterministic errors (exact match), `[TRANSIENT]` for network errors (agree if both), `[LLM]` for LLM errors (always disagree, force rotation).

---

## Reusable patterns

SkillRegistry establishes patterns that can be reused in other contracts:

- **EIP-191 signature verification**: `_signer_of()` + `_ecrecover()` — pure-Python secp256k1 ecrecover. Drop-in pattern for wallet authentication.
- **Anti-sybil attestation**: unique attestor tracking per skill via `TreeMap` deduplication.
- **Level-gated verification**: attestations must be from peers at matching or higher skill levels.
- **Reasoning quality scoring**: LLM evaluation of attestation reasoning in consensus loop.
- **Consensus via `run_nondet_unsafe`**: Leader + Validator comparing all decision fields `(verified, verified_level, attest_count, unique_attestors, best_reasoning_score)`.

---

## Security & audit

- **Signature verification**: all state-changing actions (register, attest) require EIP-191 signatures verified on-chain via pure-Python secp256k1 ecrecover. `register` requires the recovered signer to equal the transaction sender.
- **AST sandbox**: reasoning quality evaluation uses LLM with structured JSON output only.
- **Registered parties only**: both the attestation target and the attester must be registered users.
- **Consensus counters persisted**: `evaluate_skill` stores the consensus-computed `attest_count` and `unique_attestors` alongside the verification result.
- **Anti-sybil**: unique attester check prevents duplicate attestations per skill.
- **Anti-self-attest**: users cannot attest for themselves.
- **Input validation**: skill names validated (alphanumeric, max 64 chars), reasoning length enforced (20-500 chars), level bounds checked.

---

## Local lint & test

```bash
# Run tests
pytest tests/ -v

# Run linter
genvm-lint check contracts/skill_registry.py
```

21 GenVM direct-mode tests pass. Lint passes. Validate passes. E2E test passes on studionet (register, claim_skill, get_skill). Deployed to studionet.

---

## Deployed contract (proof on explorer)

[![Explore](https://img.shields.io/badge/Explore-Studionet-6366f1?style=for-the-badge)](https://genlayer-explorer.vercel.app)

**Address:** `0xad114Eb8d93D3A089279A3b34F333Afb781bb523`
**Chain:** Studionet (Genlayer Studio Network)
**Deployer:** `0x689759bb926E032EAfb1eE986eD7A98C1496ec1c`
**Tx:** `0x5bba6742b94851d60eb60ac7bcd93297d2b1e34185d7e34b53dc0fe185f44f09`
**Status:** Deployed and tested on studionet. E2E test passes (register, claim_skill, get_skill). 21/21 direct-mode tests pass. All functions operational: register, claim_skill, attest, evaluate_skill, views.

---

## Extension ideas

- Cross-contract skill verification (use verified skills as credentials in other contracts)
- Skill decay over time (requiring re-attestation)
- Skill tiers with different permissions
- Marketplace for skill verification services
