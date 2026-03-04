# 🛡️ PiRC1 Security Policy & Threat Model

## Overview
This document outlines the security architecture and threat mitigation strategies for the **PiRC1-Protocol**, designed for Launchpad-grade security within the Pi Network ecosystem.

## 1. Threat Model & Mitigation
We have identified and addressed the following attack vectors to ensure "Governance-minimized attack surface":

| Threat Vector | Mitigation Strategy | Implementation |
| :--- | :--- | :--- |
| **Sybil Attacks** | KYC-Verified Mainnet User Validation | `SigmoidTierLogic.getSecuredAllocation` |
| **Engagement Farming** | Non-linear Weight Bounding & Normalization | `PEPSchema.validate` |
| **Replay Attacks** | Deterministic HMAC-SHA256 Signatures | `SecurityManager.generatePEPProof` |
| **Key Leakage** | Backend Key Registration & Rotation Model | `SecurityManager.rotateKeys` |

## 2. Deterministic Validation Standards
To move from proposal to ecosystem standard, PiRC1 enforces **Fixed-Point Arithmetic**. This ensures that transition logic (Sigmoid) remains deterministic across all decentralized nodes, preventing floating-point consensus errors.

## 3. Reporting a Vulnerability
Integrity is our core value. If you find a technical flaw, please reach out directly to the Lead Architect (**EslaM-X**) to ensure a coordinated disclosure that protects the Pi Community.

