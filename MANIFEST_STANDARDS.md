# 🏛️ PiRC1: App-Manifest Governance Standards
### Establishing Deterministic Trust & Economic Transparency for the Pi Ecosystem

## 1. Executive Summary
The PiRC1 App-Manifest is a standardized JSON framework designed to expose the **"Economic DNA"** of a dApp. By enforcing a public `pi-manifest.json`, the Pi Ecosystem transitions from "app-level experimentation" to **"Launchpad-grade security"**, ensuring that every Pioneer can verify the integrity of a project before participation.

## 2. The Core Pillars of Trust
To align with the latest ecosystem security requirements, the PiRC1 Manifest now enforces:

* **Deterministic Utility Allocation:** Moving beyond linear models to the **Hardened Sigmoid Standard**, ensuring that utility is weighted through on-chain verifiable primitives.
* **Transparency Dashboard Layer:** A developer-facing trust layer that programmatically exposes Escrow schedules and lock-up periods.
* **Sigmoid Smoothing Algorithm (Fixed-Point):** Eliminating "Whale Manipulation" at tier boundaries through deterministic, non-linear transitions.

## 3. Canonical Schema Implementation (v2.0)
Developers must define their utility weights using the **Minimal Canonical PEP Schema**. This ensures cross-dApp interoperability and allows the Launchpad to verify:

| Metric | Governance Standard | Implementation Logic |
| :--- | :--- | :--- |
| **Integrity Check** | HMAC-SHA256 Signed Proofs | `SecurityManager.ts` |
| **Precision** | 18-Decimal Fixed-Point | `SigmoidTierLogic.ts` |
| **Validation** | Deterministic Key Rotation | `SecurityManager.rotateKeys` |
| **Access Control** | KYC-Verified Mainnet Status | `getSecuredAllocation` |

## 4. Economic Security & The p_floor
The manifest now includes a **Dynamic Price Floor (p_floor)** constraint. This ensures that even at early engagement stages, the ecosystem maintains a "Floor of Value," preventing "Engagement Farming" and protecting the network's economic health.

## 5. Deployment Guidelines
To move this from a proposal to a formal ecosystem standard, developers are required to:
1. Implement the `pi-manifest.json` in the root directory.
2. Sign all utility reports using the **PEP Rotation Model**.
3. Expose a **Transparency Manifest** to the Launchpad’s decentralized dashboard.

---
**"Transparency is the only way forward for a truly decentralized Pi Network."**
*Authored by: EslaM-X | Lead Technical Architect, PiRC1 Standards*
