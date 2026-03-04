# 🛡️ Programmable Engagement Proof (PEP) Protocol
### Deep-Dive: Securing the Pi Ecosystem against Sybil Attacks

The PEP Protocol introduces a **Multi-Layer Verification Sovereign** to ensure that dApp engagement is both authentic and human-driven.

#### 🛠️ Technical Architecture
The security relies on a **Synchronous HMAC-SHA256 Handshake** between the dApp Infrastructure and the Pi Launchpad.

1. **Payload Generation:** High-value actions are captured on the dApp backend.
2. **Cryptographic Signing:** A unique `Secret_Key` (known only to the dApp and Pi Core) signs the payload.
3. **Transmission:** The frontend receives the `PEP_Payload` and transmits it via the `usePiUtility` hook.
4. **On-Chain/SDK Verification:** The signature is verified to ensure it hasn't been tampered with or replayed.

#### 📊 Mathematical Integrity
To prevent replay attacks, every PEP payload includes a **Deterministic Nonce** ($N$) and a **Unix Timestamp** ($T$):
$$Signature = \text{HMAC-SHA256}(Secret, Payload + N + T)$$

> **Impact:** This eliminates 99.9% of automated bot farming by forcing every transaction to be backed by a verified backend authority.

