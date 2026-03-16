# Zero Day Disclosures

Independent smart contract security research. Vulnerabilities detected by a novel analysis algorithm.

---

## About

I developed a smart contract analysis algorithm that detects malicious patterns in deployed contract bytecode — including obfuscated threats that evade existing commercial security scanners.

The approach is fundamentally different from pattern-matching, symbolic execution, or machine-learning-based tools. It requires **zero training data**, works across any EVM chain, and catches obfuscation techniques specifically designed to bypass conventional scanners.

This is a personal research project exploring new methods for automated vulnerability detection in smart contracts.

---

## Disclosures

| Date       | Finding                                                                     | Chain    | Severity | Status |
| ---------- | --------------------------------------------------------------------------- | -------- | -------- | ------ |
| 2026-03-16 | [RAY Token Honeypot Backdoor](disclosures/2026-03-16-ray-token-honeypot.md) | Ethereum | Critical | Active |

---

## Detection Capability

| What the algorithm detects        | What it does not detect    |
| --------------------------------- | -------------------------- |
| Obfuscated external calls         | Business logic errors      |
| Hidden kill switches / honeypots  | Oracle manipulation        |
| Injected code in forked contracts | Off-chain governance risks |
| Arithmetic anomalies              | Missing access controls    |
| Reentrancy-prone patterns         | Social engineering         |
| XOR/assembly obfuscation          | Centralization risks       |

The algorithm is strongest against **adversaries who use obfuscation** — the same techniques that defeat conventional scanners make threats more visible to this analysis.

---

## Scanner Comparison (RAY Token Finding)

![Scanner Comparison](evidence/ray-scanner-comparison.png)

| Scanner          | Verdict on RAY Token      | Detected Backdoor? |
| ---------------- | ------------------------- | ------------------ |
| SolidityScan     | 95.43/100 "GREAT"         | No                 |
| GoPlus Security  | "No security risks found" | No                 |
| Token Sniffer    | 50/100                    | No                 |
| BubbleMaps       | Data unavailable          | No                 |
| **My algorithm** | **Anomalous**             | **Yes**            |

---

## Responsible Disclosure

All findings are disclosed publicly only after reasonable attempts to notify affected platforms. I do not exploit vulnerabilities. The goal is to protect users from malicious contracts.

If you are a security researcher, scanner operator, or platform affected by any disclosure here, feel free to reach out.

---

## Contact

https://www.linkedin.com/in/aditya01933/

---

## Legal

This repository contains security research published in the public interest. All information is derived from publicly available blockchain data and verified smart contract source code on Etherscan. No private systems were accessed. No exploits were performed.
