# Smart Contract & Web3 Security

Geladen, wenn das Projekt Smart-Contract-Code enthält:
- Solidity: `*.sol`, `hardhat.config.*`, `foundry.toml`, `truffle-config.js`, `remappings.txt`
- Vyper: `*.vy`
- Rust: `Cargo.toml` mit Substrate/Solana-Crates, `anchor.toml`
- Move: `*.move`, `Move.toml`
- Cairo: `*.cairo`

Smart Contracts haben extreme Konsequenzen bei Fehlern: Funds einmal weg, sind weg. Mathematik-Bugs sind nicht patchbar (immutable). Audit-Standard ist deutlich höher als bei klassischem Code.

## 1. Reentrancy

**Was:** External Call → Callee ruft denselben Contract erneut auf, bevor State updated → State-Manipulation.

**Klassiker:** The DAO Hack (2016, ~60M USD).

### Detection (Solidity)
```
rg "\.call\{.*value.*\}\(|\.call\.value\(|transfer\(|send\(" *.sol -B 5 -A 5
rg "external" *.sol -B 2 -A 5 | rg "balance|state"
```

### Unsicher
```solidity
function withdraw() public {
    uint amount = balances[msg.sender];
    (bool success, ) = msg.sender.call{value: amount}("");  // ← External call
    require(success);
    balances[msg.sender] = 0;  // ← State-Update NACH dem Call!
}
```

### Sicher (Checks-Effects-Interactions)
```solidity
function withdraw() public nonReentrant {  // OZ ReentrancyGuard
    uint amount = balances[msg.sender];
    balances[msg.sender] = 0;              // Effects first
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);                      // Interactions last
}
```

### Cross-Function Reentrancy
- Funktion A modifiziert State, Funktion B liest State
- Wenn A external call macht und der re-entered nach B, sieht B alten State
- ReentrancyGuard pro Funktion reicht nicht — über ALLE relevanten Funktionen

### Read-Only Reentrancy
- View-Funktion gibt stale State zurück während Mid-Transaction
- Andere Contracts, die diese View-Funktion in ihren Berechnungen nutzen, werden manipuliert
- Mitigation: ReentrancyGuard auch auf View-Funktionen, die kritische State-Variablen lesen

**Schwere:** Critical, fast immer Total-Loss.

---

## 2. Integer Overflow / Underflow

**Vor Solidity 0.8:** kein Overflow-Check, kritische Bugs.
**Solidity 0.8+:** Checked Arithmetic per Default, `unchecked { }` muss explizit sein.

### Detection
```
rg "pragma solidity\s+\^?0\.[0-7]" *.sol  # alte Compiler-Version
rg "unchecked\s*\{" *.sol -A 5  # explizit unchecked = Hot-Spot
rg "SafeMath" *.sol  # 0.8+ braucht das nicht mehr
```

### Edge Cases auch in 0.8+
- Type-Casts: `uint256` → `uint128` overflowt silent ohne Check
- ABI-Encoding: `abi.encodePacked` kann Collisions erzeugen
- Type-Casts zwischen signed/unsigned

---

## 3. Access Control

### Häufige Fehler
- `onlyOwner` fehlt auf privilegierten Funktionen
- `tx.origin` statt `msg.sender` (Phishing-anfällig)
- Initialization-Function ohne `initializer` Modifier (Anyone kann re-initialisieren → Übernahme)
- Default-Visibility `public` statt `internal` für interne Funktionen (vor Solidity 0.7)

### Detection
```
rg "tx\.origin" *.sol  # immer Befund (außer in Tests)
rg "function\s+initialize\b" *.sol -A 3
rg "Ownable|AccessControl" *.sol
rg "onlyOwner|onlyRole" *.sol  # gut wenn vorhanden
```

### Proxy-Pattern-Pitfalls
- UUPS Proxy ohne Authorization in `_authorizeUpgrade()` → jeder kann upgraden
- Transparent Proxy: Function-Selector-Collision möglich
- Storage Layout muss zwischen Implementations gleich bleiben (sonst Storage-Corruption)

---

## 4. Oracle Manipulation

**Was:** Smart Contracts vertrauen externen Price-Feeds. Wenn Oracle manipulierbar → kompletter Hack.

### Klassische Vektoren
- Spot-Price-Oracle aus DEX-Pool (Uniswap V2 ohne TWAP) → Flash-Loan-Manipulation
- Single-Source-Oracle ohne Sanity-Check
- Chainlink ohne `staleCheck` (Round-Data ist `staleCheck`-Pflicht)

### Detection
```
rg "getReserves|pair\.token|swap" *.sol -A 3  # DEX-direkt = Spot-Price = Risk
rg "latestRoundData|latestAnswer" *.sol -A 5  # Chainlink: stale-check da?
```

### Sicher
- Chainlink mit Heartbeat-Check
- TWAP (Time-Weighted Average Price), mindestens 30 min
- Multi-Oracle (Median aus mehreren Sources)
- Sanity-Bounds (Preis-Bewegungs-Caps)

---

## 5. Flash-Loan-Angriffe

**Was:** Innerhalb einer Transaktion riesige Mengen leihen, manipulieren, zurückzahlen.

### Vulnerable Patterns
- Spot-Price Oracle (siehe oben)
- Governance-Voting mit Token-Balance-Snapshot bei Tx-Start
- AMM mit kleinen Liquidity Pools

### Mitigation
- TWAP für Preise
- Voting-Snapshots vor Tx (Compound's Bravo)
- Per-Block-Limits

---

## 6. Frontrunning / MEV

**Was:** Bots beobachten Mempool, ordnen ihre Tx davor (Frontrunning) oder dahinter (Sandwich).

### Vulnerable Patterns
- DEX-Trades ohne `minOutputAmount` (Slippage-Schutz)
- Auctions, die auf Reveal-Phase verzichten
- NFT-Mints mit Whitelist + Public-Functions (Bots schneller)

### Mitigation
- Slippage-Parameter zwingend
- Commit-Reveal-Schema
- Private Mempool (Flashbots Protect)
- Batch-Auctions (CowSwap)

---

## 7. Front-end / Back-end Mismatch

- Signatur-Schema im Contract vs. Off-Chain-Signing-Logic
- Replay-Schutz: `nonce` + `chainId` + `expiration`
- EIP-712 Structured Data Signing

### Detection
```
rg "ecrecover|ECDSA\.recover" *.sol -A 5
rg "_signatures\[|usedNonces\[" *.sol  # Replay-Schutz vorhanden?
```

---

## 8. Token-Standards-Pitfalls

### ERC-20
- `transferFrom` ohne `allowance`-Check
- "Fee-on-Transfer"-Tokens (USDT-Style): empfangene Menge weniger als gesendete
- Rebase-Tokens: Balance ändert sich ohne Tx (Compound mit aTokens-Style)

### ERC-721 / 1155
- `_mint` ohne Zugriffsschutz
- `safeMint` vs `_mint` (safeMint prüft auf Empfänger-Receiver-Implementation)
- Reentrancy in `onERC721Received`

### ERC-4626 (Vaults)
- Inflation-Attack via initiale Deposit → manipuliert Share-Price
- Verlust-Akkumulation bei Rounding-Errors

---

## 9. DoS-Vektoren

### Gas-Limit-DoS
- Loops über User-controlled Arrays
- `payable` Empfänger reverten → blockiert Tx (Pull-over-Push-Pattern)

### Detection
```
rg "for\s*\(.*\.length" *.sol -B 2 -A 5
rg "while\s*\(" *.sol -A 5
```

### Unsicher
```solidity
function distribute() public {
    for (uint i = 0; i < winners.length; i++) {
        payable(winners[i]).transfer(prize);  // einer revertet → alle blockiert
    }
}
```

### Sicher (Pull-over-Push)
```solidity
mapping(address => uint) public pendingWithdrawals;

function distribute() public {
    for (uint i = 0; i < winners.length; i++) {
        pendingWithdrawals[winners[i]] += prize;  // nur Buchführung
    }
}

function withdraw() public {
    uint amount = pendingWithdrawals[msg.sender];
    pendingWithdrawals[msg.sender] = 0;
    payable(msg.sender).transfer(amount);
}
```

---

## 10. Random Number Generation

**Niemals on-chain `block.timestamp`, `blockhash`, `block.difficulty` allein nutzen** — vorhersagbar / manipulierbar (Miner kann blockhash beeinflussen).

### Detection
```
rg "block\.(timestamp|difficulty|number|coinbase)|blockhash\(" *.sol -B 2 -A 3
```

### Sicher
- Chainlink VRF (Verifiable Random Function)
- Commit-Reveal + Multi-Party
- RANDAO (post-Merge)

---

## 11. Signature Replay

### Cross-Chain Replay
- Signed Message für Chain A funktioniert auch auf Chain B → `chainId` in Signatur einbeziehen

### Cross-Contract Replay
- Signed Message für Contract A funktioniert in Contract B → `address(this)` einbeziehen

### Replay innerhalb eines Contracts
- Nonce nicht verbraucht → einmalige Aktionen mehrfach
- Mitigation: `mapping(bytes32 => bool) usedHashes`

---

## 12. Storage-Pattern-Pitfalls

### Storage Collision
- Uninitialized Storage Pointer
- Proxy + Implementation mit unterschiedlichem Storage-Layout
- `delegatecall` mit unkontrolliertem Target

### Detection
```
rg "delegatecall" *.sol -B 2 -A 5
rg "assembly\s*\{" *.sol -A 10  # Inline-Assembly = Hochrisiko
```

---

## 13. Tooling-Empfehlungen (im Bericht erwähnen)

### Statisch
- **Slither** (Trail of Bits) — der Standard
- **Mythril** — symbolic execution
- **Securify v2** — formal
- **Aderyn** (Cyfrin) — neu, Rust-basiert
- **4naly3er** — Gas + Sec

### Dynamisch
- **Echidna** — Fuzzing (Trail of Bits)
- **Foundry** mit `forge fuzz` und Invariant-Testing
- **Manticore** — Symbolic execution
- **Halmos** (a16z) — formal symbolic

### Audit-Standards
- SCSVS (Smart Contract Security Verification Standard)
- ConsenSys Best Practices
- OpenZeppelin Defender für Monitoring + Incident Response

---

## 14. Non-EVM-Chains

### Solana (Rust + Anchor)
- Missing signer checks (`Signer<'info>`)
- Account ownership/discriminator checks
- PDA (Program Derived Address) collisions
- Cross-Program-Invocation (CPI) ohne authority check
- Sysvar-misuse (Clock-manipulation)

### Cosmos / CosmWasm
- Gas-Metering pro Message
- IBC-Channel-Verification
- Migration-Function Access-Control

### Move (Aptos, Sui)
- Resource-Semantics (kein Duplicate, no Drop ohne explicit)
- Abilities (`copy`, `drop`, `store`, `key`)
- Capability-Pattern für Privileged Operations

---

## 15. Front-end-spezifisch (Web3 dApp)

- Private Keys NIEMALS in Web-Frontend
- `eth_sign` vs `personal_sign` vs `eth_signTypedData` — letzteres bevorzugen
- Address-Validation (Checksumming, EIP-55)
- Token-Approval-Phishing: User signiert `approve(maxUint, attacker)` → alle Tokens weg
- WalletConnect / Web3Modal: korrekte Chain-ID prüfen

---

## Mappings

- SWC Registry (Smart Contract Weakness Classification) — sehr ausführlich
- OWASP Smart Contract Top 10 (2025 in Vorbereitung)
- SCSVS (Smart Contract Security Verification Standard)
- DASP Top 10 (älter, dennoch nützlich)
- CWE: CWE-682 (Incorrect Calculation), CWE-841 (Improper Workflow), CWE-345 (Insufficient Verification)

## Compliance / Regulatorisches

- MiCA (EU) für Crypto-Asset-Service-Provider
- Sanctions-Screening für Adressen (OFAC)
- KYC/AML bei zentralisierten Komponenten

---

## Wichtiger Hinweis

Smart-Contract-Audits sollten IMMER zusätzlich von spezialisierten Auditoren (Trail of Bits, OpenZeppelin, ConsenSys Diligence, etc.) durchgeführt werden. Dieser Skill kann erste Befunde liefern, ersetzt aber keinen professionellen Audit. Die Konsequenzen von Smart-Contract-Bugs sind irreversibel und finanziell maximal.
