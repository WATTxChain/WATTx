# WATTx Core

[![Build Status](https://github.com/WATTxChain/WATTx/actions/workflows/ci.yml/badge.svg)](https://github.com/WATTxChain/WATTx/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/WATTxChain/WATTx)](https://github.com/WATTxChain/WATTx/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

WATTx is a hybrid Proof-of-Work/Proof-of-Stake blockchain featuring 7-algorithm merged mining (X25X), full EVM smart contract support, and full-chain privacy (FCMP+). Built on QTUM's foundation with significant enhancements for mining flexibility, cross-chain interoperability, and user privacy.

**Website:** [wattxchain.org](https://wattxchain.org) · **Explorer:** [explorer.wattxchain.org](https://explorer.wattxchain.org)

---

## Key Features

### Multi-Algorithm Mining (X25X)
Mine WATTx using any of 7 supported algorithms simultaneously via AuxPoW merged mining:

| # | Algorithm   | Target Hardware                        | Merged Coins (examples)      |
|---|-------------|----------------------------------------|------------------------------|
| 1 | SHA256d     | Bitcoin ASICs (Antminer S-series)      | BTC, BCH, BSV, NMC, DOGE     |
| 2 | Scrypt      | Litecoin miners (Antminer L-series)    | LTC, DOGE, FLO, DGB          |
| 3 | Ethash      | GPU miners (ETH-era cards)             | ETC, CLO, EGEM, EXP          |
| 4 | RandomX     | CPU miners (Monero ecosystem)          | XMR, WOW, OXEN, ARQ          |
| 5 | Equihash    | Zcash miners (miniZ, EWBF)             | ZEC, ZEN, BTCZ, KMD, ARRR    |
| 6 | X11         | Dash ASICs (Antminer D-series)         | DASH, DGB-X11, HTH, CANN     |
| 7 | kHeavyHash  | Kaspa miners (lolMiner, BzMiner)       | KAS, KLS, PYI, SPR           |

### Privacy Features (FCMP+)
- **Full-Chain Membership Proofs** — Monero-style ring signatures activating at block 210,000
- **Shielded Commitments** — Merkle tree commitments on the WATTx EVM
- **Stealth Addresses** — One-time addresses for unlinkable transactions
- **Cross-Chain Privacy Pools** — Anonymous cross-chain transfers with Monero-style privacy
- **P2P Encrypted Messaging** — End-to-end encrypted wallet-to-wallet chat

### Smart Contracts
- Full EVM compatibility (Solidity)
- Built-in contract compiler
- Contract verification via block explorer

### Hybrid Consensus
- **PoW Mining** — 7-algorithm X25X, 5 WTX per block
- **PoS Staking** — Dynamic stake maturity that halves with each reward halving, 5 WTX per block
- **AuxPoW Merged Mining** — Earn WTX while mining BTC, LTC, XMR, KAS, ETC, ZEC, DASH, and more

### Cross-Chain Bridge
- LayerZero OFT token bridge
- Bridges between WATTx, Ethereum, BSC, Polygon

---

## Network Parameters

| Parameter | Mainnet | Testnet | Regtest |
|-----------|---------|---------|---------|
| Block Time | 2 minutes | 2 minutes | instant |
| Block Reward | 5 WTX (PoW) + 5 WTX (PoS) | same | same |
| Max Supply | ~21,000,000 WTX | — | — |
| Halving Interval | 1,051,200 blocks (~4 years) | same | 200 blocks |
| Base Stake Maturity | 500 blocks | 500 blocks | 20 blocks |
| Stake Maturity Floor | 10 blocks | 10 blocks | 2 blocks |
| X25X Activation | Block 100,000 | Block 1,000 | Block 1 |
| FCMP+ Activation | Block 210,000 | Block 1,000 | Block 1 |
| P2P Port | 18888 | 13888 | 18444 |
| RPC Port | 18889 | 13889 | 18443 |

---

## Quick Start

### Download a Release

Pre-built binaries for Linux and Windows are available on the [Releases](https://github.com/WATTxChain/WATTx/releases) page.

```bash
# Linux
tar -xzf wattx-0.1.7-linux64.tar.gz
cd wattx-0.1.7-linux64

# Start daemon
./wattxd -daemon

# Check sync status
./wattx-cli getblockchaininfo
```

### Build from Source

**Prerequisites:** CMake 3.18+, GCC/Clang, Boost, OpenSSL, Berkeley DB 4.8, Qt5 (for GUI)

```bash
git clone https://github.com/WATTxChain/WATTx.git
cd WATTx
cmake -B build -DBUILD_GUI=ON
cmake --build build -j$(nproc)
```

Binaries will be in `build/bin/`:
- `wattxd` — daemon
- `wattx-cli` — CLI
- `wattx-qt` — GUI wallet
- `wattx-wallet` — wallet utility

### Running a Node

```bash
# Start daemon
./wattxd -daemon

# Create wallet
./wattx-cli createwallet "mywallet"

# Get a receive address
./wattx-cli getnewaddress

# Check sync status
./wattx-cli getblockchaininfo
```

### Mining (CLI)

```bash
# Check mining info
./wattx-cli getmininginfo

# Get network hashrate
./wattx-cli getnetworkhashps

# Generate blocks (regtest only)
./wattx-cli generatetoaddress 100 "your_address"
```

### Mining (GUI)

1. Open `wattx-qt`
2. Go to **Stake > Mining**
3. Select mining mode (Solo / Pool)
4. Choose RandomX mode (Light 256 MB / Full 2 GB)
5. Set thread count
6. Click **Start Miner**

### Pool Mining (AuxPoW Stratum)

Connect your existing mining hardware to earn WTX while mining your primary coin:

| Algorithm | Stratum Port | Hardware |
|-----------|-------------|----------|
| SHA256d | 3333 | Antminer S-series |
| Scrypt | 3334 | Antminer L-series |
| Ethash | 3335 | GPU (ETH-era) |
| RandomX | 3336 | CPU |
| Equihash | 3337 | miniZ / EWBF |
| X11 | 3338 | Antminer D-series |
| kHeavyHash | 3339 | lolMiner / BzMiner |

```bash
# SHA256d (BTC miners)
cgminer --url stratum+tcp://pool.wattxchain.org:3333 --user YOUR_BTC_ADDRESS.worker --pass x

# RandomX (CPU / XMR miners)
xmrig -o pool.wattxchain.org:3336 -u YOUR_XMR_ADDRESS -p worker

# kHeavyHash (Kaspa miners)
lolMiner --algo KASPA --pool pool.wattxchain.org:3339 --user YOUR_KAS_ADDRESS.worker
```

### Staking

```bash
# Check staking status
./wattx-cli getstakinginfo

# Enable staking (wallet must be unlocked)
./wattx-cli walletpassphrase "yourpassphrase" 99999999 true
```

---

## Development

See [DEVELOPMENT_PROGRESS.md](DEVELOPMENT_PROGRESS.md) for implementation status of all features.

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Security

See [SECURITY.md](SECURITY.md) for responsible disclosure policy.

---

## Repository Structure

```
WATTx/
├── src/
│   ├── crypto/x25x/     # X25X 7-algorithm mining framework
│   ├── consensus/        # PoW/PoS consensus rules
│   ├── rpc/              # JSON-RPC 2.0 API
│   └── wallet/           # HD wallet, staking
├── contracts/            # EVM smart contracts (privacy, bridge, mining-game)
├── explorer/             # WATTx block explorer
├── wattx-pool/           # AuxPoW pool server
├── ci/                   # CI scripts
└── doc/                  # Documentation
```

---

## License

WATTx Core is released under the [MIT License](COPYING).
