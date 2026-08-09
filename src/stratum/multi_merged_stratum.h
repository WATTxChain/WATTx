// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_STRATUM_MULTI_MERGED_STRATUM_H
#define WATTX_STRATUM_MULTI_MERGED_STRATUM_H

#include <stratum/parent_chain.h>
#include <stratum/mining_rewards.h>
#include <anchor/evm_anchor.h>
#include <interfaces/mining.h>

#include <array>
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <map>
#include <unordered_map>
#include <vector>

namespace merged_stratum {

/**
 * DECENTRALIZATION CONSTANTS
 *
 * These constants enforce hashrate decentralization across chains:
 * - No single miner can dominate any chain's hashrate
 * - Miners who diversify get better WATTx luck
 */

// Maximum percentage of network hashrate a miner can contribute to any single chain
// Shares beyond this cap don't count toward WATTx scoring (but still valid for parent chain)
static constexpr double MAX_NETHASH_PERCENT_PER_CHAIN = 50.0;

// Luck multiplier range for diversification bonus
// Concentrated miners (1 chain): luck = MIN_LUCK_MULTIPLIER (harder to find WATTx blocks)
// Diversified miners (many chains): luck = MAX_LUCK_MULTIPLIER (easier to find WATTx blocks)
static constexpr double MIN_LUCK_MULTIPLIER = 0.5;   // 50% harder for concentrated miners
static constexpr double MAX_LUCK_MULTIPLIER = 3.0;   // 3x easier for highly diversified miners

/**
 * Per-coin hashrate tracking for share calculations
 *
 * INCENTIVE MECHANISM:
 * Miners earn more points for contributing a larger % of a chain's nethash.
 * This encourages miners to support chains that NEED hashrate security.
 *
 * Example:
 *   - Mining 5% of SmallCoin's nethash = 5.0 points
 *   - Mining 0.001% of Bitcoin's nethash = 0.001 points
 *
 * This incentivizes spreading hashrate to chains that need it most.
 */
struct CoinHashrateStats {
    std::string coin_name;
    ParentChainAlgo algo;

    // Network stats (from parent chain daemon)
    uint64_t network_hashrate{0};       // Network total hashrate
    uint64_t network_difficulty{0};     // Current network difficulty
    uint64_t block_reward{0};           // Block reward in satoshis (for future use)

    // Pool stats
    uint64_t pool_hashrate{0};          // Our pool's hashrate on this coin
    uint64_t pool_shares{0};            // Total shares submitted

    // Per-miner tracking: miner_address -> their RAW (uncapped) hashrate on this
    // coin. Raw so the 50% cap + excess-to-pool split can be computed at scoring
    // time; the per-share path no longer drops shares above 50%.
    std::unordered_map<std::string, uint64_t> miner_hashrates;

    // Per-source-IP tracking: ip -> (wallet -> raw hashrate) on this coin. Used
    // for the anti-sybil IP aggregate cap (one IP splitting >50% across several
    // wallets to dodge the per-wallet cap). Empty ip ("") means unknown/untracked.
    std::unordered_map<std::string, std::unordered_map<std::string, uint64_t>> ip_wallet_hashrates;

    // Calculated metrics
    double pool_nethash_percent{0.0};   // pool_hashrate / network_hashrate * 100

    int64_t last_update{0};
};

/**
 * Miner scoring across all chains
 * Score = sum of (miner_hashrate / network_hashrate) for each chain
 *
 * DECENTRALIZATION FEATURES:
 * 1. 50% Cap: Contributions >50% on any chain don't count toward score
 * 2. Luck Bonus: Diversified miners get better WATTx block-finding luck
 */
struct MinerScore {
    std::string wtx_address;

    // Per-chain contribution percentages (raw, before cap)
    std::unordered_map<std::string, double> chain_contributions_raw;  // coin -> % of nethash (uncapped)

    // Per-chain contribution percentages (capped at MAX_NETHASH_PERCENT_PER_CHAIN)
    std::unordered_map<std::string, double> chain_contributions;  // coin -> % of nethash (capped)

    // Total score (sum of CAPPED chain contributions)
    double total_score{0.0};

    // Normalized share of block reward
    double reward_share{0.0};

    // Diversification luck multiplier (higher = easier to find WATTx blocks)
    // Based on how spread out the miner's hashrate is across chains
    // Range: [MIN_LUCK_MULTIPLIER, MAX_LUCK_MULTIPLIER]
    double luck_multiplier{1.0};

    // Number of chains being mined (for diversification calculation)
    size_t chains_mined{0};

    // Concentration index (Herfindahl-Hirschman Index, 0-1)
    // Lower = more diversified, Higher = more concentrated
    double concentration_index{1.0};
};

/**
 * Configuration for multi-chain merged mining server
 */
struct MultiMergedConfig {
    // Network settings
    std::string bind_address = "0.0.0.0";
    uint16_t base_port = 3337;           // Each algo gets its own port: base_port + algo_index
    int max_clients_per_algo = 500;

    // WATTx settings
    std::string wattx_wallet_address;

    // Parent chain configurations (any coin, any algorithm - fully flexible)
    std::vector<ParentChainConfig> parent_chains;

    // Pool settings
    int job_timeout_seconds = 60;
    uint64_t share_difficulty = 10000;
    // Optional explicit share target as an nBits compact value. When nonzero it
    // overrides share_difficulty for the share-acceptance gate — mainly a testing
    // knob so regtest can use an easy target (e.g. 0x1f0fffff) instead of the
    // diff-1 floor of DifficultyToTarget(). Zero = derive target from share_difficulty.
    uint32_t share_nbits = 0;
    double pool_fee_percent = 0.1;   // 0.1% fee for WATTx Mining Game pools

    // Decentralization / anti-cheat caps (see ComputeRewardSplit). A miner's
    // reward is credited on at most `wallet_nethash_cap_percent` of any one
    // chain's nethash; the confiscated excess is paid to `excess_redirect_address`
    // (the pool) rather than redistributed to other miners. The IP aggregate cap
    // catches a single source IP splitting >cap across several wallets to dodge
    // the per-wallet cap. Both configurable; 0 disables that cap.
    double wallet_nethash_cap_percent = 50.0;  // per-wallet per-chain cap
    double ip_nethash_cap_percent     = 50.0;  // per-IP aggregate per-chain cap (0 = off)
    // WTX address that receives the confiscated >cap excess. Empty => use
    // wattx_wallet_address (the pool's own WTX wallet).
    std::string excess_redirect_address;

    // Hashrate tracking settings
    int hashrate_update_interval = 60;   // Update network stats every N seconds
    bool normalize_cross_algo = true;    // Normalize shares across different algorithms
};

/**
 * Job for a specific algorithm (may include multiple parent chains)
 */
struct MultiAlgoJob {
    std::string job_id;
    ParentChainAlgo algo;

    // Parent chain data (primary chain for this algo)
    std::string hashing_blob;
    std::string full_template;
    std::string seed_hash;
    uint64_t parent_height{0};
    uint64_t parent_difficulty{0};
    uint256 parent_target;
    ParentCoinbaseData coinbase_data;

    // WATTx data
    std::shared_ptr<interfaces::BlockTemplate> wattx_template;
    uint64_t wattx_height{0};
    uint32_t wattx_bits{0};
    uint256 wattx_target;

    // Payout-split coinbase: the WATTx block reward divided among contributing miners
    // by reward_share, frozen at job creation. Committed to by aux_merkle_root and
    // submitted verbatim. Null => fall back to the template's default coinbase.
    CTransactionRef payout_coinbase;

    // Merge mining commitment
    uint256 aux_merkle_root;
    std::vector<uint8_t> merge_mining_tag;

    // EVM anchor
    evm_anchor::EVMAnchorData evm_anchor;
    std::vector<uint8_t> evm_anchor_tag;

    int64_t created_at{0};
};

/**
 * Connected miner for multi-algo mining
 */
// Stratum wire protocol used by a connected miner
enum class StratumProtocol {
    XMRIG,      // login / submit / getjob  (Monero-style, all algos default)
    BTC,        // mining.subscribe / mining.authorize / mining.submit
    ETHASH,     // eth_submitLogin / eth_getWork / eth_submitWork
    ZCASH,      // NiceHash equihash: subscribe(nonce1)/set_target/notify/submit(nonce2,soln)
};

struct MultiMergedClient {
    int socket_fd{-1};
    std::string session_id;
    std::string worker_name;
    std::string ip_address;   // peer IP (for the anti-sybil IP aggregate cap)
    ParentChainAlgo algo;
    StratumProtocol protocol{StratumProtocol::XMRIG};  // detected at subscribe/login time

    // Per-miner extranonce for BTC stratum (4 bytes hex)
    std::string extranonce1;

    // Addresses for each chain
    std::unordered_map<std::string, std::string> chain_addresses;  // chain_name -> address
    std::string wtx_address;

    bool authorized{false};
    bool subscribed{false};

    // Statistics per chain
    std::unordered_map<std::string, uint64_t> shares_accepted;
    std::unordered_map<std::string, uint64_t> blocks_found;

    // Rolling share window for hashrate estimation: ten one-minute buckets per
    // chain (a true 600s window). shares_accepted above is the LIFETIME total,
    // for the dashboard only — reward scoring must never use it: a counter that
    // never expires divided by a fixed 600s window inflates with uptime, so two
    // miners with identical hashrate would earn in proportion to how long they
    // have been connected rather than the work they are doing.
    struct ShareWindow {
        std::array<int64_t, 10> minute{};   // epoch-minute stamp of each bucket
        std::array<uint64_t, 10> count{};
    };
    std::unordered_map<std::string, ShareWindow> share_windows;  // chain -> window
    uint64_t shares_rejected{0};
    uint64_t wtx_blocks_found{0};

    int64_t connect_time{0};
    int64_t last_activity{0};
    std::string recv_buffer;
};

/**
 * Multi-Chain Merged Mining Stratum Server
 *
 * Supports mining WATTx via multiple parent chain algorithms:
 * - SHA256d (Bitcoin, BCH)
 * - Scrypt (Litecoin, Dogecoin)
 * - RandomX (Monero)
 * - Equihash (Zcash, Horizen)
 * - X11 (Dash)
 * - kHeavyHash (Kaspa)
 *
 * Each algorithm has its own stratum port, allowing miners to connect
 * based on their hardware capabilities.
 */

// ---------------------------------------------------------------------------
// Reward split (pure, deterministic, unit-tested — see merged_reward_tests.cpp)
// ---------------------------------------------------------------------------
// One parent chain's raw contribution data for a reward computation.
struct ChainRewardInput {
    uint64_t network_hashrate{0};  // 0 => fall back to pool_hashrate for the denominator
    uint64_t pool_hashrate{0};
    // ip -> (wallet -> raw accumulated hashrate). ip "" means unknown/untracked.
    std::unordered_map<std::string, std::unordered_map<std::string, uint64_t>> ip_wallet_hashrates;
};

struct RewardSplitResult {
    std::unordered_map<std::string, double> wallet_share;       // wallet -> reward fraction [0,1]
    double pool_share{0.0};                                     // confiscated-excess fraction [0,1]
    std::unordered_map<std::string, double> wallet_scored_pct;  // wallet -> summed scored% (for luck/logging)
    // Invariant on success: sum(wallet_share) + pool_share == 1.0 (within fp epsilon),
    // and every value is finite and in [0,1]. Empty (all zero) when there is no
    // measurable contribution.
};

// Compute each wallet's share of the WTX block reward and the pool's
// confiscated-excess share, given per-chain raw contributions.
//
// Model (per the decentralization spec):
//   * Denominator = the RAW total contribution (sum over every wallet & chain of
//     wallet_raw%_on_chain). Dividing by RAW (not capped) is what sends excess to
//     the pool instead of inflating other miners' shares.
//   * Each wallet is credited min(raw%, wallet_cap) per chain (per-wallet cap).
//   * If ip_cap > 0, wallets sharing one IP are jointly capped: per chain, if the
//     IP's summed credited% exceeds ip_cap, each member is scaled down pro-rata
//     (anti-sybil).
//   * pool_share = 1 - sum(wallet_share) = the total confiscated excess fraction.
//
// wallet_cap_pct / ip_cap_pct are percentages (e.g. 50.0). ip_cap_pct <= 0
// disables the IP cap. Deterministic: identical inputs always yield identical
// output (required — the payout coinbase is frozen into the AuxPoW job).
RewardSplitResult ComputeRewardSplit(const std::vector<ChainRewardInput>& chains,
                                     double wallet_cap_pct, double ip_cap_pct);

class MultiMergedStratumServer {
public:
    MultiMergedStratumServer();
    ~MultiMergedStratumServer();

    /**
     * Start the multi-chain merged mining server
     */
    bool Start(const MultiMergedConfig& config, interfaces::Mining* wattxMining);

    /**
     * Stop the server
     */
    void Stop();

    /**
     * Check if server is running
     */
    bool IsRunning() const { return m_running.load(); }

    /**
     * Get statistics
     */
    size_t GetTotalClientCount() const;
    size_t GetClientCount(ParentChainAlgo algo) const;
    uint64_t GetTotalSharesAccepted(const std::string& chain) const;
    uint64_t GetTotalBlocksFound(const std::string& chain) const;
    uint64_t GetWtxBlocksFound() const { return m_wtx_blocks_found.load(); }

    /**
     * Get port for specific algorithm
     */
    uint16_t GetPort(ParentChainAlgo algo) const;

    /**
     * Rich dashboard stats for the merged mining app / RPC
     */
    struct AlgoStats {
        std::string algo;         // "sha256d", "randomx", etc.
        std::string chain_name;   // "bitcoin", "monero", etc.
        uint16_t port{0};
        bool daemon_reachable{false};
        size_t miners_connected{0};
        uint64_t shares_accepted{0};
        uint64_t shares_rejected{0};
        uint64_t parent_blocks_found{0};
        std::string daemon_host;
        int daemon_port{0};
        std::string wallet_address;
    };

    struct MinerStats {
        int client_id{0};
        std::string login;
        std::string wtx_address;
        std::string algo;
        uint64_t shares_accepted{0};
        uint64_t shares_rejected{0};
        uint64_t wtx_blocks_found{0};
        int64_t connected_since{0};
        int64_t last_activity{0};
    };

    struct Dashboard {
        bool running{false};
        uint64_t wtx_blocks_found{0};
        int64_t started_at{0};
        std::vector<AlgoStats> algos;
        std::vector<MinerStats> miners;
    };

    Dashboard GetDashboard() const;

    /**
     * Update parent chain config at runtime (reconnect on next job cycle)
     */
    bool UpdateParentChainConfig(const std::string& chain_name, const ParentChainConfig& new_config);

    /**
     * Notify of new blocks
     */
    void NotifyNewParentBlock(const std::string& chain_name);
    void NotifyNewWattxBlock();

private:
    // Server threads (one accept thread per algorithm)
    void AcceptThread(ParentChainAlgo algo);
    void ClientThread(int client_id);
    void JobThread(ParentChainAlgo algo);
    void ParentPollerThread(const std::string& chain_name);

    // Protocol handlers
    void HandleMessage(int client_id, const std::string& message);
    // XMRig-style (Monero) protocol
    void HandleLogin(int client_id, const std::string& id, const std::vector<std::string>& params);
    void HandleSubmit(int client_id, const std::string& id, const std::vector<std::string>& params);
    void HandleGetJob(int client_id, const std::string& id);
    // Bitcoin stratum protocol
    void HandleSubscribe(int client_id, const std::string& id, const std::vector<std::string>& params);
    void HandleAuthorize(int client_id, const std::string& id, const std::vector<std::string>& params);
    void HandleBtcSubmit(int client_id, const std::string& id, const std::vector<std::string>& params);
    // Ethash protocol
    void HandleEthSubmitLogin(int client_id, const std::string& id, const std::vector<std::string>& params);
    void HandleEthGetWork(int client_id, const std::string& id);
    void HandleEthSubmitWork(int client_id, const std::string& id, const std::vector<std::string>& params);
    // Zcash (NiceHash equihash) protocol — shares mining.subscribe/authorize/submit
    // method names with BTC, routed by algo==EQUIHASH.
    void HandleZcashSubscribe(int client_id, const std::string& id, const std::vector<std::string>& params);
    void HandleZcashAuthorize(int client_id, const std::string& id, const std::vector<std::string>& params);
    void HandleZcashSubmit(int client_id, const std::string& id, const std::vector<std::string>& params);
    void SendZcashTarget(int client_id, const std::string& chain_name);
    void SendZcashNotify(int client_id, const MultiAlgoJob& job, bool clean_jobs);
    // Shared helpers
    void SendMiningNotify(int client_id, const MultiAlgoJob& job, bool clean_jobs = false);
    void SendSetDifficulty(int client_id, double diff);
    std::string BuildBtcNotifyParams(const MultiAlgoJob& job, bool clean_jobs) const;
    static std::string MakeExtranonce1(int client_id);
    // Algo of the port a client connected to (set at accept). Returns a
    // sentinel-safe value if the client is gone.
    ParentChainAlgo ClientAlgo(int client_id);

    // Job management
    void CreateJob(ParentChainAlgo algo);

    // Per-chain share gate resolution: a parent chain's nonzero
    // share_nbits/share_difficulty override the pool-global config values.
    uint32_t EffectiveShareNbits(const std::string& chain_name) const;
    uint64_t EffectiveShareDifficulty(const std::string& chain_name) const;
    uint256 EffectiveShareTarget(const std::string& chain_name);
    double EffectiveShareDiffNumber(const std::string& chain_name) const;
    // Share target advertised in XMRig-protocol job pushes for the job's algo
    // (falls back to the parent block target if the algo has no primary chain).
    uint256 XmrigJobTarget(const MultiAlgoJob& job);
    std::string XmrigTargetHex(const MultiAlgoJob& job);
    // Build the payout-split WATTx coinbase: divides the block reward among the
    // currently-scored miners by reward_share (value-conserving). Returns the
    // template's default coinbase if no miners are scored yet.
    CTransactionRef BuildPayoutCoinbase(const std::shared_ptr<interfaces::BlockTemplate>& tmpl);
    void BroadcastJob(ParentChainAlgo algo, const MultiAlgoJob& job);
    // proto_extra: protocol-specific payload for CreateAuxPow — Bitcoin stratum
    // passes "extranonce8_hex:ntime8_hex" so the proof rebuilds the miner's exact
    // coinbase/header; XMRig submits leave it empty.
    bool ValidateShare(int client_id, const std::string& job_id,
                       const std::string& nonce, const std::string& result,
                       const std::string& proto_extra = "");

    // Network helpers
    void SendToClient(int client_id, const std::string& message);
    void SendResult(int client_id, const std::string& id, const std::string& result);
    void SendError(int client_id, const std::string& id, int code, const std::string& msg);
    void SendJob(int client_id, const MultiAlgoJob& job,
                 StratumProtocol proto = StratumProtocol::XMRIG);
    void DisconnectClient(int client_id);

    // Utility
    std::string GenerateJobId();
    std::string GenerateSessionId();

    // Configuration
    MultiMergedConfig m_config;
    interfaces::Mining* m_wattx_mining{nullptr};

    // Parent chain handlers
    std::unordered_map<std::string, std::unique_ptr<IParentChainHandler>> m_parent_handlers;
    std::unordered_map<ParentChainAlgo, std::string> m_algo_primary_chain;  // algo -> primary chain name

    // Server state
    std::atomic<bool> m_running{false};
    std::atomic<int64_t> m_started_at{0};
    std::unordered_map<ParentChainAlgo, int> m_listen_sockets;
    // Actual bound port per algo, in enum order. m_listen_sockets iterates in
    // arbitrary (hash) order, so ports must never be derived from its position.
    std::map<ParentChainAlgo, uint16_t> m_algo_ports;

    // Threads
    std::vector<std::thread> m_accept_threads;
    std::vector<std::thread> m_job_threads;
    std::vector<std::thread> m_poller_threads;
    std::vector<std::thread> m_client_threads;

    // Clients
    mutable std::mutex m_clients_mutex;
    std::unordered_map<int, std::unique_ptr<MultiMergedClient>> m_clients;
    int m_next_client_id{0};

    // Jobs (per algorithm)
    mutable std::mutex m_jobs_mutex;
    std::unordered_map<ParentChainAlgo, MultiAlgoJob> m_current_jobs;
    std::unordered_map<std::string, MultiAlgoJob> m_jobs;  // job_id -> job
    std::atomic<uint64_t> m_job_counter{0};

    // Ethash trustless "round": the WATTx aux block (template + payout coinbase +
    // commitment) stays FIXED while the WATTx tip is unchanged, so the aux_root
    // the pool commits to geth (mm_setCommitment) is stable and geth's sealing
    // header can settle on it (Namecoin-style rounds). Rebuilding it per
    // parent-height job would thrash the commitment — geth's header would never
    // carry the current job's aux_root and no proof would ever bind.
    struct EthashRound {
        uint256 wtx_tip;
        std::shared_ptr<interfaces::BlockTemplate> wattx_template;
        CTransactionRef payout_coinbase;
        uint256 aux_merkle_root;
        std::vector<uint8_t> merge_mining_tag;
        uint64_t wattx_height{0};
        uint32_t wattx_bits{0};
        uint256 wattx_target;
        bool valid{false};
    };
    EthashRound m_ethash_round;

    // Statistics
    std::unordered_map<std::string, std::atomic<uint64_t>> m_total_shares;
    std::unordered_map<std::string, std::atomic<uint64_t>> m_blocks_found;
    std::atomic<uint64_t> m_wtx_blocks_found{0};

    // Per-coin hashrate tracking for cross-algorithm share calculation
    mutable std::mutex m_hashrate_mutex;
    std::unordered_map<std::string, CoinHashrateStats> m_coin_stats;  // coin_name -> stats
    std::unordered_map<std::string, MinerScore> m_miner_scores;       // wtx_address -> score
    // Confiscated-excess share of the WTX block reward and where it is paid
    // (the pool). Set by RecalculateMinerScores, read by BuildPayoutCoinbase;
    // both hold m_hashrate_mutex.
    double m_pool_reward_share{0.0};
    std::string m_excess_redirect_address;

    // Set by RecalculateMinerScores when the set of wallets in the payout split
    // changes; the hashrate thread then wakes every JobThread so the very next
    // job commits to a payout coinbase that reflects the change. Without this a
    // newcomer's blocks pay the STALE split for up to hashrate_update_interval +
    // job_timeout_seconds — and when no one was scored yet (fresh pool, daemon
    // restart) the stale split is the template default: 100% to the pool wallet.
    bool m_payout_set_changed{false};             // guarded by m_hashrate_mutex
    std::set<std::string> m_last_payout_wallets;  // guarded by m_hashrate_mutex

    // Out-of-band wake for the hashrate/scoring cycle: fired on the first
    // accepted share from a wallet not yet in m_miner_scores, so a new miner is
    // scored (and jobs rebuilt) immediately instead of after the interval sleep.
    std::condition_variable m_rescore_cv;
    std::mutex m_rescore_mutex;
    bool m_rescore_now{false};

    // Hashrate update thread
    std::thread m_hashrate_thread;
    void HashrateUpdateThread();
    void UpdateCoinHashrates();
    void UpdateMinerHashrates();
    void RecalculateMinerScores();

    // Record a share submission (updates miner's hashrate on that chain)
    void RecordMinerShare(const std::string& wtx_address, const std::string& coin_name, uint64_t difficulty,
                          const std::string& ip_address = "");

    // Get miner's score and reward share
    MinerScore GetMinerScore(const std::string& wtx_address) const;
    std::vector<MinerScore> GetAllMinerScores() const;

    // Get total scores for reward distribution
    double GetTotalMinerScores() const;

    // ========================================================================
    // DECENTRALIZATION MECHANISMS
    // ========================================================================

    /**
     * Check if a miner has exceeded the 50% nethash cap on a specific chain.
     * @param wtx_address The miner's WATTx address
     * @param coin_name The parent chain name
     * @return true if miner is at or above 50% cap (share should not count toward score)
     */
    bool IsMinerCappedOnChain(const std::string& wtx_address, const std::string& coin_name) const;

    /**
     * Get a miner's current nethash percentage on a specific chain.
     * @param wtx_address The miner's WATTx address
     * @param coin_name The parent chain name
     * @return Percentage of network hashrate (0-100+)
     */
    double GetMinerNethashPercent(const std::string& wtx_address, const std::string& coin_name) const;

    /**
     * Calculate the luck multiplier for a miner based on diversification.
     * More diversified = higher luck = easier to find WATTx blocks.
     * Uses Herfindahl-Hirschman Index (HHI) for concentration measurement.
     * @param score The miner's score data
     * @return Luck multiplier in range [MIN_LUCK_MULTIPLIER, MAX_LUCK_MULTIPLIER]
     */
    static double CalculateLuckMultiplier(const MinerScore& score);

    /**
     * Get the adjusted WATTx target for a specific miner.
     * Target is multiplied by luck_multiplier (higher luck = higher target = easier).
     * @param base_target The base WATTx target from job
     * @param wtx_address The miner's WATTx address
     * @return Adjusted target
     */
    uint256 GetAdjustedWtxTarget(const uint256& base_target, const std::string& wtx_address) const;

    // Synchronization
    std::unordered_map<ParentChainAlgo, std::condition_variable> m_job_cvs;
    std::unordered_map<ParentChainAlgo, std::mutex> m_job_cv_mutexes;
};

/**
 * Global multi-chain merged stratum server instance
 */
MultiMergedStratumServer& GetMultiMergedStratumServer();

}  // namespace merged_stratum

#endif  // WATTX_STRATUM_MULTI_MERGED_STRATUM_H
