// Copyright (c) 2024 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_NODE_RANDOMX_MINER_H
#define BITCOIN_NODE_RANDOMX_MINER_H

#include <uint256.h>
#include <primitives/block.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>
#include <functional>

struct randomx_cache;
struct randomx_dataset;
struct randomx_vm;

namespace node {

/**
 * RandomX Miner - ASIC-resistant proof-of-work using RandomX algorithm
 *
 * RandomX is a proof-of-work algorithm that is optimized for general-purpose CPUs.
 * It uses random code execution and memory-hard techniques to prevent ASIC advantage.
 *
 * This miner supports:
 * - CPU mining with configurable thread count
 * - Light mode (slower but less memory) or Full mode (faster, needs ~2GB RAM)
 * - JIT compilation for faster execution
 * - Background mining with low CPU priority
 */
class RandomXMiner {
public:
    /** Hash size in bytes (32 bytes = 256 bits) */
    static constexpr size_t HASH_SIZE = 32;

    /** Cache memory requirement (~256 MB) */
    static constexpr size_t CACHE_SIZE = 256 * 1024 * 1024;

    /** Dataset memory requirement (~2 GB) - used in full mode */
    static constexpr size_t DATASET_SIZE = 2ULL * 1024 * 1024 * 1024;

    /** Mining mode */
    enum class Mode {
        LIGHT,  // Uses cache only (~256 MB), slower
        FULL    // Uses dataset (~2 GB), faster
    };

    /** Callback for found blocks */
    using BlockFoundCallback = std::function<void(const CBlock&)>;

    /** Callback for pool shares found by StartBlobMining. Receives the nonce
     *  that was spliced into the blob and the resulting RandomX hash. Mining
     *  CONTINUES after the callback — a pool wants every share, not the first. */
    using ShareFoundCallback = std::function<void(uint32_t nonce, const uint256& hash)>;

    RandomXMiner();
    ~RandomXMiner();

    // Disable copy
    RandomXMiner(const RandomXMiner&) = delete;
    RandomXMiner& operator=(const RandomXMiner&) = delete;

    /**
     * Initialize the RandomX context with a key (typically previous block hash)
     * @param key The initialization key (usually merkle root of recent blocks)
     * @param keySize Size of the key in bytes
     * @param mode Mining mode (LIGHT or FULL)
     * @param safeMode If true, disable JIT compilation (slower but more stable)
     * @return true if initialization succeeded
     */
    bool Initialize(const void* key, size_t keySize, Mode mode = Mode::LIGHT, bool safeMode = false);

    /**
     * Reinitialize with a new key if the key has changed
     * This is called when the blockchain advances and we need a new mining context
     */
    bool ReinitializeIfNeeded(const void* key, size_t keySize);

    /**
     * Calculate a RandomX hash for input data
     * @param input Input data to hash
     * @param inputSize Size of input data
     * @param output Buffer for 32-byte hash output
     */
    void CalculateHash(const void* input, size_t inputSize, void* output);

    /**
     * Check if a hash meets the target difficulty
     * @param hash The 32-byte hash to check
     * @param target The target threshold (hash must be <= target)
     * @return true if hash meets target
     */
    static bool MeetsTarget(const uint256& hash, const uint256& target);

    /**
     * Start mining on a block template
     * @param block Block template to mine
     * @param target Target difficulty
     * @param numThreads Number of mining threads (0 = auto)
     * @param callback Called when a valid block is found
     */
    void StartMining(const CBlock& block, const uint256& target,
                     int numThreads, BlockFoundCallback callback);

    /**
     * Mine an arbitrary hashing blob (pool mining): splice a nonce into the
     * blob at nonceOffset (4 bytes, little-endian), RandomX-hash the blob, and
     * report every hash meeting the target via the callback. Unlike
     * StartMining this never stops on a find — the pool wants a stream of
     * shares. The context must already be Initialize()d with the pool job's
     * seed. Runs until StopMining() or a new StartBlobMining() call.
     * @return false when the blob/offset is invalid or no VMs are available
     */
    bool StartBlobMining(const std::vector<unsigned char>& blob, size_t nonceOffset,
                         const uint256& target, int numThreads, ShareFoundCallback callback);

    /**
     * Stop all mining threads
     */
    void StopMining();

    /**
     * Check if mining is currently active
     */
    bool IsMining() const { return m_mining.load(); }

    /**
     * Get the current hashrate in hashes per second
     */
    double GetHashrate() const;

    /**
     * Get total hashes computed since mining started
     */
    uint64_t GetTotalHashes() const { return m_totalHashes.load(); }

    /**
     * Check if RandomX is properly initialized
     */
    bool IsInitialized() const { return m_initialized.load(); }

    /**
     * Get recommended flags for the current platform
     */
    static unsigned GetRecommendedFlags();

    /**
     * Check if hardware AES is available
     */
    static bool HasHardwareAES();

    /**
     * Check if large pages are available
     */
    static bool HasLargePages();

    /**
     * Serialize block header for hashing (full format for internal mining)
     */
    static std::vector<unsigned char> SerializeBlockHeader(const CBlockHeader& header);

    /**
     * Serialize block header into XMRig-compatible mining blob format.
     * This format has nonce at bytes 39-42 for XMRig compatibility.
     * The blob is exactly 80 bytes:
     *   bytes 0-31:  hashPrevBlock (32 bytes)
     *   bytes 32-35: nVersion (4 bytes, little-endian)
     *   bytes 36-38: nBits lower 3 bytes (3 bytes)
     *   bytes 39-42: nNonce (4 bytes, little-endian) <- XMRig modifies here
     *   bytes 43-46: nTime (4 bytes, little-endian)
     *   bytes 47-78: hashMerkleRoot (32 bytes)
     *   bytes 79:    nBits high byte (1 byte)
     */
    static std::vector<unsigned char> SerializeMiningBlob(const CBlockHeader& header);

    /**
     * Extract nonce from mining blob at bytes 39-42
     */
    static uint32_t ExtractNonceFromBlob(const std::vector<unsigned char>& blob);

private:
    /** Mining thread function */
    void MineThread(int threadId, CBlock block, uint256 target,
                    uint32_t startNonce, uint32_t nonceRange,
                    BlockFoundCallback callback);

    /** Pool-blob mining thread function */
    void BlobMineThread(int threadId, std::vector<unsigned char> blob, size_t nonceOffset,
                        uint256 target, uint32_t startNonce, uint32_t nonceRange,
                        ShareFoundCallback callback);

    /** Create per-thread VMs (under m_vmMutex); returns the usable thread count. */
    int PrepareVMs(int numThreads);

    /** Set low priority for mining threads */
    static void SetLowThreadPriority();

    /** Cleanup RandomX resources */
    void Cleanup();

    /** Internal cleanup without locking (called when mutex is already held) */
    void CleanupInternal();

    // RandomX objects
    randomx_cache* m_cache{nullptr};
    randomx_dataset* m_dataset{nullptr};
    std::vector<randomx_vm*> m_vms;  // VMs for mining threads
    randomx_vm* m_validationVm{nullptr};  // Dedicated VM for block validation (separate from mining)

    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_mining{false};
    std::atomic<bool> m_stopMining{false};
    std::atomic<uint64_t> m_totalHashes{0};
    std::atomic<int64_t> m_miningStartTime{0};

    // Persistent hashrate tracking (survives across block changes)
    mutable std::atomic<uint64_t> m_sessionHashes{0};      // Total hashes this session
    mutable std::atomic<int64_t> m_sessionStartTime{0};    // Session start time
    mutable std::atomic<double> m_lastHashrate{0.0};       // Last known hashrate
    mutable std::atomic<uint64_t> m_recentHashes{0};       // Hashes in recent window
    mutable std::atomic<int64_t> m_recentWindowStart{0};   // Start of recent window

    // Current key for detecting key changes
    std::vector<unsigned char> m_currentKey;

    // Mining threads
    std::vector<std::thread> m_threads;

    // Synchronization
    mutable std::mutex m_mutex;
    mutable std::mutex m_vmMutex;

    // Configuration
    Mode m_mode{Mode::LIGHT};
    unsigned m_flags{0};
    bool m_safeMode{false};
};

/**
 * Global RandomX miner instance
 */
RandomXMiner& GetRandomXMiner();

// Dedicated context for verifying merged-mined parent (Monero) RandomX PoW,
// keyed with the parent chain's own seed rather than the WATTx genesis key.
RandomXMiner& GetRandomXAuxMiner();

} // namespace node

#endif // BITCOIN_NODE_RANDOMX_MINER_H
