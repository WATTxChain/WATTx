// Copyright (c) 2024 The WATTx developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_X25X_X25X_H
#define BITCOIN_CRYPTO_X25X_X25X_H

#include <primitives/block.h>
#include <uint256.h>
#include <consensus/params.h>

#include <string>
#include <vector>
#include <map>
#include <functional>

// Forward declaration
class CBlockIndex;

/**
 * X25X Multi-Algorithm Mining Framework
 *
 * WATTx supports multiple mining algorithms to enable merged mining
 * and decentralize mining across different hardware types:
 *
 * - SHA256d:   Bitcoin-compatible, ASIC-friendly
 * - Scrypt:    Litecoin-compatible, memory-hard
 * - Ethash:    Ethereum-compatible, GPU-optimized (until PoS transition)
 * - RandomX:   Monero-compatible, CPU-optimized, ASIC-resistant
 * - Equihash:  ZCash-compatible (ZHash variant), memory-hard
 * - X11:       Dash-compatible, chain of 11 algorithms
 *
 * Each algorithm maintains its own difficulty to ensure fair block times
 * regardless of which algorithm finds a block.
 */

namespace x25x {

/**
 * Supported mining algorithms
 */
enum class Algorithm : uint8_t {
    SHA256D     = 0x00,  // Double SHA-256 (Bitcoin)
    SCRYPT      = 0x01,  // Scrypt (Litecoin) - N=1024, r=1, p=1
    ETHASH      = 0x02,  // Ethash (Ethereum)
    RANDOMX     = 0x03,  // RandomX (Monero)
    EQUIHASH    = 0x04,  // Equihash 200,9 (ZCash)
    X11         = 0x05,  // X11 chain (Dash)
    GHOSTRIDER  = 0x06,  // GhostRider (Raptoreum) - reserved for future
    KHEAVYHASH  = 0x07,  // kHeavyHash (Kaspa) - GPU-optimized optical mining

    // Special values
    INVALID     = 0xFF,
    DEFAULT     = SHA256D  // Default algorithm when none specified
};

/**
 * Algorithm metadata
 */
struct AlgorithmInfo {
    Algorithm algo;
    std::string name;
    std::string description;
    bool enabled;
    bool supportsMergedMining;
    uint32_t difficultyMultiplier;  // Relative difficulty scaling (1000 = 1.0x)
};

/**
 * Get algorithm information
 */
const AlgorithmInfo& GetAlgorithmInfo(Algorithm algo);

/**
 * Get algorithm by name (case-insensitive)
 */
Algorithm GetAlgorithmByName(const std::string& name);

/**
 * Get all enabled algorithms
 */
std::vector<Algorithm> GetEnabledAlgorithms();

/**
 * Check if an algorithm is enabled
 */
bool IsAlgorithmEnabled(Algorithm algo);

/**
 * @brief Can this algorithm's proof of work be verified from the block header alone?
 *
 * An algorithm may be ENABLED (it takes part in merged mining, has a difficulty
 * chain, is offered by the stratum server) and still have no way to prove work
 * from a bare CBlockHeader. Equihash is the case that matters: its proof is a
 * Wagner solution, which the header has nowhere to carry, so it can only be
 * proved through the AuxPoW path where the parent block supplies it.
 *
 * Solo mining such an algorithm MUST be refused rather than approximated with
 * some other algorithm's hash -- see HashBlockHeader.
 */
bool HasSoloProofOfWork(Algorithm algo);

/**
 * Extract algorithm from block version
 * Algorithm is encoded in bits 8-15 of nVersion
 */
Algorithm GetBlockAlgorithm(int32_t nVersion);

/**
 * Encode algorithm into block version
 */
int32_t SetBlockAlgorithm(int32_t nVersion, Algorithm algo);

/**
 * Calculate the hash of a block header using the specified algorithm
 *
 * @param header The block header to hash
 * @param algo The algorithm to use (if INVALID, detect from header)
 * @param blockHeight Block height (required for Ethash epoch calculation)
 * @return The resulting hash
 */
uint256 HashBlockHeader(const CBlockHeader& header, Algorithm algo = Algorithm::INVALID, uint64_t blockHeight = 0);

/**
 * Verify that a block's proof-of-work is valid for its algorithm
 *
 * @param header The block header to verify
 * @param nBits The target difficulty (compact format)
 * @param params Consensus parameters
 * @return true if the PoW is valid
 */
bool CheckProofOfWork(const CBlockHeader& header, unsigned int nBits, const Consensus::Params& params);

/**
 * Get the proof-of-work limit for a specific algorithm
 */
uint256 GetAlgorithmPowLimit(Algorithm algo, const Consensus::Params& params);

/**
 * Calculate next work required for a specific algorithm
 * Each algorithm maintains its own difficulty chain
 *
 * @param pindexLast The last block index
 * @param algo The algorithm to calculate difficulty for
 * @param params Consensus parameters
 * @return The new difficulty target (compact format)
 */
unsigned int GetNextWorkRequiredForAlgorithm(const CBlockIndex* pindexLast,
                                              Algorithm algo,
                                              const Consensus::Params& params);

/**
 * Hash functions for each algorithm
 */
namespace hash {

/**
 * Double SHA-256 hash
 */
uint256 SHA256D(const unsigned char* data, size_t len);
uint256 SHA256D(const CBlockHeader& header);

/**
 * Scrypt hash with standard parameters (N=1024, r=1, p=1)
 */
uint256 Scrypt(const unsigned char* data, size_t len);
uint256 Scrypt(const CBlockHeader& header);

/**
 * Ethash (requires DAG epoch context)
 * @param header Block header to hash
 * @param nonce 64-bit nonce
 * @param blockHeight Block height (used to determine epoch: epoch = height / 30000)
 * @param mixHashOut Optional output for the mix hash (needed for block submission)
 * @return The final hash result
 */
uint256 Ethash(const CBlockHeader& header, uint64_t nonce, uint64_t blockHeight = 0, uint256* mixHashOut = nullptr);

/**
 * RandomX hash (requires initialized RandomX context)
 */
uint256 RandomX(const unsigned char* data, size_t len);
uint256 RandomX(const CBlockHeader& header);

/**
 * Equihash verification (ZHash variant)
 * Note: Equihash doesn't produce a traditional hash; it's a solution verification
 */
bool VerifyEquihash(const CBlockHeader& header, const std::vector<unsigned char>& solution);

/**
 * X11 hash chain (blake, bmw, groestl, jh, keccak, skein, luffa, cubehash, shavite, simd, echo)
 */
uint256 X11(const unsigned char* data, size_t len);
uint256 X11(const CBlockHeader& header);

/**
 * kHeavyHash (Kaspa) - GPU-optimized optical mining algorithm
 * Uses Blake3 + 64x64 matrix multiplication for ASIC resistance
 */
uint256 KHeavyHash(const unsigned char* data, size_t len);
uint256 KHeavyHash(const CBlockHeader& header);

} // namespace hash

/**
 * Merged mining support
 */
namespace merged {

/**
 * Check if a parent chain block can be used for merged mining
 *
 * @param parentChainId The chain ID of the parent block
 * @param algo The algorithm used
 * @return true if valid for merged mining
 */
bool IsValidParentChain(uint32_t parentChainId, Algorithm algo);

/**
 * Get the chain ID for a given algorithm's primary chain
 */
uint32_t GetPrimaryChainId(Algorithm algo);

/**
 * Verify merged mining proof
 *
 * @param header WATTx block header
 * @param auxpowData Auxiliary proof-of-work data
 * @param params Consensus parameters
 * @return true if the merged mining proof is valid
 */
bool VerifyMergedMiningProof(const CBlockHeader& header,
                              const std::vector<unsigned char>& auxpowData,
                              const Consensus::Params& params);

} // namespace merged

/**
 * Algorithm-specific difficulty adjustment
 */
class MultiAlgoDifficultyManager {
public:
    /**
     * Get the last block index that used a specific algorithm
     */
    static const CBlockIndex* GetLastBlockForAlgorithm(const CBlockIndex* pindexLast, Algorithm algo);

    /**
     * Count blocks using a specific algorithm within a range
     */
    static int CountBlocksForAlgorithm(const CBlockIndex* pindexStart, int nCount, Algorithm algo);

    /**
     * Calculate the average time between blocks for an algorithm
     */
    static int64_t GetAverageBlockTimeForAlgorithm(const CBlockIndex* pindexLast,
                                                    Algorithm algo,
                                                    int nLookback);
};

} // namespace x25x

#endif // BITCOIN_CRYPTO_X25X_X25X_H
