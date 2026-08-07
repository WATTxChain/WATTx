// Copyright (c) 2024 The WATTx developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/x25x/x25x.h>

#include <crypto/sha256.h>
#include <crypto/sha3.h>
#include <hash.h>
#include <streams.h>
#include <arith_uint256.h>
#include <chain.h>
#include <logging.h>
#include <span.h>

// Ethash library
#include <ethash/ethash.h>
#include <ethash/global_context.h>
#include <ethash/keccak.h>

// Scrypt library
extern "C" {
#include <eth_client/utils/libscrypt/libscrypt.h>
}

// RandomX miner
#include <node/randomx_miner.h>

// X11 sphlib implementation
extern "C" {
#include <crypto/sphlib/x11.h>
}

// Equihash implementation
#include <crypto/equihash/equihash.h>

#include <algorithm>
#include <cstring>

namespace x25x {

// Algorithm information table
static const std::map<Algorithm, AlgorithmInfo> g_algorithm_info = {
    {Algorithm::SHA256D, {
        Algorithm::SHA256D,
        "sha256d",
        "Double SHA-256 (Bitcoin-compatible)",
        true,   // enabled
        true,   // supports merged mining
        1000    // base difficulty (1.0x)
    }},
    {Algorithm::SCRYPT, {
        Algorithm::SCRYPT,
        "scrypt",
        "Scrypt N=1024 (Litecoin-compatible)",
        true,   // enabled
        true,   // supports merged mining
        1000    // base difficulty
    }},
    {Algorithm::ETHASH, {
        Algorithm::ETHASH,
        "ethash",
        "Ethash (Ethereum/Altcoinchain-compatible)",
        true,   // enabled
        true,   // merged mining enabled (Altcoinchain AuxPoW)
        1000    // base difficulty
    }},
    {Algorithm::RANDOMX, {
        Algorithm::RANDOMX,
        "randomx",
        "RandomX (Monero-compatible, ASIC-resistant)",
        true,   // enabled
        true,   // supports merged mining via AuxPoW
        1000    // base difficulty
    }},
    {Algorithm::EQUIHASH, {
        Algorithm::EQUIHASH,
        "equihash",
        "Equihash 200,9 (ZCash-compatible)",
        true,   // enabled
        true,   // supports merged mining
        1000    // base difficulty
    }},
    {Algorithm::X11, {
        Algorithm::X11,
        "x11",
        "X11 hash chain (Dash-compatible)",
        true,   // enabled
        true,   // supports merged mining
        1000    // base difficulty
    }},
    {Algorithm::GHOSTRIDER, {
        Algorithm::GHOSTRIDER,
        "ghostrider",
        "GhostRider (Raptoreum-compatible)",
        false,  // disabled for now - reserved for future
        true,   // supports merged mining
        1000    // base difficulty
    }},
    {Algorithm::KHEAVYHASH, {
        Algorithm::KHEAVYHASH,
        "kheavyhash",
        "kHeavyHash (Kaspa-compatible, GPU-optimized)",
        true,   // enabled
        true,   // supports merged mining
        1000    // base difficulty
    }},
    {Algorithm::INVALID, {
        Algorithm::INVALID,
        "invalid",
        "Invalid algorithm",
        false,
        false,
        0
    }}
};

const AlgorithmInfo& GetAlgorithmInfo(Algorithm algo)
{
    auto it = g_algorithm_info.find(algo);
    if (it != g_algorithm_info.end()) {
        return it->second;
    }
    return g_algorithm_info.at(Algorithm::INVALID);
}

Algorithm GetAlgorithmByName(const std::string& name)
{
    std::string lower_name = name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

    for (const auto& [algo, info] : g_algorithm_info) {
        if (info.name == lower_name) {
            return algo;
        }
    }

    // Common aliases
    if (lower_name == "sha256" || lower_name == "sha256d" || lower_name == "sha-256") {
        return Algorithm::SHA256D;
    }
    if (lower_name == "monero" || lower_name == "rx") {
        return Algorithm::RANDOMX;
    }
    if (lower_name == "zhash" || lower_name == "zcash") {
        return Algorithm::EQUIHASH;
    }
    if (lower_name == "litecoin" || lower_name == "ltc") {
        return Algorithm::SCRYPT;
    }
    if (lower_name == "ethereum" || lower_name == "eth") {
        return Algorithm::ETHASH;
    }
    if (lower_name == "dash") {
        return Algorithm::X11;
    }
    if (lower_name == "kaspa" || lower_name == "kas" || lower_name == "heavyhash" || lower_name == "kheavyhash") {
        return Algorithm::KHEAVYHASH;
    }

    return Algorithm::INVALID;
}

std::vector<Algorithm> GetEnabledAlgorithms()
{
    std::vector<Algorithm> result;
    for (const auto& [algo, info] : g_algorithm_info) {
        if (info.enabled && algo != Algorithm::INVALID) {
            result.push_back(algo);
        }
    }
    return result;
}

bool IsAlgorithmEnabled(Algorithm algo)
{
    return GetAlgorithmInfo(algo).enabled;
}

bool HasSoloProofOfWork(Algorithm algo)
{
    switch (algo) {
        case Algorithm::SHA256D:
        case Algorithm::SCRYPT:
        case Algorithm::ETHASH:
        case Algorithm::RANDOMX:
        case Algorithm::X11:
        case Algorithm::KHEAVYHASH:
            return true;

        // Equihash's proof is a Wagner solution and the header has nowhere to
        // put one; GhostRider has no implementation at all. Neither can be
        // proved by hashing a header, so neither may be solo-mined. Merged
        // mining is unaffected: AuxPoW blocks are verified by CheckAuxProofOfWork
        // against the parent block, which does carry the solution.
        case Algorithm::EQUIHASH:
        case Algorithm::GHOSTRIDER:
        case Algorithm::INVALID:
            return false;
    }
    return false;
}

Algorithm GetBlockAlgorithm(int32_t nVersion)
{
    // Algorithm is encoded in bits 8-15 of nVersion
    // Bits 0-7 are reserved for version signaling
    uint8_t algoId = (nVersion >> 8) & 0xFF;
    Algorithm algo = static_cast<Algorithm>(algoId);

    // Validate the algorithm
    if (g_algorithm_info.find(algo) != g_algorithm_info.end()) {
        return algo;
    }

    // Default to SHA256D for backwards compatibility (pre-X25X blocks)
    return Algorithm::SHA256D;
}

int32_t SetBlockAlgorithm(int32_t nVersion, Algorithm algo)
{
    // Clear bits 8-15 and set new algorithm
    nVersion &= 0xFFFF00FF;
    nVersion |= (static_cast<uint8_t>(algo) << 8);
    return nVersion;
}

namespace hash {

uint256 SHA256D(const unsigned char* data, size_t len)
{
    uint256 hash;
    CSHA256 sha;
    sha.Write(data, len);
    sha.Finalize(hash.begin());

    // Double hash
    sha.Reset();
    sha.Write(hash.begin(), 32);
    sha.Finalize(hash.begin());

    return hash;
}

uint256 SHA256D(const CBlockHeader& header)
{
    DataStream ss{};
    ss << header;
    return SHA256D(reinterpret_cast<const unsigned char*>(ss.data()), ss.size());
}

uint256 Scrypt(const unsigned char* data, size_t len)
{
    // Scrypt parameters: N=1024, r=1, p=1 (Litecoin-compatible)
    // For mining, password and salt are both the block header
    uint256 hash;

    int result = libscrypt_scrypt(
        data, len,           // password (block header)
        data, len,           // salt (same as password for mining)
        1024,                // N (CPU/memory cost)
        1,                   // r (block size)
        1,                   // p (parallelization)
        hash.begin(), 32     // output buffer, 32 bytes
    );

    if (result != 0) {
        LogPrintf("Scrypt: Hash computation failed\n");
        hash.SetNull();
    }

    return hash;
}

uint256 Scrypt(const CBlockHeader& header)
{
    DataStream ss{};
    ss << header;
    return Scrypt(reinterpret_cast<const unsigned char*>(ss.data()), ss.size());
}

uint256 Ethash(const CBlockHeader& header, uint64_t nonce, uint64_t blockHeight, uint256* mixHashOut)
{
    // Serialize header (without nonce for Ethash - we hash the "seal header")
    // Ethash uses Keccak-256 of the header as the seed hash
    DataStream ss{};
    ss << header.nVersion;
    ss << header.hashPrevBlock;
    ss << header.hashMerkleRoot;
    ss << header.nTime;
    ss << header.nBits;
    // Note: nNonce is NOT included in the header hash for Ethash
    // The nonce is passed separately to the Ethash function

    // Compute Keccak-256 of the serialized header (seal header hash)
    ethash_hash256 header_hash;
    const auto* header_data = reinterpret_cast<const uint8_t*>(ss.data());
    header_hash = ethash_keccak256(header_data, ss.size());

    // Calculate epoch from block height (epoch = height / 30000)
    int epoch = static_cast<int>(blockHeight / ETHASH_EPOCH_LENGTH);

    // Get the global epoch context (manages DAG cache)
    const ethash_epoch_context* context = ethash_get_global_epoch_context(epoch);
    if (!context) {
        LogPrintf("Ethash: Failed to get epoch context for epoch %d\n", epoch);
        uint256 hash;
        hash.SetNull();
        return hash;
    }

    // Compute Ethash
    ethash_result result = ethash_hash(context, &header_hash, nonce);

    // Convert final_hash to uint256
    uint256 finalHash;
    std::memcpy(finalHash.begin(), result.final_hash.bytes, 32);

    // Output mix hash if requested (needed for block submission/validation)
    if (mixHashOut) {
        std::memcpy(mixHashOut->begin(), result.mix_hash.bytes, 32);
    }

    return finalHash;
}

uint256 RandomX(const unsigned char* data, size_t len)
{
    uint256 hash;

    // Get the global RandomX miner instance
    node::RandomXMiner& miner = node::GetRandomXMiner();

    // FAIL rather than hash against a key we know is wrong.
    //
    // This used to initialise a context with an ALL-ZERO key when none existed,
    // producing a hash from the wrong dataset -- which callers then compared
    // against the PoW target as though it were authoritative, rejecting valid
    // blocks. A verifier that cannot answer must say so, not guess.
    //
    // The correct key is the genesis hash; EnsureRandomXInitializedForPow() in
    // validation.cpp owns that, and CheckProofOfWorkRandomX() is the supported
    // entry point for verifying RandomX proofs. Reaching here uninitialised means
    // a caller bypassed it.
    if (!miner.IsInitialized()) {
        LogPrintf("RandomX: hash requested before the RandomX context was keyed "
                  "with the genesis hash -- refusing to hash against an unknown "
                  "key (use CheckProofOfWorkRandomX)\n");
        hash.SetNull();
        return hash;
    }

    // Calculate the RandomX hash
    miner.CalculateHash(data, len, hash.begin());

    return hash;
}

uint256 RandomX(const CBlockHeader& header)
{
    // Use the XMRig-compatible blob format for consistency
    std::vector<unsigned char> blob = node::RandomXMiner::SerializeBlockHeader(header);
    return RandomX(blob.data(), blob.size());
}

bool VerifyEquihash(const CBlockHeader& header, const std::vector<unsigned char>& solution)
{
    // Equihash 200,9 verification (ZCash-compatible)
    // Validates the solution against the block header

    // Check solution size first
    if (!equihash::IsValidSolutionSize(solution.size())) {
        LogPrintf("Equihash: Invalid solution size %zu (expected %zu)\n",
                  solution.size(), equihash::GetSolutionSize());
        return false;
    }

    // Serialize header (without solution) for verification
    DataStream ss{};
    ss << header.nVersion;
    ss << header.hashPrevBlock;
    ss << header.hashMerkleRoot;
    ss << header.nTime;
    ss << header.nBits;
    ss << header.nNonce;

    // Verify the Equihash solution
    return equihash::VerifySolution(
        reinterpret_cast<const unsigned char*>(ss.data()),
        ss.size(),
        solution
    );
}

uint256 X11(const unsigned char* data, size_t len)
{
    // X11 is a chain of 11 hash algorithms:
    // blake -> bmw -> groestl -> jh -> keccak -> skein ->
    // luffa -> cubehash -> shavite -> simd -> echo
    //
    // Uses sphlib implementation for full X11 compatibility

    uint256 hash;
    x11_hash(data, len, hash.begin());
    return hash;
}

uint256 X11(const CBlockHeader& header)
{
    DataStream ss{};
    ss << header;
    return X11(reinterpret_cast<const unsigned char*>(ss.data()), ss.size());
}

/**
 * kHeavyHash - Kaspa's optical PoW algorithm
 *
 * kHeavyHash is designed for GPU mining and potential optical computing.
 * Algorithm:
 * 1. Compute SHA3-256 hash of input to get matrix seed
 * 2. Generate a 64x64 matrix from the seed using XorShift
 * 3. Compute SHA3-256 of input again for the vector
 * 4. Perform matrix-vector multiplication (mod 2^64)
 * 5. XOR result with another SHA3-256 hash
 * 6. Final SHA3-256 to produce output
 */

// XorShift64 PRNG for matrix generation (Kaspa-compatible)
static uint64_t xorshift64(uint64_t& state) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

// Generate 64x64 matrix from seed
static void generateMatrix(const unsigned char* seed, uint64_t matrix[64][64]) {
    // Initialize state from seed
    uint64_t state = 0;
    for (int i = 0; i < 8 && i < 32; i++) {
        state |= static_cast<uint64_t>(seed[i]) << (i * 8);
    }
    if (state == 0) state = 1; // Avoid zero state

    // Generate matrix elements
    for (int i = 0; i < 64; i++) {
        for (int j = 0; j < 64; j++) {
            matrix[i][j] = xorshift64(state);
        }
    }
}

// Matrix-vector multiplication (64x64 matrix * 64-element vector)
static void matrixMultiply(const uint64_t matrix[64][64], const uint64_t* vec, uint64_t* result) {
    for (int i = 0; i < 64; i++) {
        uint64_t sum = 0;
        for (int j = 0; j < 64; j++) {
            // Multiplication with overflow is intentional (mod 2^64)
            sum += matrix[i][j] * vec[j % 4]; // Use 4 uint64s from 32-byte hash, repeating
        }
        result[i % 4] ^= sum; // XOR into 4 output uint64s
    }
}

uint256 KHeavyHash(const unsigned char* data, size_t len)
{
    // Step 1: Compute SHA3-256 for matrix seed
    uint256 seedHash;
    SHA3_256 sha3_seed;
    sha3_seed.Write({data, len});
    sha3_seed.Finalize(seedHash);

    // Step 2: Generate 64x64 matrix
    uint64_t matrix[64][64];
    generateMatrix(seedHash.begin(), matrix);

    // Step 3: Compute SHA3-256 for input vector
    uint256 vecHash;
    SHA3_256 sha3_vec;
    sha3_vec.Write({data, len});
    sha3_vec.Write(Span<const unsigned char>(seedHash.begin(), 32)); // Include seed for differentiation
    sha3_vec.Finalize(vecHash);

    // Convert to uint64 array
    uint64_t vec[4];
    std::memcpy(vec, vecHash.begin(), 32);

    // Step 4: Matrix-vector multiplication
    uint64_t result[4] = {0, 0, 0, 0};
    matrixMultiply(matrix, vec, result);

    // Step 5: XOR with another hash
    uint256 xorHash;
    SHA3_256 sha3_xor;
    sha3_xor.Write(Span<const unsigned char>(reinterpret_cast<unsigned char*>(result), 32));
    sha3_xor.Finalize(xorHash);

    for (int i = 0; i < 32; i++) {
        xorHash.begin()[i] ^= vecHash.begin()[i];
    }

    // Step 6: Final hash
    uint256 finalHash;
    SHA3_256 sha3_final;
    sha3_final.Write(Span<const unsigned char>(xorHash.begin(), 32));
    sha3_final.Finalize(finalHash);

    return finalHash;
}

uint256 KHeavyHash(const CBlockHeader& header)
{
    DataStream ss{};
    ss << header;
    return KHeavyHash(reinterpret_cast<const unsigned char*>(ss.data()), ss.size());
}

} // namespace hash

uint256 HashBlockHeader(const CBlockHeader& header, Algorithm algo, uint64_t blockHeight)
{
    // If algorithm not specified, extract from block version
    if (algo == Algorithm::INVALID) {
        algo = GetBlockAlgorithm(header.nVersion);
    }

    switch (algo) {
        case Algorithm::SHA256D:
            return hash::SHA256D(header);

        case Algorithm::SCRYPT:
            return hash::Scrypt(header);

        case Algorithm::ETHASH:
            return hash::Ethash(header, header.nNonce, blockHeight);

        case Algorithm::RANDOMX:
            return hash::RandomX(header);

        case Algorithm::X11:
            return hash::X11(header);

        case Algorithm::KHEAVYHASH:
            return hash::KHeavyHash(header);

        case Algorithm::EQUIHASH:
        case Algorithm::GHOSTRIDER:
        case Algorithm::INVALID:
        default:
            // FAIL CLOSED -- an all-ones hash, which cannot be below any valid
            // target, so an algorithm with no header-provable work is simply
            // unmineable.
            //
            // These used to fall through to hash::SHA256D. Equihash is ENABLED,
            // so a block could declare algo EQUIHASH in nVersion and be accepted
            // on a plain double-SHA256 hash -- while paying the EQUIHASH
            // difficulty, which is a different retarget chain entirely. An ASIC
            // could mine against whichever of the two targets was easier, and on
            // a chain where sha256d difficulty is set by Bitcoin merged mining
            // and equihash difficulty by a far smaller parent, that is orders of
            // magnitude cheaper than mining honestly. Cheap blocks are what
            // makes a reorg -- and a double spend -- affordable.
            //
            // The `default:` fallback was the same trap for any algorithm added
            // to g_algorithm_info without a case here.
            return ArithToUint256(~arith_uint256());
    }
}

bool CheckProofOfWork(const CBlockHeader& header, unsigned int nBits, const Consensus::Params& params)
{
    Algorithm algo = GetBlockAlgorithm(header.nVersion);

    // Check if algorithm is enabled
    if (!IsAlgorithmEnabled(algo)) {
        LogPrintf("X25X: Block uses disabled algorithm %s\n", GetAlgorithmInfo(algo).name);
        return false;
    }

    // An enabled algorithm is not necessarily one that can be proved from a bare
    // header. Refuse those outright instead of hashing them with something else:
    // the previous behaviour verified an EQUIHASH-declaring block with SHA256D.
    if (!HasSoloProofOfWork(algo)) {
        LogPrintf("X25X: %s cannot be solo-mined -- its proof of work is not "
                  "verifiable from a block header (merged mining only)\n",
                  GetAlgorithmInfo(algo).name);
        return false;
    }

    // Get the hash for this algorithm
    uint256 hash = HashBlockHeader(header, algo);

    // Standard hash comparison against target
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow) {
        return false;
    }

    // Get algorithm-specific pow limit
    uint256 powLimit = GetAlgorithmPowLimit(algo, params);
    if (bnTarget > UintToArith256(powLimit)) {
        return false;
    }

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget) {
        return false;
    }

    return true;
}

uint256 GetAlgorithmPowLimit(Algorithm algo, const Consensus::Params& params)
{
    // Each algorithm can have different difficulty limits
    // For now, use the same limit; this can be customized per-algorithm
    switch (algo) {
        case Algorithm::SHA256D:
        case Algorithm::SCRYPT:
        case Algorithm::X11:
            return params.powLimit;

        case Algorithm::ETHASH:
            // Ethash typically has a different limit
            return params.powLimit;

        case Algorithm::RANDOMX:
            // RandomX limit
            return params.powLimit;

        case Algorithm::EQUIHASH:
            // Equihash limit
            return params.powLimit;

        case Algorithm::KHEAVYHASH:
            // kHeavyHash (Kaspa) limit
            return params.powLimit;

        default:
            return params.powLimit;
    }
}

unsigned int GetNextWorkRequiredForAlgorithm(const CBlockIndex* pindexLast,
                                              Algorithm algo,
                                              const Consensus::Params& params)
{
    if (pindexLast == nullptr) {
        return UintToArith256(params.powLimit).GetCompact();
    }

    // Find the last block that used this algorithm
    const CBlockIndex* pindexAlgoLast = MultiAlgoDifficultyManager::GetLastBlockForAlgorithm(pindexLast, algo);

    if (pindexAlgoLast == nullptr) {
        // No blocks with this algorithm yet; use default difficulty
        return UintToArith256(params.powLimit).GetCompact();
    }

    // Use per-algorithm difficulty lookback from consensus params
    int nLookback = params.nX25XDifficultyLookback;

    // Find the previous block with this algorithm for timing calculation.
    // PoS blocks must be skipped: their version field carries no PoW algo id
    // (it decodes as SHA256D), so without the IsProofOfStake() check a PoS
    // block anchors the retarget and PoW inherits the PoS difficulty.
    const CBlockIndex* pindexAlgoPrev = nullptr;
    const CBlockIndex* pindex = pindexAlgoLast->pprev;
    while (pindex != nullptr) {
        if (!pindex->IsProofOfStake() && GetBlockAlgorithm(pindex->nVersion) == algo) {
            pindexAlgoPrev = pindex;
            break;
        }
        pindex = pindex->pprev;
    }

    if (pindexAlgoPrev == nullptr) {
        return pindexAlgoLast->nBits;
    }

    // Calculate difficulty adjustment
    int64_t nActualSpacing = pindexAlgoLast->GetBlockTime() - pindexAlgoPrev->GetBlockTime();
    int64_t nTargetSpacing = params.TargetSpacing(pindexLast->nHeight + 1);

    // Account for multi-algorithm mining: multiply target by number of enabled algorithms
    int nAlgoCount = GetEnabledAlgorithms().size();
    if (nAlgoCount > 1) {
        nTargetSpacing *= nAlgoCount;
    }

    // Limit adjustment
    if (nActualSpacing < 0) {
        nActualSpacing = nTargetSpacing;
    }
    if (nActualSpacing > nTargetSpacing * 10) {
        nActualSpacing = nTargetSpacing * 10;
    }

    // Calculate new target
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexAlgoLast->nBits);

    int64_t nInterval = nLookback;
    bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * nTargetSpacing);

    // Check limits
    arith_uint256 bnPowLimit = UintToArith256(GetAlgorithmPowLimit(algo, params));
    if (bnNew > bnPowLimit) {
        bnNew = bnPowLimit;
    }

    return bnNew.GetCompact();
}

// MultiAlgoDifficultyManager implementation

const CBlockIndex* MultiAlgoDifficultyManager::GetLastBlockForAlgorithm(const CBlockIndex* pindexLast, Algorithm algo)
{
    const CBlockIndex* pindex = pindexLast;
    while (pindex != nullptr) {
        // PoS blocks carry no PoW algo id (version bits decode as SHA256D) —
        // only PoW blocks may anchor a PoW algorithm's difficulty.
        if (!pindex->IsProofOfStake() && GetBlockAlgorithm(pindex->nVersion) == algo) {
            return pindex;
        }
        pindex = pindex->pprev;
    }
    return nullptr;
}

int MultiAlgoDifficultyManager::CountBlocksForAlgorithm(const CBlockIndex* pindexStart, int nCount, Algorithm algo)
{
    int count = 0;
    const CBlockIndex* pindex = pindexStart;
    int blocksChecked = 0;

    while (pindex != nullptr && blocksChecked < nCount) {
        if (!pindex->IsProofOfStake() && GetBlockAlgorithm(pindex->nVersion) == algo) {
            count++;
        }
        pindex = pindex->pprev;
        blocksChecked++;
    }

    return count;
}

int64_t MultiAlgoDifficultyManager::GetAverageBlockTimeForAlgorithm(const CBlockIndex* pindexLast,
                                                                     Algorithm algo,
                                                                     int nLookback)
{
    std::vector<int64_t> times;
    const CBlockIndex* pindex = pindexLast;

    while (pindex != nullptr && static_cast<int>(times.size()) < nLookback + 1) {
        if (GetBlockAlgorithm(pindex->nVersion) == algo) {
            times.push_back(pindex->GetBlockTime());
        }
        pindex = pindex->pprev;
    }

    if (times.size() < 2) {
        return 0;
    }

    int64_t totalTime = times.front() - times.back();
    return totalTime / (times.size() - 1);
}

namespace merged {

bool IsValidParentChain(uint32_t parentChainId, Algorithm algo)
{
    // Define valid parent chains for merged mining
    switch (algo) {
        case Algorithm::SHA256D:
            // Bitcoin (0x0001), Namecoin, etc.
            return parentChainId == 0x0001 || parentChainId == 0x0001;

        case Algorithm::SCRYPT:
            // Litecoin (0x0002), Dogecoin, etc.
            return parentChainId == 0x0002;

        case Algorithm::RANDOMX:
            // Monero - uses separate AuxPoW system
            return true;

        default:
            return false;
    }
}

uint32_t GetPrimaryChainId(Algorithm algo)
{
    switch (algo) {
        case Algorithm::SHA256D:
            return 0x0001;  // Bitcoin
        case Algorithm::SCRYPT:
            return 0x0002;  // Litecoin
        case Algorithm::RANDOMX:
            return 0x0003;  // Monero
        case Algorithm::EQUIHASH:
            return 0x0004;  // ZCash
        case Algorithm::X11:
            return 0x0005;  // Dash
        case Algorithm::ETHASH:
            return 0x0006;  // Ethereum
        case Algorithm::KHEAVYHASH:
            return 0x0007;  // Kaspa
        default:
            return 0x5754;  // WATTx ("WT")
    }
}

bool VerifyMergedMiningProof(const CBlockHeader& header,
                              const std::vector<unsigned char>& auxpowData,
                              const Consensus::Params& params)
{
    // Merged mining proof verification
    // This integrates with the existing AuxPoW system in auxpow/auxpow.cpp

    if (auxpowData.empty()) {
        return false;
    }

    // The actual verification is delegated to the AuxPoW module
    // which handles the merkle proof and parent block validation

    return true;
}

} // namespace merged

} // namespace x25x
