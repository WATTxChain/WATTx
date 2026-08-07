// Copyright (c) 2024 The WATTx developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <crypto/x25x/x25x.h>
#include <node/randomx_miner.h>
#include <primitives/block.h>
#include <uint256.h>
#include <streams.h>
#include <arith_uint256.h>
#include <chainparams.h>
#include <test/util/setup_common.h>

#include <cstring>

BOOST_FIXTURE_TEST_SUITE(x25x_tests, BasicTestingSetup)

// Test data - a simple block header for testing
static CBlockHeader CreateTestHeader()
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock = uint256::ONE;
    header.hashMerkleRoot = uint256::ONE;
    header.nTime = 1700000000;
    header.nBits = 0x1d00ffff;
    header.nNonce = 12345;
    return header;
}

BOOST_AUTO_TEST_CASE(algorithm_info_test)
{
    // Test that all algorithms have proper info
    auto algos = x25x::GetEnabledAlgorithms();
    BOOST_CHECK(algos.size() >= 6);  // At least 6 algorithms should be enabled

    for (auto algo : algos) {
        const auto& info = x25x::GetAlgorithmInfo(algo);
        BOOST_CHECK(!info.name.empty());
        BOOST_CHECK(!info.description.empty());
        BOOST_CHECK(info.enabled);
    }
}

BOOST_AUTO_TEST_CASE(algorithm_by_name_test)
{
    // Test algorithm lookup by name
    BOOST_CHECK(x25x::GetAlgorithmByName("sha256d") == x25x::Algorithm::SHA256D);
    BOOST_CHECK(x25x::GetAlgorithmByName("SHA256D") == x25x::Algorithm::SHA256D);
    BOOST_CHECK(x25x::GetAlgorithmByName("scrypt") == x25x::Algorithm::SCRYPT);
    BOOST_CHECK(x25x::GetAlgorithmByName("ethash") == x25x::Algorithm::ETHASH);
    BOOST_CHECK(x25x::GetAlgorithmByName("randomx") == x25x::Algorithm::RANDOMX);
    BOOST_CHECK(x25x::GetAlgorithmByName("equihash") == x25x::Algorithm::EQUIHASH);
    BOOST_CHECK(x25x::GetAlgorithmByName("x11") == x25x::Algorithm::X11);
    BOOST_CHECK(x25x::GetAlgorithmByName("kheavyhash") == x25x::Algorithm::KHEAVYHASH);

    // Test aliases
    BOOST_CHECK(x25x::GetAlgorithmByName("litecoin") == x25x::Algorithm::SCRYPT);
    BOOST_CHECK(x25x::GetAlgorithmByName("monero") == x25x::Algorithm::RANDOMX);
    BOOST_CHECK(x25x::GetAlgorithmByName("zcash") == x25x::Algorithm::EQUIHASH);
    BOOST_CHECK(x25x::GetAlgorithmByName("dash") == x25x::Algorithm::X11);
    BOOST_CHECK(x25x::GetAlgorithmByName("kaspa") == x25x::Algorithm::KHEAVYHASH);
}

BOOST_AUTO_TEST_CASE(block_version_algorithm_encoding)
{
    // Test encoding/decoding algorithm in block version
    int32_t version = 0x20000000;  // BIP9 version bits

    // Test each algorithm
    for (int i = 0; i <= 7; i++) {
        x25x::Algorithm algo = static_cast<x25x::Algorithm>(i);
        int32_t encodedVersion = x25x::SetBlockAlgorithm(version, algo);
        x25x::Algorithm decoded = x25x::GetBlockAlgorithm(encodedVersion);
        BOOST_CHECK(decoded == algo);
    }

    // Test that low bits are preserved
    version = 0x20000001;  // version with low bit set
    int32_t encoded = x25x::SetBlockAlgorithm(version, x25x::Algorithm::SCRYPT);
    BOOST_CHECK((encoded & 0xFF) == 0x01);  // Low byte preserved
    BOOST_CHECK(x25x::GetBlockAlgorithm(encoded) == x25x::Algorithm::SCRYPT);
}

BOOST_AUTO_TEST_CASE(sha256d_hash_test)
{
    CBlockHeader header = CreateTestHeader();
    header.nVersion = x25x::SetBlockAlgorithm(header.nVersion, x25x::Algorithm::SHA256D);

    uint256 hash = x25x::HashBlockHeader(header, x25x::Algorithm::SHA256D);

    // Hash should not be zero
    BOOST_CHECK(!hash.IsNull());

    // Same input should produce same hash
    uint256 hash2 = x25x::HashBlockHeader(header, x25x::Algorithm::SHA256D);
    BOOST_CHECK(hash == hash2);

    // Different nonce should produce different hash
    header.nNonce = 54321;
    uint256 hash3 = x25x::HashBlockHeader(header, x25x::Algorithm::SHA256D);
    BOOST_CHECK(hash != hash3);
}

BOOST_AUTO_TEST_CASE(scrypt_hash_test)
{
    CBlockHeader header = CreateTestHeader();
    header.nVersion = x25x::SetBlockAlgorithm(header.nVersion, x25x::Algorithm::SCRYPT);

    uint256 hash = x25x::HashBlockHeader(header, x25x::Algorithm::SCRYPT);

    // Hash should not be zero
    BOOST_CHECK(!hash.IsNull());

    // Same input should produce same hash
    uint256 hash2 = x25x::HashBlockHeader(header, x25x::Algorithm::SCRYPT);
    BOOST_CHECK(hash == hash2);

    // Should be different from SHA256D
    uint256 sha256hash = x25x::HashBlockHeader(header, x25x::Algorithm::SHA256D);
    BOOST_CHECK(hash != sha256hash);
}

BOOST_AUTO_TEST_CASE(ethash_hash_test)
{
    CBlockHeader header = CreateTestHeader();
    header.nVersion = x25x::SetBlockAlgorithm(header.nVersion, x25x::Algorithm::ETHASH);

    // Ethash requires block height for epoch calculation
    uint256 hash = x25x::HashBlockHeader(header, x25x::Algorithm::ETHASH, 1000);

    // Hash should not be zero
    BOOST_CHECK(!hash.IsNull());

    // Same input should produce same hash
    uint256 hash2 = x25x::HashBlockHeader(header, x25x::Algorithm::ETHASH, 1000);
    BOOST_CHECK(hash == hash2);
}

/**
 * A RandomX verifier that has not been keyed must refuse to answer, not guess.
 *
 * hash::RandomX() used to initialise a context with an ALL-ZERO key whenever
 * none existed, and return a hash computed against that wrong dataset. Callers
 * compared it to the PoW target as though it were authoritative. On mainnet that
 * rejected a valid block at startup -- block index entries are checked before
 * anything keys RandomX with the genesis hash -- and the node refused to start
 * with "Error loading block database", crash-looping until it was stopped.
 *
 * This cannot be caught on regtest: powLimit there is 0x207fffff, so even a hash
 * from the wrong dataset clears the target and the block still validates. It
 * needs either real difficulty or a direct check like this one.
 *
 * The correct key is the genesis hash, owned by EnsureRandomXInitializedForPow()
 * in validation.cpp and reached via CheckProofOfWorkRandomX().
 */
BOOST_AUTO_TEST_CASE(randomx_unkeyed_verifier_fails_closed)
{
    // Only meaningful while the process-wide context is unkeyed. If an earlier
    // test in this binary initialised it, say so rather than assert something
    // this test is not actually exercising.
    if (node::GetRandomXMiner().IsInitialized()) {
        BOOST_TEST_MESSAGE("RandomX context already keyed by an earlier test; "
                           "skipping the unkeyed fail-closed check");
        return;
    }

    CBlockHeader header;
    header.nVersion = x25x::SetBlockAlgorithm(0x20000000, x25x::Algorithm::RANDOMX);
    header.hashPrevBlock = uint256::ONE;
    header.hashMerkleRoot = uint256::ONE;
    header.nTime = 1700000000;
    header.nBits = 0x1e242554;
    header.nNonce = 12345;

    const uint256 hash = x25x::hash::RandomX(header);

    // A null hash is the refusal. Anything else is a confident answer computed
    // against a key we never established -- the exact failure this guards.
    BOOST_CHECK_MESSAGE(hash.IsNull(),
        "unkeyed RandomX verifier returned a hash instead of failing closed");

    // And it must not have silently keyed itself along the way.
    BOOST_CHECK(!node::GetRandomXMiner().IsInitialized());
}

BOOST_AUTO_TEST_CASE(randomx_hash_test)
{
    CBlockHeader header = CreateTestHeader();
    header.nVersion = x25x::SetBlockAlgorithm(header.nVersion, x25x::Algorithm::RANDOMX);

    // Key the context explicitly. This test previously asserted that hashing
    // WITHOUT keying still returned a hash -- encoding as correct the behaviour
    // that made a node reject a valid block and refuse to start. Hashing against
    // an unestablished key is the bug, not the baseline; see
    // randomx_unkeyed_verifier_fails_closed below.
    node::RandomXMiner& miner = node::GetRandomXMiner();
    if (!miner.IsInitialized()) {
        const uint256 key = uint256::ONE; // any fixed key; consensus uses genesis
        BOOST_REQUIRE(miner.Initialize(key.data(), 32, node::RandomXMiner::Mode::LIGHT, false));
    }

    uint256 hash = x25x::HashBlockHeader(header, x25x::Algorithm::RANDOMX);
    BOOST_CHECK(!hash.IsNull());

    // Same input and same key must produce the same hash
    uint256 hash2 = x25x::HashBlockHeader(header, x25x::Algorithm::RANDOMX);
    BOOST_CHECK(hash == hash2);
}

BOOST_AUTO_TEST_CASE(x11_hash_test)
{
    CBlockHeader header = CreateTestHeader();
    header.nVersion = x25x::SetBlockAlgorithm(header.nVersion, x25x::Algorithm::X11);

    uint256 hash = x25x::HashBlockHeader(header, x25x::Algorithm::X11);

    // Hash should not be zero
    BOOST_CHECK(!hash.IsNull());

    // Same input should produce same hash
    uint256 hash2 = x25x::HashBlockHeader(header, x25x::Algorithm::X11);
    BOOST_CHECK(hash == hash2);

    // Should be different from other algorithms
    uint256 sha256hash = x25x::HashBlockHeader(header, x25x::Algorithm::SHA256D);
    BOOST_CHECK(hash != sha256hash);
}

BOOST_AUTO_TEST_CASE(kheavyhash_hash_test)
{
    CBlockHeader header = CreateTestHeader();
    header.nVersion = x25x::SetBlockAlgorithm(header.nVersion, x25x::Algorithm::KHEAVYHASH);

    uint256 hash = x25x::HashBlockHeader(header, x25x::Algorithm::KHEAVYHASH);

    // Hash should not be zero
    BOOST_CHECK(!hash.IsNull());

    // Same input should produce same hash
    uint256 hash2 = x25x::HashBlockHeader(header, x25x::Algorithm::KHEAVYHASH);
    BOOST_CHECK(hash == hash2);
}

BOOST_AUTO_TEST_CASE(all_algorithms_different_output)
{
    // Test that all algorithms produce different hashes for the same input
    CBlockHeader header = CreateTestHeader();

    std::vector<x25x::Algorithm> algos = {
        x25x::Algorithm::SHA256D,
        x25x::Algorithm::SCRYPT,
        x25x::Algorithm::X11,
        x25x::Algorithm::KHEAVYHASH
        // Note: Ethash and RandomX require special initialization
    };

    std::vector<uint256> hashes;
    for (auto algo : algos) {
        header.nVersion = x25x::SetBlockAlgorithm(header.nVersion, algo);
        uint256 hash = x25x::HashBlockHeader(header, algo);
        BOOST_CHECK(!hash.IsNull());
        hashes.push_back(hash);
    }

    // All hashes should be unique
    for (size_t i = 0; i < hashes.size(); i++) {
        for (size_t j = i + 1; j < hashes.size(); j++) {
            BOOST_CHECK(hashes[i] != hashes[j]);
        }
    }
}

BOOST_AUTO_TEST_CASE(hash_raw_data_test)
{
    // Test hashing raw data directly
    const unsigned char testData[] = "WATTx X25X Multi-Algorithm Test";
    size_t dataLen = sizeof(testData) - 1;

    // SHA256D
    uint256 sha256d = x25x::hash::SHA256D(testData, dataLen);
    BOOST_CHECK(!sha256d.IsNull());

    // Scrypt
    uint256 scrypt = x25x::hash::Scrypt(testData, dataLen);
    BOOST_CHECK(!scrypt.IsNull());

    // X11
    uint256 x11 = x25x::hash::X11(testData, dataLen);
    BOOST_CHECK(!x11.IsNull());

    // kHeavyHash
    uint256 kheavy = x25x::hash::KHeavyHash(testData, dataLen);
    BOOST_CHECK(!kheavy.IsNull());

    // All should be different
    BOOST_CHECK(sha256d != scrypt);
    BOOST_CHECK(sha256d != x11);
    BOOST_CHECK(sha256d != kheavy);
    BOOST_CHECK(scrypt != x11);
    BOOST_CHECK(scrypt != kheavy);
    BOOST_CHECK(x11 != kheavy);
}


/**
 * An algorithm without a header-provable proof of work must be UNMINEABLE, not
 * silently verified with some other algorithm's hash.
 *
 * EQUIHASH and GHOSTRIDER used to fall through a switch into hash::SHA256D.
 * EQUIHASH is enabled, so a block could declare it in nVersion and be accepted
 * on a plain double-SHA256 hash while paying EQUIHASH's difficulty -- a
 * completely separate retarget chain. An attacker mines with whichever of the
 * two targets is easier. On a chain where sha256d difficulty comes from Bitcoin
 * merged mining and equihash difficulty from a far smaller parent, that is
 * blocks for a tiny fraction of the honest cost, which is what makes reorgs --
 * and double spends -- affordable.
 */
BOOST_AUTO_TEST_CASE(unprovable_algorithms_do_not_hash_as_sha256d)
{
    CBlockHeader header = CreateTestHeader();

    const uint256 sha256d = x25x::HashBlockHeader(header, x25x::Algorithm::SHA256D);

    // Algorithm::INVALID is excluded deliberately: it is HashBlockHeader's
    // "detect the algorithm from the header" sentinel, not an algorithm.
    for (const auto algo : {x25x::Algorithm::EQUIHASH,
                            x25x::Algorithm::GHOSTRIDER}) {
        const uint256 h = x25x::HashBlockHeader(header, algo);
        BOOST_CHECK_MESSAGE(h != sha256d,
            "algorithm " << static_cast<int>(algo) << " hashes as SHA256D -- "
            "its blocks can be mined with the wrong algorithm's work");
        // All-ones cannot be below any valid target, so the algorithm is unmineable.
        BOOST_CHECK(h == ArithToUint256(~arith_uint256()));
    }
}

/**
 * An UNKNOWN algorithm id decodes to SHA256D, and that is fine -- but only
 * because both the hash and the difficulty lookup go through GetBlockAlgorithm,
 * so such a block behaves as a sha256d block in every respect. Pinned here
 * because the danger is the two ever disagreeing: work charged at one
 * algorithm's difficulty and proved with another's hash is the whole bug.
 */
BOOST_AUTO_TEST_CASE(unknown_algorithm_id_is_consistently_sha256d)
{
    CBlockHeader header = CreateTestHeader();
    // 0x7E is not in the algorithm table.
    header.nVersion = (header.nVersion & ~0xFF00) | (0x7E << 8);

    BOOST_CHECK(x25x::GetBlockAlgorithm(header.nVersion) == x25x::Algorithm::SHA256D);
    BOOST_CHECK(x25x::HashBlockHeader(header, x25x::GetBlockAlgorithm(header.nVersion)) ==
                x25x::hash::SHA256D(header));
}

BOOST_AUTO_TEST_CASE(solo_proof_of_work_is_declared_per_algorithm)
{
    // Provable from a bare header.
    BOOST_CHECK(x25x::HasSoloProofOfWork(x25x::Algorithm::SHA256D));
    BOOST_CHECK(x25x::HasSoloProofOfWork(x25x::Algorithm::SCRYPT));
    BOOST_CHECK(x25x::HasSoloProofOfWork(x25x::Algorithm::ETHASH));
    BOOST_CHECK(x25x::HasSoloProofOfWork(x25x::Algorithm::RANDOMX));
    BOOST_CHECK(x25x::HasSoloProofOfWork(x25x::Algorithm::X11));
    BOOST_CHECK(x25x::HasSoloProofOfWork(x25x::Algorithm::KHEAVYHASH));

    // Not provable: equihash needs a Wagner solution the header cannot carry,
    // and ghostrider has no implementation. Both remain ENABLED for merged
    // mining, where the parent block supplies the proof -- being enabled is not
    // the same as being solo-mineable, and conflating the two is the bug.
    BOOST_CHECK(!x25x::HasSoloProofOfWork(x25x::Algorithm::EQUIHASH));
    BOOST_CHECK(!x25x::HasSoloProofOfWork(x25x::Algorithm::GHOSTRIDER));
    BOOST_CHECK(!x25x::HasSoloProofOfWork(x25x::Algorithm::INVALID));

    BOOST_CHECK(x25x::IsAlgorithmEnabled(x25x::Algorithm::EQUIHASH));
}

/**
 * The end-to-end form of the bug: a header carrying a valid SHA256D proof, but
 * declaring EQUIHASH, must be rejected.
 */
BOOST_AUTO_TEST_CASE(sha256d_work_cannot_satisfy_an_equihash_block)
{
    const Consensus::Params& params = Params().GetConsensus();

    // Model the attacker exactly: declare EQUIHASH in the version FIRST, then
    // grind SHA256D over that header. (Grinding as SHA256D and relabelling
    // afterwards would not be the attack -- changing nVersion changes the header
    // bytes, so it changes the hash.)
    CBlockHeader header = CreateTestHeader();
    header.nVersion = x25x::SetBlockAlgorithm(header.nVersion, x25x::Algorithm::EQUIHASH);
    header.nBits = UintToArith256(params.powLimit).GetCompact();

    arith_uint256 target;
    target.SetCompact(header.nBits);

    bool found_sha256d_proof = false;
    for (uint32_t n = 0; n < 200000; ++n) {
        header.nNonce = n;
        if (UintToArith256(x25x::hash::SHA256D(header)) <= target) {
            found_sha256d_proof = true;
            break;
        }
    }
    BOOST_REQUIRE_MESSAGE(found_sha256d_proof,
        "could not grind a SHA256D proof at powLimit -- test cannot conclude");

    // The header now carries genuine SHA256D work and declares EQUIHASH, whose
    // difficulty is a separate retarget chain. Consensus must refuse it.
    BOOST_CHECK_MESSAGE(!x25x::CheckProofOfWork(header, header.nBits, params),
        "SHA256D work was accepted for a block declaring EQUIHASH -- an attacker "
        "can mine against whichever algorithm's difficulty is cheapest");
}

BOOST_AUTO_TEST_SUITE_END()
