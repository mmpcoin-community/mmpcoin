// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2022 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1386325540, nBits=0x1e0ffff0, nNonce=99943, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "29/11/2024 MmpCoin started.";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
private:
    Consensus::Params digishieldConsensus;
    Consensus::Params auxpowConsensus;
    Consensus::Params minDifficultyConsensus;
public:
    CMainParams() {
        strNetworkID = "main";

        // Not used in MmpCoin
        consensus.nSubsidyHalvingInterval = 100000;

        consensus.nMajorityEnforceBlockUpgrade = 1500;
        consensus.nMajorityRejectBlockOutdated = 1900;
        consensus.nMajorityWindow = 2000;


        // // After deployments are activated we can change it
        // consensus.BIP34Hash = uint256S("0x00"); // unused for now.
        // consensus.BIP65Height = 99999999; 
        // consensus.BIP65Height = 99999999; 
        // consensus.BIP66Height = 99999999; 


        consensus.powLimit = uint256S("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 20;
        consensus.nPowTargetTimespan = 20 * 60; // pre-digishield: 20 minutes
        consensus.nPowTargetSpacing = 60; // 1 minute
        consensus.nCoinbaseMaturity = 90;
        consensus.fPowNoRetargeting = false;


        consensus.nRuleChangeActivationThreshold = 9576; // 95% of 10,080
        consensus.nMinerConfirmationWindow = 10080; // 60 * 24 * 7 = 10,080 blocks, or one week

        // consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        // consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        // consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP34].bit = 0;
        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP34].nStartTime = 1703462400;   // 2023-12-25 00:00:00
        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP34].nTimeout   = 1735084800;   // 2024-12-25 00:00:00

        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP66].bit = 1;
        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP66].nStartTime = 1703462400;   // 2023-12-25 00:00:00
        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP66].nTimeout   = 1735084800;   // 2024-12-25 18:00:00


        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP65].bit = 2;
        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP65].nStartTime = 1703462400;   // 2023-12-25 00:00:00
        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP65].nTimeout   = 1735084800;   // 2024-12-25 18:00:00


        // // Deployment of BIP68, BIP112, and BIP113.
        // // XXX: BIP heights and hashes all need to be updated to MmpCoin values
        // consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 3;
        // consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1703462400; // 2023-12-25 00:00:00
        // consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1735084800;   // 2024-12-25 18:00:00

        // // Deployment of SegWit (BIP141, BIP143, and BIP147)
        // consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 4;
        // consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1703462400; // 2023-12-25 00:00:00
        // consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1735084800;   // 2024-12-25 18:00:00

        // // The best chain should have at least this much work.
        // consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000003e3c33bc605e5d"); // 4,303,965

        // // By default assume that the signatures in ancestors of this block are valid.
        // consensus.defaultAssumeValid = uint256S("0x2c05ea6918e28ca2d216c6518940c8782c09bebfe705d792155465662e275351"); // 10000

        // AuxPoW parameters

        consensus.nAuxpowChainId = 0x00e6; // 320
        consensus.fStrictChainId = false;  // we set this to false as block is nonAuxPow

        consensus.fAllowLegacyBlocks = true;
        
        // We do not activate digishield in this consensus
        digishieldConsensus = consensus;

        digishieldConsensus.nHeightEffective = 0xFFFFFFFF; // like never

        digishieldConsensus.fSimplifiedRewards = true;
        digishieldConsensus.fDigishieldDifficultyCalculation = true;
        digishieldConsensus.nPowTargetTimespan = 60; // post-digishield: 1 minute
        digishieldConsensus.nCoinbaseMaturity = 240;

        // Not implementing digishield yet
        minDifficultyConsensus = digishieldConsensus;
        minDifficultyConsensus.nHeightEffective = std::numeric_limits<uint32_t>::max();;
        minDifficultyConsensus.fPowAllowDigishieldMinDifficultyBlocks = true;
        minDifficultyConsensus.fPowAllowMinDifficultyBlocks = true;

        // Not implementing AuxPow hardfork yet
        auxpowConsensus = digishieldConsensus;
        auxpowConsensus.nHeightEffective = std::numeric_limits<uint32_t>::max();
        auxpowConsensus.fAllowLegacyBlocks = false;

        // Assemble the binary search tree of consensus parameters
        pConsensusRoot = &digishieldConsensus;
        digishieldConsensus.pLeft = &consensus;
        digishieldConsensus.pRight = &auxpowConsensus;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xc0;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xc0;
        nDefaultPort = 10320;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1732866195, 2000076429, 0x1e0ffff0, 1, 88 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();
        digishieldConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;

        assert(consensus.hashGenesisBlock == uint256S("0x05de8a722d49871f48a9b8e52c72ce7ab76f68d8ebef21abd595a171d874c8c7"));
        assert(genesis.hashMerkleRoot == uint256S("0xd9b31d73546d5dbc8316d8d6b8e3c1c54b9cf8a5b399c17a71dece0e8c593261"));

        // Note that of those with the service bits flag, most only support a subset of possible options
        vSeeds.push_back(CDNSSeedData("mmpcoin.com", "seeder.mmpcoin.com", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,50);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,30);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,153);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x02)(0xfa)(0xca)(0xfd).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x02)(0xfa)(0xc3)(0x98).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        /*checkpointData = (CCheckpointData) {
                boost::assign::map_list_of
                        (      0, uint256S("0x1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691"))
                        ( 14000, uint256S("0x0f3bec6968ad87171063c28f696f133c0e4bdf3a0bd56d369be658367dd21ee9"))
        };

        chainTxData = ChainTxData{
                // Data as of block ed7d266dcbd8bb8af80f9ccb8deb3e18f9cc3f6972912680feeb37b090f8cee0 (height 4303965).
                // Tx estimate based on average between 2021-07-01 (3793538) and 2022-07-01 (4288126)
                1702700138, // * UNIX timestamp of last checkpoint block
                15423,   // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
                0.1        // * estimated number of transactions per second after checkpoint
        };*/

        checkpointData = (CCheckpointData) {
                boost::assign::map_list_of
                        (      0, uint256S("0x05de8a722d49871f48a9b8e52c72ce7ab76f68d8ebef21abd595a171d874c8c7"))
//                        (   1000, uint256S("0x35668ee4f0fc1334849813c8a8e583814e9b22bfe5dc5a2bd2ded2b3aeec6643"))
//                        (  10000, uint256S("0x2c05ea6918e28ca2d216c6518940c8782c09bebfe705d792155465662e275351"))
        };

        chainTxData = ChainTxData{
                // Data as of block ed7d266dcbd8bb8af80f9ccb8deb3e18f9cc3f6972912680feeb37b090f8cee0 (height 4303965).
                // Tx estimate based on average between 2021-07-01 (3793538) and 2022-07-01 (4288126)
                1732866195, // * UNIX timestamp of last checkpoint block
                0,   // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
                0        // * estimated number of transactions per second after checkpoint
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
private:
    Consensus::Params digishieldConsensus;
    Consensus::Params auxpowConsensus;
    Consensus::Params minDifficultyConsensus;
public:
    CTestNetParams() {
        strNetworkID = "test";

        consensus.nSubsidyHalvingInterval = 100000;

        consensus.nMajorityEnforceBlockUpgrade = 1500;
        consensus.nMajorityRejectBlockOutdated = 1900;
        consensus.nMajorityWindow = 2000;


        // After deployments are activated we can change it
        // consensus.BIP34Hash = uint256S("0x00"); // unused for now.
        // consensus.BIP65Height = 99999999;
        // consensus.BIP65Height = 99999999;
        // consensus.BIP66Height = 99999999;


        consensus.powLimit = uint256S("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 20;
        consensus.nPowTargetTimespan = 20 * 60; // pre-digishield: 4 hours
        consensus.nPowTargetSpacing = 60; // 1 minute
        consensus.nCoinbaseMaturity = 30;
        consensus.fPowNoRetargeting = false;


        consensus.nRuleChangeActivationThreshold = 9576; // 95% of 10,080
        consensus.nMinerConfirmationWindow = 10080; // 60 * 24 * 7 = 10,080 blocks, or one week

        // consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        // consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        // consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP34].bit = 0;
        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP34].nStartTime = 1703462400;   // 2023-12-25 00:00:00
        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP34].nTimeout   = 1735084800;   // 2024-12-25 00:00:00

        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP66].bit = 1;
        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP66].nStartTime = 1703462400;   // 2023-12-25 00:00:00
        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP66].nTimeout   = 1735084800;   // 2024-12-25 18:00:00


        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP65].bit = 2;
        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP65].nStartTime = 1703462400;   // 2023-12-25 00:00:00
        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP65].nTimeout   = 1735084800;   // 2024-12-25 18:00:00


        // // Deployment of BIP68, BIP112, and BIP113.
        // // XXX: BIP heights and hashes all need to be updated to MmpCoin values
        // consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 3;
        // consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1703462400; // 2023-12-25 00:00:00
        // consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1735084800;   // 2024-12-25 18:00:00

        // // Deployment of SegWit (BIP141, BIP143, and BIP147)
        // consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 4;
        // consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1703462400; // 2023-12-25 00:00:00
        // consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1735084800;   // 2024-12-25 18:00:00

        // // The best chain should have at least this much work.
        // consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000003e3c33bc605e5d"); // 4,303,965

        // // By default assume that the signatures in ancestors of this block are valid.
        // consensus.defaultAssumeValid = uint256S("0x2c05ea6918e28ca2d216c6518940c8782c09bebfe705d792155465662e275351"); // 10000

        // AuxPoW parameters
        consensus.nAuxpowChainId = 0x00e6; // 320 - Josh Wise!
        consensus.fStrictChainId = true;
        consensus.fAllowLegacyBlocks = true;

        // We do not activate digishield in this consensus
        digishieldConsensus = consensus;

        digishieldConsensus.nHeightEffective = 0xFFFFFFFF; // like never

        digishieldConsensus.fSimplifiedRewards = true;
        digishieldConsensus.fDigishieldDifficultyCalculation = true;
        digishieldConsensus.nPowTargetTimespan = 60; // post-digishield: 1 minute
        digishieldConsensus.nCoinbaseMaturity = 240;

        // Not implementing digishield yet
        minDifficultyConsensus = digishieldConsensus;
        minDifficultyConsensus.nHeightEffective = std::numeric_limits<uint32_t>::max();;
        minDifficultyConsensus.fPowAllowDigishieldMinDifficultyBlocks = true;
        minDifficultyConsensus.fPowAllowMinDifficultyBlocks = true;

        // Not implementing AuxPow hardfork yet
        auxpowConsensus = digishieldConsensus;
        auxpowConsensus.nHeightEffective = std::numeric_limits<uint32_t>::max();
        auxpowConsensus.fAllowLegacyBlocks = true;

        // Assemble the binary search tree of consensus parameters
        pConsensusRoot = &digishieldConsensus;
        digishieldConsensus.pLeft = &consensus;
        digishieldConsensus.pRight = &auxpowConsensus;

        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xc1;
        pchMessageStart[2] = 0xb7;
        pchMessageStart[3] = 0xdc;

        nDefaultPort = 10420;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1732866195, 542590, 0x1e0ffff0, 1, 88 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();
        digishieldConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;

        assert(consensus.hashGenesisBlock == uint256S("0x2bef638807102e42c3055778f1ecb7f262edf00c28fcce07c7984e902a89260c"));
        assert(genesis.hashMerkleRoot == uint256S("0xd9b31d73546d5dbc8316d8d6b8e3c1c54b9cf8a5b399c17a71dece0e8c593261"));

        // nodes with support for servicebits filtering should be at the top
        vSeeds.push_back(CDNSSeedData("mmpcoin.com", "testnetseed.mmpcoin.com", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,50);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,30);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,153);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x02)(0xfa)(0xca)(0xfd).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x02)(0xfa)(0xc3)(0x98).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = (CCheckpointData) {
                boost::assign::map_list_of
                        (      0, uint256S("0x2bef638807102e42c3055778f1ecb7f262edf00c28fcce07c7984e902a89260c"))
        };

        chainTxData = ChainTxData{
                // Data as of block ed7d266dcbd8bb8af80f9ccb8deb3e18f9cc3f6972912680feeb37b090f8cee0 (height 4303965).
                // Tx estimate based on average between 2021-07-01 (3793538) and 2022-07-01 (4288126)
                1732866195, // * UNIX timestamp of last checkpoint block
                0,   // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
                0        // * estimated number of transactions per second after checkpoint
        };
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
private:
    Consensus::Params digishieldConsensus;
    Consensus::Params auxpowConsensus;
    Consensus::Params minDifficultyConsensus;
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        // Not used in MmpCoin
        consensus.nSubsidyHalvingInterval = 100000;

        consensus.nMajorityEnforceBlockUpgrade = 1500;
        consensus.nMajorityRejectBlockOutdated = 1900;
        consensus.nMajorityWindow = 2000;


        // // After deployments are activated we can change it
        // consensus.BIP34Hash = uint256S("0x00"); // unused for now.
        // consensus.BIP65Height = 99999999;
        // consensus.BIP65Height = 99999999;
        // consensus.BIP66Height = 99999999;


        consensus.powLimit = uint256S("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 20;
        consensus.nPowTargetTimespan = 20 * 60; // pre-digishield: 4 hours
        consensus.nPowTargetSpacing = 60; // 1 minute
        consensus.nCoinbaseMaturity = 30;
        consensus.fPowNoRetargeting = false;


        consensus.nRuleChangeActivationThreshold = 9576; // 95% of 10,080
        consensus.nMinerConfirmationWindow = 10080; // 60 * 24 * 7 = 10,080 blocks, or one week

        // consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        // consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        // consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP34].bit = 0;
        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP34].nStartTime = 1703462400;   // 2023-12-25 00:00:00
        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP34].nTimeout   = 1735084800;   // 2024-12-25 00:00:00

        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP66].bit = 1;
        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP66].nStartTime = 1703462400;   // 2023-12-25 00:00:00
        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP66].nTimeout   = 1735084800;   // 2024-12-25 18:00:00


        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP65].bit = 2;
        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP65].nStartTime = 1703462400;   // 2023-12-25 00:00:00
        // consensus.vDeployments[Consensus::DEPLOYMENT_BIP65].nTimeout   = 1735084800;   // 2024-12-25 18:00:00


        // // Deployment of BIP68, BIP112, and BIP113.
        // // XXX: BIP heights and hashes all need to be updated to MmpCoin values
        // consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 3;
        // consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1703462400; // 2023-12-25 00:00:00
        // consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1735084800;   // 2024-12-25 18:00:00

        // // Deployment of SegWit (BIP141, BIP143, and BIP147)
        // consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 4;
        // consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1703462400; // 2023-12-25 00:00:00
        // consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1735084800;   // 2024-12-25 18:00:00

        // // The best chain should have at least this much work.
        // consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000003e3c33bc605e5d"); // 4,303,965

        // // By default assume that the signatures in ancestors of this block are valid.
        // consensus.defaultAssumeValid = uint256S("0x2c05ea6918e28ca2d216c6518940c8782c09bebfe705d792155465662e275351"); // 10000

        // AuxPoW parameters
        consensus.nAuxpowChainId = 0x00e6; // 320 - Josh Wise!
        consensus.fStrictChainId = true;
        consensus.fAllowLegacyBlocks = true;

        // We do not activate digishield in this consensus
        digishieldConsensus = consensus;

        digishieldConsensus.nHeightEffective = 0xFFFFFFFF; // like never

        digishieldConsensus.fSimplifiedRewards = true;
        digishieldConsensus.fDigishieldDifficultyCalculation = true;
        digishieldConsensus.nPowTargetTimespan = 60; // post-digishield: 1 minute
        digishieldConsensus.nCoinbaseMaturity = 240;

        // Not implementing digishield yet
        minDifficultyConsensus = digishieldConsensus;
        minDifficultyConsensus.nHeightEffective = std::numeric_limits<uint32_t>::max();;
        minDifficultyConsensus.fPowAllowDigishieldMinDifficultyBlocks = true;
        minDifficultyConsensus.fPowAllowMinDifficultyBlocks = true;

        // Not implementing AuxPow hardfork yet
        auxpowConsensus = digishieldConsensus;
        auxpowConsensus.nHeightEffective = std::numeric_limits<uint32_t>::max();
        auxpowConsensus.fAllowLegacyBlocks = false;

        // Assemble the binary search tree of consensus parameters
        pConsensusRoot = &digishieldConsensus;
        digishieldConsensus.pLeft = &consensus;
        digishieldConsensus.pRight = &auxpowConsensus;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xc0;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xc0;
        nDefaultPort = 10520;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1732866195, 0, 0x207fffff, 1, 88 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();
        digishieldConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;

        assert(consensus.hashGenesisBlock == uint256S("0x2c02e61349707b8e6ddc8dfe8889983167a35a0d20e0f212e82d426e021328ef"));
        assert(genesis.hashMerkleRoot == uint256S("0xd9b31d73546d5dbc8316d8d6b8e3c1c54b9cf8a5b399c17a71dece0e8c593261"));

        // nodes with support for servicebits filtering should be at the top
        vSeeds.push_back(CDNSSeedData("mmpcoin.com", "testnetseed.mmpcoin.com", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,50);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,30);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,153);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x02)(0xfa)(0xca)(0xfd).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x02)(0xfa)(0xc3)(0x98).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x2c02e61349707b8e6ddc8dfe8889983167a35a0d20e0f212e82d426e021328ef"))
        };

        chainTxData = ChainTxData{
            1732866195,
            0,
            0
        };
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

const Consensus::Params *Consensus::Params::GetConsensus(uint32_t nTargetHeight) const {
    if (nTargetHeight < this -> nHeightEffective && this -> pLeft != NULL) {
        return this -> pLeft -> GetConsensus(nTargetHeight);
    } else if (nTargetHeight > this -> nHeightEffective && this -> pRight != NULL) {
        const Consensus::Params *pCandidate = this -> pRight -> GetConsensus(nTargetHeight);
        if (pCandidate->nHeightEffective <= nTargetHeight) {
            return pCandidate;
        }
    }

    // No better match below the target height
    return this;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
