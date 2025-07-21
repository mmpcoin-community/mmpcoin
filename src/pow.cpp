// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "auxpow.h"
#include "arith_uint256.h"
#include "chain.h"
#include "dogecoin.h"
#include "primitives/block.h"
#include "uint256.h"
#include "util.h"

// Determine if the for the given block, a min difficulty setting applies
bool AllowMinDifficultyForBlock(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    // check if the chain allows minimum difficulty blocks
    if (!params.fPowAllowMinDifficultyBlocks)
        return false;

    // mmpcoin: Magic number at which reset protocol switches
    // check if we allow minimum difficulty at this block-height
    if ((unsigned)pindexLast->nHeight < params.nHeightEffective) {
        return false;
    }

    // Allow for a minimum block time if the elapsed time > 2*nTargetSpacing
    return (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2);
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{

    if (pindexLast->nHeight + 1 >= 155550) {
        // Use new improved algorithm
        return GetNextWorkRequiredNewAlgo(pindexLast, pblock, params);
    } else {
        // Use old algorithm
        return GetNextWorkRequiredOldAlgo(pindexLast, pblock, params);
    }

}

unsigned int GetNextWorkRequiredNewAlgo(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{

    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Genesis block or early blocks safety check
    if (pindexLast == NULL || pindexLast->pprev == NULL) {
        return nProofOfWorkLimit;
    }
    
    if (pindexLast->nHeight >= 155550 && pindexLast->nHeight < 155650) {
        return nProofOfWorkLimit;
    }

    // 🚀 Improved Digishield V3 Algorithm - Better handling of hashrate volatility
    // Main improvements:
    // 1. Enhanced hashrate surge handling
    // 2. Smarter attack detection
    // 3. Adaptive parameter adjustment

    const int64_t nTargetSpacing = params.nPowTargetSpacing;
    int64_t nActualSpacing = pindexLast->GetBlockTime() - pindexLast->pprev->GetBlockTime();

    // Time-related variables
    int64_t nCurrentTime = GetTime();
    int64_t nTimeSinceLastBlock = nCurrentTime - pindexLast->GetBlockTime();

    // 🛡️ Enhanced security checks
    const int64_t MAX_FUTURE_TIME = 2 * 60 * 60;
    const int64_t MIN_BLOCK_TIME = nTargetSpacing / 20; // 5% of target time

    // Timestamp validation
    if (pindexLast->GetBlockTime() > nCurrentTime + MAX_FUTURE_TIME) {
        LogPrintf("Warning: Block timestamp too far in future\n");
        nTimeSinceLastBlock = nCurrentTime - pindexLast->GetMedianTimePast();
    }

    nActualSpacing = std::max<int64_t>(nActualSpacing, MIN_BLOCK_TIME);

    // 🔍 Enhanced historical analysis (extended to 24 blocks)
    const int SECURITY_WINDOW = 24;
    const int SHORT_WINDOW = 6;
    std::vector<int64_t> recentSpacings;
    int64_t nLongAverage = 0;
    int64_t nShortAverage = 0;

    const CBlockIndex* pindex = pindexLast;
    for (int i = 0; i < SECURITY_WINDOW && pindex->pprev; i++) {
        int64_t spacing = pindex->GetBlockTime() - pindex->pprev->GetBlockTime();
        spacing = std::max<int64_t>(spacing, MIN_BLOCK_TIME);
        spacing = std::min<int64_t>(spacing, nTargetSpacing * 20);
        
        recentSpacings.push_back(spacing);
        nLongAverage += spacing;
        
        if (i < SHORT_WINDOW) {
            nShortAverage += spacing;
        }
        
        pindex = pindex->pprev;
    }

    if (!recentSpacings.empty()) {
        nLongAverage /= recentSpacings.size();
        nShortAverage /= std::min((int)recentSpacings.size(), SHORT_WINDOW);
    }

    // 🎯 Hashrate trend analysis
    double hashrateTrend = 0;
    if (nLongAverage > 0) {
        hashrateTrend = (double)nShortAverage / (double)nLongAverage;
    }

    // 🛡️ Smart attack detection
    bool bSuspiciousPattern = false;
    bool bHashrateManipulation = false;
    int volatilityScore = 0;

    if (recentSpacings.size() >= 12) {
        // Calculate volatility score
        for (size_t i = 1; i < recentSpacings.size(); i++) {
            double change = (double)recentSpacings[i] / (double)recentSpacings[i-1];
            if (change > 3.0 || change < 0.33) {
                volatilityScore++;
            }
        }
        
        // Detect hashrate manipulation patterns
        int fastBlocks = 0, slowBlocks = 0;
        for (size_t i = 0; i < 6 && i < recentSpacings.size(); i++) {
            if (recentSpacings[i] < nTargetSpacing / 2) fastBlocks++;
            if (recentSpacings[i] > nTargetSpacing * 3) slowBlocks++;
        }
        
        // Fast-slow alternation might be hashrate switching attack
        if (fastBlocks >= 2 && slowBlocks >= 2) {
            bHashrateManipulation = true;
            LogPrintf("Warning: Possible hashrate switching attack detected\n");
        }
        
        // High volatility indicates anomaly
        if (volatilityScore > (int)(recentSpacings.size() / 3)) {
            bSuspiciousPattern = true;
            LogPrintf("Warning: High volatility detected (score: %d)\n", volatilityScore);
        }
    }

    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);

    // 🚀 Improved multi-level recovery mechanism
    // Level 1: Extreme emergency
    if (nActualSpacing > 30 * nTargetSpacing || nTimeSinceLastBlock > 30 * nTargetSpacing) {
        LogPrintf("CRITICAL: Level 1 emergency activated\n");
        if (bHashrateManipulation) {
            // Even with attack detected, ensure network continues
            arith_uint256 bnEmergency;
            bnEmergency.SetCompact(pindexLast->nBits);
            bnEmergency *= 10; // 90% reduction
            if (bnEmergency > bnPowLimit) bnEmergency = bnPowLimit;
            return bnEmergency.GetCompact();
        }
        return bnPowLimit.GetCompact();
    }

    // Level 2-4: Dynamic adjustment based on trends
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);

    int consecutiveFastBlocks = 0;

    // 🎯 Choose adjustment strategy based on hashrate trend
    if (hashrateTrend < 0.5 && nTimeSinceLastBlock > 3 * nTargetSpacing) {
        // Hashrate dropping rapidly
        LogPrintf("Hashrate dropping rapidly (trend: %.2f)\n", hashrateTrend);
        int reductionPercent = 40 + (int)((0.5 - hashrateTrend) * 60);
        reductionPercent = std::min(reductionPercent, 80);
        
        if (bHashrateManipulation) {
            reductionPercent = std::min(reductionPercent, 50);
        }
        
        bnNew *= (100 + reductionPercent);
        bnNew /= 100;
    } 
    else if (hashrateTrend > 2.0 && nActualSpacing < nTargetSpacing / 2) {
        // 🔥 Hashrate rising rapidly - this is the weakness of original algorithm
        LogPrintf("Hashrate rising rapidly (trend: %.2f)\n", hashrateTrend);
        
        // Determine adjustment magnitude based on trend strength
        int increasePercent = 30 + (int)((hashrateTrend - 2.0) * 20);
        increasePercent = std::min(increasePercent, 100); // Maximum double
        
        // If continuous fast blocks, increase adjustment
        consecutiveFastBlocks = 0;
        for (size_t i = 0; i < std::min(size_t(6), recentSpacings.size()); i++) {
            if (recentSpacings[i] < nTargetSpacing / 2) {
                consecutiveFastBlocks++;
            }
        }
        
        if (consecutiveFastBlocks >= 4) {
            increasePercent = std::min(increasePercent + 20, 150);
            LogPrintf("Consecutive fast blocks detected, aggressive adjustment\n");
        }
        
        bnNew *= 100;
        bnNew /= (100 + increasePercent);
    }
    else {
        // Normal Digishield V3 adjustment
        bnNew *= nActualSpacing;
        bnNew /= nTargetSpacing;
    }

    // 🛡️ Adaptive adjustment limits
    int maxAdjustmentPercent = 25; // Base limit

    // Dynamically adjust limits based on network state
    if (volatilityScore < 2 && !bHashrateManipulation) {
        // Network stable, allow larger adjustments
        maxAdjustmentPercent = 40;
    } else if (bHashrateManipulation) {
        // Attack detected, tighten limits
        maxAdjustmentPercent = 15;
    } else if (volatilityScore > 5) {
        // High volatility, conservative adjustment
        maxAdjustmentPercent = 20;
    }

    // Special case overrides
    if (nTimeSinceLastBlock > 10 * nTargetSpacing) {
        // Long time without blocks, relax limits
        maxAdjustmentPercent = std::max(maxAdjustmentPercent, 60);
    } else if (nActualSpacing < nTargetSpacing / 3 && consecutiveFastBlocks >= 3) {
        // Continuous fast blocks, allow significant difficulty increase
        maxAdjustmentPercent = std::max(maxAdjustmentPercent, 80);
    }

    // Apply adjustment limits
    arith_uint256 bnPrevious;
    bnPrevious.SetCompact(pindexLast->nBits);

    arith_uint256 bnUpper = bnPrevious * (100 + maxAdjustmentPercent) / 100;
    arith_uint256 bnLower = bnPrevious * (100 - maxAdjustmentPercent) / 100;

    if (bnNew > bnUpper) {
        bnNew = bnUpper;
        LogPrintf("Difficulty increase capped at %d%%\n", maxAdjustmentPercent);
    } else if (bnNew < bnLower) {
        bnNew = bnLower;
        LogPrintf("Difficulty decrease capped at %d%%\n", maxAdjustmentPercent);
    }

    // Ensure not exceeding minimum difficulty
    if (bnNew > bnPowLimit) {
        bnNew = bnPowLimit;
    }

    // 📊 Enhanced logging
    LogPrintf("Enhanced Digishield V3 Adjustment:\n");
    LogPrintf("  Previous: %08x, New: %08x (%.2f%% change)\n", 
            pindexLast->nBits, bnNew.GetCompact(),
            ((double)bnNew.GetCompact() / pindexLast->nBits - 1) * 100);
    LogPrintf("  Spacing: actual=%ds, target=%ds, since_last=%ds\n",
            nActualSpacing, nTargetSpacing, nTimeSinceLastBlock);
    LogPrintf("  Hashrate trend: %.2f, Volatility: %d, Max adjustment: %d%%\n",
            hashrateTrend, volatilityScore, maxAdjustmentPercent);
    LogPrintf("  Attack detection: Suspicious=%s, Manipulation=%s\n",
            bSuspiciousPattern ? "YES" : "NO",
            bHashrateManipulation ? "YES" : "NO");

    // 🚨 Alert system
    if (hashrateTrend > 5.0 || hashrateTrend < 0.2) {
        LogPrintf("ALERT: Extreme hashrate change detected (%.2fx)\n", hashrateTrend);
    }

    return bnNew.GetCompact();

}

unsigned int GetNextWorkRequiredOldAlgo(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    // mmpcoin: Special rules for minimum difficulty blocks with Digishield
    if (AllowDigishieldMinDifficultyForBlock(pindexLast, pblock, params))
    {
        // Special difficulty rule for testnet:
        // If the new block's timestamp is more than 2* nTargetSpacing minutes
        // then allow mining of a min-difficulty block.
        return nProofOfWorkLimit;
    }

    if (pindexLast->nHeight >= 145364 && pindexLast->nHeight < 145464) {
        return nProofOfWorkLimit;
    }

    // Only change once per difficulty adjustment interval
    // bool fNewDifficultyProtocol = (pindexLast->nHeight >= 145000);
    bool fNewDifficultyProtocol = (pindexLast->nHeight >= 145000 && pindexLast->nHeight < 145365);

    const int64_t difficultyAdjustmentInterval = fNewDifficultyProtocol
                                                ? 1
                                                : params.DifficultyAdjustmentInterval();
    if ((pindexLast->nHeight+1) % difficultyAdjustmentInterval != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Litecoin: This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    int blockstogoback = difficultyAdjustmentInterval-1;
    if ((pindexLast->nHeight+1) != difficultyAdjustmentInterval)
        blockstogoback = difficultyAdjustmentInterval;

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - blockstogoback;
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateDogecoinNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
