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

    const int64_t nTargetSpacing = params.nPowTargetSpacing;
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    
    // Get current time and time since last block
    int64_t nCurrentTime = GetTime();
    int64_t nTimeSinceLastBlock = nCurrentTime - pindexLast->GetBlockTime();
    
    // Calculate actual block spacing
    int64_t nActualSpacing = pindexLast->GetBlockTime() - pindexLast->pprev->GetBlockTime();
    
    // Basic safety checks
    const int64_t MIN_BLOCK_TIME = 1;  // Minimum 1 second
    const int64_t MAX_BLOCK_TIME = nTargetSpacing * 100;  // Maximum 100x target time
    nActualSpacing = std::max<int64_t>(nActualSpacing, MIN_BLOCK_TIME);
    nActualSpacing = std::min<int64_t>(nActualSpacing, MAX_BLOCK_TIME);

    // =============================================================
    // Emergency handling - simplified and effective
    // =============================================================
    
    // Extreme emergency: no new block for over 20x target time
    if (nTimeSinceLastBlock > 20 * nTargetSpacing) {
        LogPrintf("EMERGENCY: No block for %ds, resetting to minimum difficulty\n", nTimeSinceLastBlock);
        return bnPowLimit.GetCompact();
    }
    
    // Critical delay: last block spacing over 10x target time
    if (nActualSpacing > 10 * nTargetSpacing) {
        LogPrintf("CRITICAL: Block spacing %ds (target %ds), emergency difficulty reduction\n", 
                 nActualSpacing, nTargetSpacing);
        
        arith_uint256 bnEmergency;
        bnEmergency.SetCompact(pindexLast->nBits);
        
        // Adjust based on delay severity
        int emergencyFactor = std::min(nActualSpacing / nTargetSpacing, (int64_t)50);
        bnEmergency *= emergencyFactor;
        
        if (bnEmergency > bnPowLimit) {
            bnEmergency = bnPowLimit;
        }
        
        LogPrintf("Emergency adjustment: %dx difficulty reduction\n", emergencyFactor);
        return bnEmergency.GetCompact();
    }

    // =============================================================
    // Analyze recent block history
    // =============================================================
    
    const int ANALYSIS_WINDOW = 12;  // Analyze last 12 blocks
    std::vector<int64_t> recentSpacings;
    int64_t totalSpacing = 0;
    
    const CBlockIndex* pindex = pindexLast;
    for (int i = 0; i < ANALYSIS_WINDOW && pindex->pprev; i++) {
        int64_t spacing = pindex->GetBlockTime() - pindex->pprev->GetBlockTime();
        spacing = std::max<int64_t>(spacing, MIN_BLOCK_TIME);
        spacing = std::min<int64_t>(spacing, MAX_BLOCK_TIME);
        
        recentSpacings.push_back(spacing);
        totalSpacing += spacing;
        pindex = pindex->pprev;
    }
    
    if (recentSpacings.empty()) {
        // If no historical data, use current spacing
        recentSpacings.push_back(nActualSpacing);
        totalSpacing = nActualSpacing;
    }
    
    int64_t averageSpacing = totalSpacing / recentSpacings.size();
    
    // Calculate average time for last 6 blocks (short-term trend)
    int64_t shortTermAverage = 0;
    int shortTermCount = std::min(6, (int)recentSpacings.size());
    for (int i = 0; i < shortTermCount; i++) {
        shortTermAverage += recentSpacings[i];
    }
    shortTermAverage /= shortTermCount;

    // =============================================================
    // Attack detection - simplified but effective
    // =============================================================
    
    bool bPossibleAttack = false;
    
    // Detect fast-slow alternating pattern (hashrate switching attack)
    if (recentSpacings.size() >= 6) {
        int fastBlocks = 0;
        int slowBlocks = 0;
        
        for (int i = 0; i < 6; i++) {
            if (recentSpacings[i] < nTargetSpacing / 3) fastBlocks++;
            if (recentSpacings[i] > nTargetSpacing * 3) slowBlocks++;
        }
        
        // If both very fast and very slow blocks exist, possible attack
        if (fastBlocks >= 2 && slowBlocks >= 2) {
            bPossibleAttack = true;
            LogPrintf("Possible hashrate switching attack detected (fast:%d, slow:%d)\n", 
                     fastBlocks, slowBlocks);
        }
    }

    // =============================================================
    // Difficulty adjustment calculation
    // =============================================================
    
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    
    // Choose which time interval to use for adjustment
    int64_t adjustmentSpacing;
    
    if (bPossibleAttack) {
        // Use long-term average during attack to reduce volatility
        adjustmentSpacing = averageSpacing;
        LogPrintf("Attack detected, using long-term average: %ds\n", adjustmentSpacing);
    } else {
        // Use short-term average for faster response in normal conditions
        adjustmentSpacing = shortTermAverage;
    }
    
    // Basic adjustment formula: new_difficulty = old_difficulty * target_time / actual_time
    bnNew *= nTargetSpacing;
    bnNew /= adjustmentSpacing;
    
    // =============================================================
    // Adjustment limits - more reasonable ranges
    // =============================================================
    
    arith_uint256 bnPrevious;
    bnPrevious.SetCompact(pindexLast->nBits);
    
    // Set adjustment limits based on conditions
    int maxIncrease, maxDecrease;
    
    if (bPossibleAttack) {
        // More conservative during attack
        maxIncrease = 25;  // Max 25% increase
        maxDecrease = 25;  // Max 25% decrease
    } else if (nTimeSinceLastBlock > 3 * nTargetSpacing) {
        // Allow larger adjustments when no new blocks for long time
        maxIncrease = 100; // Max 100% increase
        maxDecrease = 75;  // Max 75% decrease
    } else {
        // Normal conditions
        maxIncrease = 50;  // Max 50% increase
        maxDecrease = 50;  // Max 50% decrease
    }
    
    // Apply limits
    arith_uint256 bnMaxIncrease = bnPrevious * (100 - maxIncrease) / 100;  // Difficulty increase = bits decrease
    arith_uint256 bnMaxDecrease = bnPrevious * (100 + maxDecrease) / 100;  // Difficulty decrease = bits increase
    
    if (bnNew < bnMaxIncrease) {
        bnNew = bnMaxIncrease;
        LogPrintf("Difficulty increase capped at %d%%\n", maxIncrease);
    } else if (bnNew > bnMaxDecrease) {
        bnNew = bnMaxDecrease;
        LogPrintf("Difficulty decrease capped at %d%%\n", maxDecrease);
    }
    
    // Ensure not exceeding minimum difficulty
    if (bnNew > bnPowLimit) {
        bnNew = bnPowLimit;
    }
    
    // =============================================================
    // Logging
    // =============================================================
    
    double changePercent = ((double)bnNew.GetCompact() / (double)pindexLast->nBits - 1.0) * 100.0;
    
    LogPrintf("Improved Difficulty Adjustment:\n");
    LogPrintf("  Previous: %08x, New: %08x (%.2f%% change)\n", 
             pindexLast->nBits, bnNew.GetCompact(), changePercent);
    LogPrintf("  Spacing: actual=%ds, short_avg=%ds, long_avg=%ds, target=%ds\n",
             nActualSpacing, shortTermAverage, averageSpacing, nTargetSpacing);
    LogPrintf("  Time since last: %ds, Attack detected: %s\n",
             nTimeSinceLastBlock, bPossibleAttack ? "YES" : "NO");
    LogPrintf("  Max adjustment: +%d%% -%d%%\n", maxIncrease, maxDecrease);
    
    // Warning system
    double hashrateChange = (double)nTargetSpacing / (double)shortTermAverage;
    if (hashrateChange > 3.0 || hashrateChange < 0.33) {
        LogPrintf("ALERT: Significant hashrate change detected (%.2fx)\n", hashrateChange);
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
