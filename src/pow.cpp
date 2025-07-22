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
#include <cmath>

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
    
    // Special handling for specific block range if needed
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
    const int64_t MIN_BLOCK_TIME = 1;
    const int64_t MAX_BLOCK_TIME = nTargetSpacing * 100;
    nActualSpacing = std::max<int64_t>(nActualSpacing, MIN_BLOCK_TIME);
    nActualSpacing = std::min<int64_t>(nActualSpacing, MAX_BLOCK_TIME);

    // =============================================================
    // Death spiral protection - prevent chain death from hashrate crash
    // =============================================================

    // Check for potential death spiral
    bool bDeathSpiralRisk = false;
    if (nTimeSinceLastBlock > 15 * nTargetSpacing) {  // Over 15 minutes without block
        LogPrintf("DEATH SPIRAL RISK: No block for %ds (%.1f minutes)\n", 
                 nTimeSinceLastBlock, (double)nTimeSinceLastBlock / 60.0);
        bDeathSpiralRisk = true;
    }

    // Extreme emergency: immediately reset to minimum difficulty
    if (bDeathSpiralRisk || nTimeSinceLastBlock > 30 * nTargetSpacing) {
        LogPrintf("DEATH SPIRAL PROTECTION: Resetting to minimum difficulty immediately\n");
        LogPrintf("Time since last block: %ds (%.1f minutes)\n", 
                 nTimeSinceLastBlock, (double)nTimeSinceLastBlock / 60.0);
        return bnPowLimit.GetCompact();
    }

    // =============================================================
    // Enhanced emergency handling with gradual recovery
    // =============================================================

    // Severe delay but not yet death spiral level
    if (nActualSpacing > 3 * nTargetSpacing || nTimeSinceLastBlock > 5 * nTargetSpacing) {
        LogPrintf("SEVERE DELAY: Block spacing %ds, time since last %ds\n", 
                 nActualSpacing, nTimeSinceLastBlock);
        
        arith_uint256 bnEmergency;
        bnEmergency.SetCompact(pindexLast->nBits);
        
        // Calculate emergency adjustment factor with reasonable cap
        int64_t delayFactor = std::max(nActualSpacing / nTargetSpacing, 
                                       nTimeSinceLastBlock / nTargetSpacing);
        int emergencyReduction = std::min(delayFactor, (int64_t)50);  // Max 50x reduction
        
        bnEmergency *= emergencyReduction;
        
        if (bnEmergency > bnPowLimit) {
            bnEmergency = bnPowLimit;
        }
        
        LogPrintf("Emergency difficulty reduction: %dx (capped at 50x)\n", emergencyReduction);
        LogPrintf("New emergency difficulty: %08x\n", bnEmergency.GetCompact());
        
        return bnEmergency.GetCompact();
    }

    // =============================================================
    // Analyze recent block history
    // =============================================================
    
    const int ANALYSIS_WINDOW = 8;  // Analyze last 8 blocks
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
        recentSpacings.push_back(nActualSpacing);
        totalSpacing = nActualSpacing;
    }
    
    int64_t averageSpacing = totalSpacing / recentSpacings.size();
    
    // Calculate short-term average (last 3 blocks)
    int64_t shortTermAverage = 0;
    int shortTermCount = std::min(3, (int)recentSpacings.size());
    for (int i = 0; i < shortTermCount; i++) {
        shortTermAverage += recentSpacings[i];
    }
    shortTermAverage /= shortTermCount;

    // =============================================================
    // Hashrate volatility protection
    // =============================================================

    // Check recent difficulty adjustment history
    bool bRecentLargeAdjustment = false;
    if (pindexLast->pprev && pindexLast->pprev->pprev) {
        double recentChange = (double)pindexLast->nBits / (double)pindexLast->pprev->nBits;
        if (recentChange > 2.0 || recentChange < 0.5) {
            bRecentLargeAdjustment = true;
            LogPrintf("Recent large difficulty adjustment detected (%.2fx change)\n", recentChange);
        }
    }

    // =============================================================
    // Attack detection - simplified but effective
    // =============================================================
    
    bool bPossibleAttack = false;
    if (recentSpacings.size() >= 4) {
        int fastBlocks = 0;
        int slowBlocks = 0;
        
        for (size_t i = 0; i < std::min(size_t(6), recentSpacings.size()); i++) {
            if (recentSpacings[i] < nTargetSpacing / 3) fastBlocks++;
            if (recentSpacings[i] > nTargetSpacing * 3) slowBlocks++;
        }
        
        // Fast-slow alternation might be hashrate switching attack
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
    
    if (bPossibleAttack || bRecentLargeAdjustment) {
        // Use long-term average during attack or after large adjustments
        adjustmentSpacing = averageSpacing;
        LogPrintf("Using long-term average due to %s: %ds\n", 
                 bPossibleAttack ? "attack detection" : "recent volatility", adjustmentSpacing);
    } else {
        // Use short-term average for faster response in normal conditions
        adjustmentSpacing = shortTermAverage;
    }
    
    // CORRECT formula: newBits = oldBits * actual_time / target_time
    bnNew *= adjustmentSpacing;
    bnNew /= nTargetSpacing;

    // =============================================================
    // Adaptive adjustment limits
    // =============================================================
    
    arith_uint256 bnPrevious;
    bnPrevious.SetCompact(pindexLast->nBits);
    
    // Set adjustment limits based on conditions
    int maxIncrease, maxDecrease;
    
    if (bPossibleAttack) {
        // Conservative during detected attack
        maxIncrease = 25;
        maxDecrease = 25;
        LogPrintf("Attack detected - using conservative limits (±25%%)\n");
    } else if (bRecentLargeAdjustment) {
        // Moderate limits after recent large adjustments to prevent oscillation
        maxIncrease = 40;
        maxDecrease = 40;
        LogPrintf("Recent volatility - using moderate limits (±40%%)\n");
    } else if (nTimeSinceLastBlock > 2 * nTargetSpacing) {
        // Allow larger adjustments when blocks are significantly delayed
        maxIncrease = 150;
        maxDecrease = 100;
        LogPrintf("Significant delay - using aggressive limits (+150%% -100%%)\n");
    } else {
        // Normal conditions
        maxIncrease = 75;
        maxDecrease = 75;
    }
    
    // Apply limits
    arith_uint256 bnMaxIncrease = bnPrevious * (100 - maxIncrease) / 100;  // Difficulty increase = bits decrease
    arith_uint256 bnMaxDecrease = bnPrevious * (100 + maxDecrease) / 100;  // Difficulty decrease = bits increase
    
    bool adjustmentCapped = false;
    if (bnNew < bnMaxIncrease) {
        bnNew = bnMaxIncrease;
        adjustmentCapped = true;
        LogPrintf("Difficulty increase capped at %d%% (blocks too fast)\n", maxIncrease);
    } else if (bnNew > bnMaxDecrease) {
        bnNew = bnMaxDecrease;
        adjustmentCapped = true;
        LogPrintf("Difficulty decrease capped at %d%% (blocks too slow)\n", maxDecrease);
    }
    
    // Ensure not exceeding minimum difficulty
    if (bnNew > bnPowLimit) {
        bnNew = bnPowLimit;
    }

    // =============================================================
    // Force minimum meaningful adjustment when needed
    // =============================================================
    
    // Calculate actual change percentage
    double actualChangePercent = ((double)bnNew.GetCompact() / (double)pindexLast->nBits - 1.0) * 100.0;
    
    // If change is too small and blocks are significantly off target, force larger change
    if (!bPossibleAttack && !bRecentLargeAdjustment && abs(actualChangePercent) < 1.0) {
        double targetDeviation = (double)adjustmentSpacing / (double)nTargetSpacing;
        
        if (targetDeviation < 0.6 || targetDeviation > 1.4) {  // More than 40% deviation
            LogPrintf("Forcing minimum 3%% adjustment due to significant timing deviation (%.1f%%)\n", 
                     (targetDeviation - 1.0) * 100.0);
            
            if (adjustmentSpacing < nTargetSpacing) {
                // Blocks too fast, increase difficulty by at least 3%
                bnNew = bnPrevious * 97 / 100;
            } else {
                // Blocks too slow, decrease difficulty by at least 3%
                bnNew = bnPrevious * 103 / 100;
            }
            
            if (bnNew > bnPowLimit) {
                bnNew = bnPowLimit;
            }
            
            actualChangePercent = ((double)bnNew.GetCompact() / (double)pindexLast->nBits - 1.0) * 100.0;
        }
    }

    // =============================================================
    // Enhanced logging and monitoring
    // =============================================================
    
    LogPrintf("Advanced Difficulty Adjustment Algorithm:\n");
    LogPrintf("  Previous: %08x, New: %08x (%.2f%% change)\n", 
             pindexLast->nBits, bnNew.GetCompact(), actualChangePercent);
    LogPrintf("  Spacing: actual=%ds, short_avg=%ds, long_avg=%ds, target=%ds\n",
             nActualSpacing, shortTermAverage, averageSpacing, nTargetSpacing);
    LogPrintf("  Time since last: %ds, Adjustment spacing used: %ds\n",
             nTimeSinceLastBlock, adjustmentSpacing);
    LogPrintf("  Conditions: Attack=%s, RecentVolatility=%s, Capped=%s\n",
             bPossibleAttack ? "YES" : "NO",
             bRecentLargeAdjustment ? "YES" : "NO", 
             adjustmentCapped ? "YES" : "NO");
    LogPrintf("  Max adjustment limits: +%d%% -%d%%\n", maxIncrease, maxDecrease);
    
    // Warning system for extreme conditions
    double hashrateChangeRatio = (double)nTargetSpacing / (double)shortTermAverage;
    if (hashrateChangeRatio > 3.0 || hashrateChangeRatio < 0.33) {
        LogPrintf("ALERT: Extreme hashrate change detected (%.2fx)\n", hashrateChangeRatio);
    }
    
    if (averageSpacing < nTargetSpacing / 3 || averageSpacing > nTargetSpacing * 3) {
        LogPrintf("WARNING: Average block time severely off target: %ds vs %ds\n", 
                 averageSpacing, nTargetSpacing);
    }

    // Network health indicator
    double networkStability = 1.0;
    if (recentSpacings.size() >= 4) {
        // Calculate coefficient of variation as stability metric
        double variance = 0;
        for (size_t i = 0; i < recentSpacings.size(); i++) {
            double deviation = (double)recentSpacings[i] - (double)averageSpacing;
            variance += deviation * deviation;
        }
        variance /= recentSpacings.size();
        double stddev = sqrt(variance);
        double cv = stddev / averageSpacing;  // Coefficient of variation
        
        networkStability = std::max(0.0, 1.0 - cv);  // Higher is more stable
        LogPrintf("  Network stability index: %.2f (1.0=stable, 0.0=volatile)\n", networkStability);
        
        if (networkStability < 0.5) {
            LogPrintf("WARNING: High network instability detected\n");
        }
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
