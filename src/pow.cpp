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

    if (pindexLast->nHeight + 1 >= 155549) {
        // Use new improved algorithm
        return GetNextWorkRequiredNewAlgo(pindexLast, pblock, params);
    } else {
        // Use old algorithm
        return GetNextWorkRequiredOldAlgo(pindexLast, pblock, params);
    }

}

unsigned int GetNextWorkRequiredNewAlgo(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params) {
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();
    
    // Genesis block or early blocks safety check
    if (pindexLast == NULL || pindexLast->pprev == NULL) {
        return nProofOfWorkLimit;
    }
    
    // Special handling for specific block range if needed
    if (pindexLast->nHeight < 155650) {
        return nProofOfWorkLimit;
    }

    const int64_t nTargetSpacing = params.nPowTargetSpacing;  // 60 seconds
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    
    // =============================================================
    // EMERGENCY PROTECTION - Always check first
    // =============================================================
    
    // Get current time vs last block time (chain death protection)
    int64_t nTimeSinceLastBlock = pblock->GetBlockTime() - pindexLast->GetBlockTime();
    
    // If more than 2 hours since last block, emergency difficulty reduction
    if (nTimeSinceLastBlock > 2 * 3600) {
        LogPrintf("EMERGENCY: Block time gap %d minutes, resetting to minimum difficulty\n", 
                  nTimeSinceLastBlock / 60);
        return bnPowLimit.GetCompact();
    }
    
    // If more than 30 minutes since last block, significant difficulty reduction
    if (nTimeSinceLastBlock > 30 * 60) {
        LogPrintf("CHAIN RECOVERY: Block time gap %d minutes, reducing difficulty\n", 
                  nTimeSinceLastBlock / 60);
        
        arith_uint256 bnEmergency;
        bnEmergency.SetCompact(pindexLast->nBits);
        
        // 根据延迟时间调整难度
        if (nTimeSinceLastBlock > 6 * 3600) {      // 6+ hours
            bnEmergency *= 100;
        } else if (nTimeSinceLastBlock > 3 * 3600) { // 3-6 hours  
            bnEmergency *= 50;
        } else if (nTimeSinceLastBlock > 1 * 3600) { // 1-3 hours
            bnEmergency *= 20;
        } else {                                     // 30min-1hour
            bnEmergency *= 10;
        }
        
        if (bnEmergency > bnPowLimit) bnEmergency = bnPowLimit;
        return bnEmergency.GetCompact();
    }
    
    // =============================================================
    // ADAPTIVE ADJUSTMENT INTERVAL - Key stability improvement
    // =============================================================
    
    // Use different adjustment frequencies based on network stability
    int adjustmentInterval = 1;  // Default: every block
    
    // Calculate recent block time variance to determine stability
    bool isNetworkStable = true;
    if (pindexLast->nHeight >= 10) {  // Need at least 10 blocks
        int64_t totalTime = 0;
        int validBlocks = 0;
        const CBlockIndex* pindex = pindexLast;
        
        // Check last 10 blocks for stability
        for (int i = 0; i < 10 && pindex && pindex->pprev; i++) {
            int64_t blockTime = pindex->GetBlockTime() - pindex->pprev->GetBlockTime();
            if (blockTime > 0 && blockTime < 10 * nTargetSpacing) {  // Valid block time
                totalTime += blockTime;
                validBlocks++;
            }
            pindex = pindex->pprev;
        }
        
        if (validBlocks >= 5) {
            int64_t avgTime = totalTime / validBlocks;
            // Network is stable if average is within 50% of target
            isNetworkStable = (avgTime > nTargetSpacing / 2 && avgTime < nTargetSpacing * 2);
        }
    }
    
    // Set adjustment interval based on stability
    if (isNetworkStable) {
        adjustmentInterval = 12;  // Stable: adjust every 12 blocks (更稳定)
    } else {
        adjustmentInterval = 4;   // Unstable: adjust every 4 blocks  
    }
    
    // Check if we should adjust difficulty this block
    if ((pindexLast->nHeight + 1) % adjustmentInterval != 0) {
        // Not an adjustment block, return current difficulty
        return pindexLast->nBits;
    }
    
    LogPrintf("Difficulty adjustment at block %d (interval: %d, stable: %s)\n", 
              pindexLast->nHeight + 1, adjustmentInterval, isNetworkStable ? "yes" : "no");
    
    // =============================================================
    // CALCULATE AVERAGE TIME OVER ADJUSTMENT WINDOW
    // =============================================================
    
    int blocksToCheck = adjustmentInterval;
    int64_t totalActualTime = 0;
    int validTimeSpans = 0;
    
    const CBlockIndex* pindex = pindexLast;
    for (int i = 0; i < blocksToCheck && pindex && pindex->pprev; i++) {
        int64_t blockTime = pindex->GetBlockTime() - pindex->pprev->GetBlockTime();
        
        // Filter out extreme values
        if (blockTime > 0 && blockTime < 20 * nTargetSpacing) {
            totalActualTime += blockTime;
            validTimeSpans++;
        }
        pindex = pindex->pprev;
    }
    
    int64_t nActualSpacing;
    if (validTimeSpans > 0) {
        nActualSpacing = totalActualTime / validTimeSpans;
    } else {
        // Fallback to last two blocks
        nActualSpacing = pindexLast->GetBlockTime() - pindexLast->pprev->GetBlockTime();
    }
    
    // Safety limits
    nActualSpacing = std::max<int64_t>(nActualSpacing, 1);
    nActualSpacing = std::min<int64_t>(nActualSpacing, nTargetSpacing * 60);  // Max 1 hour
    
    // =============================================================
    // DIGISHIELD-INSPIRED SMOOTHING FILTER
    // =============================================================
    
    int64_t nTargetTimespan = nTargetSpacing * adjustmentInterval;
    int64_t nActualTimespan = nActualSpacing * adjustmentInterval;
    
    // Apply smoothing filter (inspired by DigiShield)
    // Only take 1/6 of the deviation for more stability
    int64_t nModulatedTimespan = nTargetTimespan + (nActualTimespan - nTargetTimespan) / 6;
    
    LogPrintf("Timespan calculation: actual=%ds, target=%ds, smoothed=%ds\n",
              nActualTimespan, nTargetTimespan, nModulatedTimespan);
    
    // =============================================================
    // CALCULATE NEW DIFFICULTY
    // =============================================================
    
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    
    // Apply the standard formula with smoothed values
    bnNew *= nModulatedTimespan;
    bnNew /= nTargetTimespan;
    
    // =============================================================
    // ADAPTIVE ADJUSTMENT LIMITS
    // =============================================================
    
    arith_uint256 bnPrevious;
    bnPrevious.SetCompact(pindexLast->nBits);
    
    // More aggressive limits for unstable networks
    int maxIncrease, maxDecrease;
    if (!isNetworkStable) {
        // Unstable network: allow bigger changes for faster recovery
        maxIncrease = 75;   // Can increase by 75%
        maxDecrease = 60;   // Can reduce by 60%
    } else {
        // Stable network: smaller changes for stability
        maxIncrease = 25;   // Max 25% increase (更保守)
        maxDecrease = 25;   // Max 25% decrease
    }
    
    // Special case: if blocks are consistently too fast, be more aggressive
    if (nActualSpacing < nTargetSpacing / 3) {  // Less than 20 seconds
        maxIncrease = 150;  // Can increase 2.5x
        LogPrintf("Fast block protection: increasing max adjustment to %d%%\n", maxIncrease);
    }
    
    // Apply limits
    arith_uint256 bnMax = bnPrevious * (100 + maxIncrease) / 100;
    arith_uint256 bnMin = bnPrevious * (100 - maxDecrease) / 100;
    
    if (bnNew > bnMax) bnNew = bnMax;
    if (bnNew < bnMin) bnNew = bnMin;
    
    // Never exceed minimum difficulty
    if (bnNew > bnPowLimit) bnNew = bnPowLimit;
    
    // =============================================================
    // FINAL CHAIN DEATH PROTECTION
    // =============================================================
    
    // If difficulty is still too high and recent blocks were slow, reduce more
    double avgRecentTime = (double)nActualSpacing;
    if (avgRecentTime > 5 * nTargetSpacing) {  // Average > 5 minutes
        LogPrintf("Chain protection: Recent blocks too slow (%.1fs), reducing difficulty further\n", 
                  avgRecentTime);
        
        // Additional reduction for chain protection
        bnNew *= 2;  // Make it 2x easier
        if (bnNew > bnPowLimit) bnNew = bnPowLimit;
    }
    
    // =============================================================
    // LOGGING
    // =============================================================
    
    double changePercent = ((double)bnNew.GetCompact() / (double)pindexLast->nBits - 1.0) * 100.0;
    
    LogPrintf("Stable Difficulty Adjustment:\n");
    LogPrintf("  %08x -> %08x (%.1f%% change)\n", 
              pindexLast->nBits, bnNew.GetCompact(), changePercent);
    LogPrintf("  Avg block time: %.1fs (target: %ds)\n", 
              (double)nActualSpacing, nTargetSpacing);
    LogPrintf("  Network stable: %s, Adjustment interval: %d\n", 
              isNetworkStable ? "yes" : "no", adjustmentInterval);
    
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
