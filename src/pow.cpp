// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "primitives/block.h"
#include "uint256.h"
#include "util.h"

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

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

    return CalculateNextWorkRequired(pindexLast, 0, params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    LogPrintf("CalculateNextWorkRequired: Height (before): %s\n", pindexLast->nHeight);

    // find first block in averaging interval
    if (pindexLast->nHeight < params.DifficultyAdjustmentInterval())
    {
        LogPrintf("CalculateNextWorkRequired: Use default POW Limit\n");
        return UintToArith256(params.powLimit).GetCompact();
    }

    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval() - 1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    // Limit adjustment step
    // Use medians to prevent time-warp attacks
    const int64_t nMaxAdjustDown = 16;
    const int64_t nMaxAdjustUp = 8;
    const int64_t nMinActualTimespan = params.nPowTargetTimespan * (100 - nMaxAdjustUp) / 100;
    const int64_t nMaxActualTimespan = params.nPowTargetTimespan * (100 + nMaxAdjustDown) / 100;

    int64_t nActualTimespan = pindexLast->GetMedianTimePast() - pindexFirst->GetMedianTimePast();
    nActualTimespan = params.nPowTargetTimespan + (nActualTimespan - params.nPowTargetTimespan)/4;

    LogPrintf("CalculateNextWorkRequired: nActualTimespan = %d before bounds\n", nActualTimespan);

    if (nActualTimespan < nMinActualTimespan)
        nActualTimespan = nMinActualTimespan;
    if (nActualTimespan > nMaxActualTimespan)
        nActualTimespan = nMaxActualTimespan;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
    {
        LogPrintf("CalculateNextWorkRequired: bnNew > bnPowLimit\n");
        bnNew = bnPowLimit;
    }

    LogPrintf("CalculateNextWorkRequired: Target timespan = %d; nActualTimespan = %d\n",
              params.nPowTargetTimespan, nActualTimespan);
    LogPrintf("CalculateNextWorkRequired: Before: %08x  %s\n",
              pindexLast->nBits, arith_uint256().SetCompact(pindexLast->nBits).ToString());
    LogPrintf("CalculateNextWorkRequired: After:  %08x  %s\n",
              bnNew.GetCompact(), bnNew.ToString());

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
