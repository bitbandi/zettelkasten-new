// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include <primitives/transaction.h>
#include <pubkey.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>

const uint32_t NONCE_MASK = 0x3F;

// FIXME!
static const unsigned int MAX_BLOCK_SIZE = 200000;                      // 200KB block hard limit
/** Block Height (>=) for SDKPGABSPCSSWSSBP start height */
static const unsigned int SDKPGABSPCSSWSSBP_START_HEIGHT = 400000;
/** Block Height (>=) for SDKPGABSPCSSWS start height */
static const unsigned int SDKPGABSPCSSWS_START_HEIGHT = 300000;
/** Block Height (>=) for SDKPGABSPC start height */
static const unsigned int SDKPGABSPC_START_HEIGHT = 200000;
/** Block Height (>=) for SDKPGAB start height */
static const unsigned int SDKPGAB_START_HEIGHT = 100000;

class CMinerSignature
{
    uint8_t sgn[65];

public:
    CMinerSignature()
    {
        SetNull();
    }

    unsigned int size() const    { return 65; }

          uint8_t* begin()          { return sgn; }
    const uint8_t* begin() const    { return sgn; }
          uint8_t* end()            { return sgn + size(); }
    const uint8_t* end() const      { return sgn + size(); }

    void SetNull()
    {
        memset(sgn, 0, size());
    }

    std::string ToString() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(FLATDATA(sgn));
    }
};

struct ABCBytesForSDKPGAB {
    uint8_t A;
    uint8_t B;
    uint8_t C;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(A);
        READWRITE(B);
        READWRITE(C); // sould we store this?
    }

    ABCBytesForSDKPGAB() {
        SetNull();
    }

    void SetNull() { A = 0; B = 0; C = 0;}
    bool IsNull() const { return (A == 0); }
    bool operator==(const ABCBytesForSDKPGAB& bytes) const { return bytes.A == A && bytes.B == B && bytes.C == C; }
    bool operator!=(const ABCBytesForSDKPGAB& bytes) const { return bytes.A != A || bytes.B != B || bytes.C != C; }

    std::string ToString() const;
};

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint64_t nTime;
    uint32_t nBits;
    uint32_t nHeight;
    uint32_t nNonce;

    // Spread mining extensions:
    uint256 hashWholeBlock; // proof of whole block knowledge
    CMinerSignature MinerSignature; // proof of private key knowledge
    ABCBytesForSDKPGAB ABCBytes;

    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nHeight);
        READWRITE(nNonce);
        READWRITE(hashWholeBlock);
        READWRITE(MinerSignature);
        if(s.GetVersion() >= 70016) {
            READWRITE(ABCBytes);
        }
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        hashWholeBlock.SetNull();
        nTime = 0;
        nBits = 0;
        nHeight = 0;
        nNonce = 0;
        MinerSignature.SetNull();
        ABCBytes.SetNull();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    uint256 GetPoWHash() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    // Get miner's public key
    CPubKey GetRewardAddress() const;

    // Hash that is signed with miner's public key in MinerSignature.
    uint256 GetHashForSignature() const;

    CDataStream SerializeHeaderForHash() const;
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // memory only
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CBlockHeader*)this);
        READWRITE(vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.hashWholeBlock = hashWholeBlock;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nHeight        = nHeight;
        block.nNonce         = nNonce;
        block.MinerSignature = MinerSignature;
        block.ABCBytes       = ABCBytes;
        return block;
    }

    std::string ToString() const;

    uint256 GetPoKHash() const;

    // Serialized block data used for PoK hashing
    void GetPoKData(CDataStream &BlockData) const;

    // Compute wholeBlockHash
    uint256 HashPoKData(const CDataStream &PoKData) const;

};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    explicit CBlockLocator(const std::vector<uint256>& vHaveIn) : vHave(vHaveIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
