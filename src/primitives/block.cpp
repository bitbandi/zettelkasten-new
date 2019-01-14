// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>
#include <utilstrencodings.h>
#include <crypto/common.h>
#include <crypto/powhash.h>

std::string CMinerSignature::ToString() const
{
    return HexStr(begin(), end());
}

std::string ABCBytesForSDKPGAB::ToString() const
{
    return strprintf("ABCBytesForSDKPGAB(A=%i, B=%i, C=%i)", A, B, C);
}


uint256 CBlockHeader::GetHash() const
{
    CDataStream Header = SerializeHeaderForHash();
    return Hash(Header.begin(), Header.end());
//    return SerializeHash(*this);
}

// TODO: add Consensus::Params for hardfork heights
uint256 CBlockHeader::GetPoWHash() const
{
/*
    uint256 thash;
    scrypt_1024_1_1_256(BEGIN(nVersion), BEGIN(thash));
    return thash;
*/
        CDataStream Header = SerializeHeaderForHash();

        ABCBytesForSDKPGAB bytes;

        if (nHeight >= SDKPGABSPCSSWSSBP_START_HEIGHT)
        {
                uint32_t SDKPGABSPC_sinetable_pos = nHeight%64;

                uint256 pubkey_hashPrevBlock;

// TODO: cache this different way
                pubkey_hashPrevBlock = SDKPGABSPCSSWSSBP_GetPublicKeyFromPrivateKey(hashPrevBlock);

                if(nHeight%2 == 0){
                        return HashSDKPGABSPCSSWSSBP_EVEN(Header.begin(), Header.end(), ABCBytes.A, ABCBytes.B, SDKPGABSPC_sinetable_pos, pubkey_hashPrevBlock);
                }
                else { // if(nHeight%2 == 1){
                        return HashSDKPGABSPCSSWSSBP_ODD(Header.begin(), Header.end(), ABCBytes.A, ABCBytes.B, SDKPGABSPC_sinetable_pos, pubkey_hashPrevBlock);
                }
        }
        else if (nHeight >= SDKPGABSPCSSWS_START_HEIGHT)
        {
                uint32_t SDKPGABSPC_sinetable_pos = nHeight%64;

                if(nHeight%2 == 0){
                        return HashSDKPGABSPCSSWS_EVEN(Header.begin(), Header.end(), ABCBytes.A, ABCBytes.B, SDKPGABSPC_sinetable_pos);
                }
                else { // if(nHeight%2 == 1){
                        return HashSDKPGABSPCSSWS_ODD(Header.begin(), Header.end(), ABCBytes.A, ABCBytes.B, SDKPGABSPC_sinetable_pos);
                }
        }

        else if (nHeight >= SDKPGABSPC_START_HEIGHT)
        {
                uint32_t SDKPGABSPC_sinetable_pos = nHeight%64;

                if(nHeight%2 == 0){
                        return HashSDKPGABSPC_EVEN(Header.begin(), Header.end(), ABCBytes.A, ABCBytes.B, SDKPGABSPC_sinetable_pos);
                }
                else { // if(nHeight%2 == 1){
                        return HashSDKPGABSPC_ODD(Header.begin(), Header.end(), ABCBytes.A, ABCBytes.B, SDKPGABSPC_sinetable_pos);
                }
        }

        else if(nHeight >= SDKPGAB_START_HEIGHT)
        {
                if(nHeight%2 == 0){
                        return HashSDKPGAB_EVEN(Header.begin(), Header.end(),ABCBytes.A,ABCBytes.B);
                }
                else { // if(nHeight%2 == 1){
                        return HashSDKPGAB_ODD(Header.begin(), Header.end(),ABCBytes.A,ABCBytes.B);
                }
        }

        return HashSDK(Header.begin(), Header.end());
}

uint256 CBlockHeader::GetHashForSignature() const
{
    CDataStream Header(SER_GETHASH, 0);
    Header << nVersion;
    Header << hashPrevBlock;
    Header << hashMerkleRoot;
    Header << nTime;
    Header << nBits;
    Header << nHeight;
    Header << (nNonce & ~NONCE_MASK); // ignore lowest 6 bits in nonce to allow enumeration of 64 hashes without recomputing whole block hash
    // Skip MinerSignature because it is what we are computing right now.
    // Skip hashWholeBlock because it depends on MinerSignature.
    assert(Header.end() - Header.begin() == 88);
    return Hash(Header.begin(), Header.end());
}

CPubKey CBlockHeader::GetRewardAddress() const
{
    CPubKey PubKey;
    PubKey.RecoverCompact(GetHashForSignature(), std::vector<uint8_t>(MinerSignature.begin(), MinerSignature.end()));
    return PubKey;
}

CDataStream CBlockHeader::SerializeHeaderForHash() const
{
    CDataStream Header(SER_GETHASH, 0);
    Header << nVersion;
    Header << hashPrevBlock;
    Header << hashMerkleRoot;
    Header << nTime;
    Header << nBits;
    Header << nHeight;
    Header << nNonce;
    Header << hashWholeBlock;
    Header << MinerSignature;
    assert(Header.end() - Header.begin() == 185);
    return Header;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, PoW=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, hashWholeBlock=%s, nTime=%llu, nBits=%08x, nNonce=%u, nHeight=%u, MinerSignature=%s, ABCBytes=(%i,%i,%i), vtx=%u)\n",
        GetHash().ToString(),
        GetPoWHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        hashWholeBlock.ToString(),
        nTime, nBits, nNonce, nHeight,
        MinerSignature.ToString(),
        ABCBytes.A, ABCBytes.B, ABCBytes.C,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

void CBlock::GetPoKData(CDataStream& BlockData) const
{
        // Start with nonce, time and miner signature as these are values changed during mining.
        BlockData << (nNonce & ~NONCE_MASK); // ignore lowest 6 bits in nonce to allow enumeration of 64 hashes without recomputing whole block hash
        BlockData << nTime;
        BlockData << MinerSignature;
        BlockData << nVersion;
        BlockData << hashPrevBlock;
        BlockData << hashMerkleRoot;
        BlockData << nBits;
        BlockData << nHeight;
        // Skip hashWholeBlock because it is what we are computing right now.
        BlockData << vtx;

        uint8_t FILLER;

        if (nHeight >= SDKPGAB_START_HEIGHT)
        {
                FILLER = ABCBytes.C;
        }
        if (nHeight < SDKPGAB_START_HEIGHT){

                FILLER = 0x07;
        }

        BlockData.resize(MAX_BLOCK_SIZE, 0);
        while (BlockData.size() % 4 != 0)
                BlockData << uint8_t(FILLER);

        // Fill rest of the buffer to ensure that there is no incentive to mine small blocks without transactions.
        uint32_t *pFillBegin = (uint32_t*)&BlockData[BlockData.size()];
        uint32_t *pFillEnd = (uint32_t*)&BlockData[MAX_BLOCK_SIZE];
        uint32_t *pFillFooter = std::max(pFillBegin, pFillEnd - 8);

        memcpy(pFillFooter, &hashPrevBlock, (pFillEnd - pFillFooter)*4);
        for (uint32_t *pI = pFillFooter; pI < pFillEnd; pI++)
                *pI |= 1;

        for (uint32_t *pI = pFillFooter - 1; pI >= pFillBegin; pI--)
                pI[0] = pI[3]*pI[7];

//        BlockData.forsed_resize(MAX_BLOCK_SIZE);
}

uint256 CBlock::HashPoKData(const CDataStream& PoKData) const
{
    CHashWriter hasher(SER_GETHASH, 0);

    // Hash everything twice to ensure that pool can not hide part of the block from miners by supplying them hash state.
    for (int i = 0; i < 2; i++)
    {
        uint8_t LowByte = PoKData[0] & ~NONCE_MASK;  // ignore lowest 6 bits in nonce to allow enumeration of 64 hashes without recomputing whole block hash
        hasher.write((const char*)&LowByte, 1);
        hasher.write(&PoKData[1], PoKData.size() - 1);
    }

    return hasher.GetHash();
}

uint256 CBlock::GetPoKHash() const
{
    CDataStream Data(SER_GETHASH, 0);
    GetPoKData(Data);

    return HashPoKData(Data);
}
