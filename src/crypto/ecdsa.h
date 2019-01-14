#ifndef ECDSA_H
#define ECDSA_H

#include <openssl/bn.h>

#include "util.h" // for uint64

// Faster ECDSA signer for mining.
// DO NOT sign multiple messages with the same instance of this class, this is not safe.
// It is ok to sign many different hashes during mining because only one of it will be broadcasted.
// See https://en.wikipedia.org/wiki/Elliptic_Curve_DSA beginning with the words
// "As the standard notes, it is crucial to select different k for different signatures".
class CSignerECDSA
{
    BN_CTX* ctx;

    BIGNUM order;
    BIGNUM kinv;
    BIGNUM pmr;
    BIGNUM prk;

public:

    CSignerECDSA()
    {
        ctx = BN_CTX_new();
        if (ctx == NULL)
            throw std::runtime_error("CSignerECDSA : BN_CTX_new() returned NULL");
        BN_init(&order);
        BN_init(&kinv);
        BN_init(&pmr);
        BN_init(&prk);
//        BIGNUM *pbn = BN_new();
        BIGNUM * pbn = &order;
        BN_hex2bn(&pbn,"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
//        BN_copy(&order, pbn);
//        BN_free(pbn);
    }

    ~CSignerECDSA()
    {
        BN_clear_free(&order);
        BN_clear_free(&kinv);
        BN_clear_free(&pmr);
        BN_clear_free(&prk);
        if (ctx != NULL)
            BN_CTX_free(ctx);
    }

    std::string GetPMR()
    {
//        std::string str;
        return BN_bn2hex(&pmr);
    }

    std::string GetKInv()
    {
        return BN_bn2hex(&kinv);
    }

    std::string GetPRK()
    {
        return BN_bn2hex(&prk);
    }

    // Initialize signer and part of signature with random data which is not depended on message being signed.
    CSignerECDSA(const uint8_t PrivData[32], unsigned char Signature[65]);

    // Initialize rest of signature with data specific to message being signed.
    void SignFast(const uint256 &hash, unsigned char Signature[65]);
};

#endif // ECDSA_H
