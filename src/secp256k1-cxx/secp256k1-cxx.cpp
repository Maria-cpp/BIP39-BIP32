#include "secp256k1-cxx.hpp"

#include <cassert>
#include <cstring>
#include <iostream>
#include <random>
#include <tuple>
#include <vector>
#include <secp256k1_recovery.h>

/**
 * @brief Secp256K1::Secp256K1
 * creates pub/priv key pair
 */
Secp256K1::Secp256K1()
        : ctx(secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)) {
}

Secp256K1::~Secp256K1() {
    secp256k1_context_destroy(ctx);
}


bool Secp256K1::createPrivateKey() {
    //get epoch time
    unsigned seed1 = std::chrono::system_clock::now().time_since_epoch().count();

    //generate random number for priv key
    std::seed_seq seed{seed1};
    std::mt19937_64 eng(seed);
    std::string randString;
    for (int i = 0; i < 10; ++i) {
        randString += eng();
    }

    //generate SHA-256 (our priv key)
    std::vector<uint8_t> out;
    out.resize(32);
    sha256_Raw(reinterpret_cast<const uint8_t *>(randString.c_str()), randString.length(), &out[0]);

    assert(out.size() == 32);

    privKey = std::move(out);
    return verifyKey();
}

void Secp256K1::setPrivKey(std::vector<uint8_t> priv) {
    privKey = std::move(priv);
}

void Secp256K1::setPubkey(std::vector<uint8_t> pub) {
    pubKey = std::move(pub);
}

/**
 * @brief verifies private key and generates corresponding public key
 * @param privateKey - in hexadecimal
 */
bool Secp256K1::createPublicKeyFromPriv(const std::vector<uint8_t> &privateKey) {
    privKey = privateKey;
    //verify priv key
    if (!verifyKey()) {
        throw Secp256K1Exception("Unable to create and verify key:  ");
    }

    if (!createPublicKey()) {
        throw Secp256K1Exception("Unable to create publick key");
    }
    return true;
}

/**
 * @brief add tweak and module curve order (key + tweak) mod n
 * @param key
 * @param tweak
 * @return true | false
 */
bool Secp256K1::privKeyTweakAdd(std::vector<uint8_t> &key, const std::vector<uint8_t> &tweak) {
    bool ret = secp256k1_ec_privkey_tweak_add(ctx, &key[0], tweak.data());
    return ret;
}

std::vector<uint8_t> Secp256K1::uncompressedPublicKey() {
    secp256k1_pubkey pubkey;
    assert(ctx && "secp256k1_context_verify must be initialized to use CPubKey.");
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, &pubKey[0], pubKey.size())) {
        throw Secp256K1Exception("Unable to parse public key.");
    }
    std::vector<uint8_t> pub(65);
    size_t publen = 65;
    secp256k1_ec_pubkey_serialize(ctx, &pub[0], &publen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    unComppubKey = pub;
    return pub;
}

std::vector<uint8_t> Secp256K1::uncompress(const std::vector<uint8_t> &pubkey) {
    if (pubkey.empty())
        throw Secp256K1Exception("Empty public key in Secp256K1::uncompress");
    Secp256K1 s;
    s.setPubkey(pubkey);
    return s.uncompressedPublicKey();
}

std::vector<uint8_t> Secp256K1::publicKey() const {
    return pubKey;
}

std::vector<uint8_t> Secp256K1::privateKey() const {
    return privKey;
}

uint32_t Secp256K1::fingerprint() const {
    std::vector<uint8_t> final(32);
    sha256_Raw(pubKey.data(), pubKey.size(), &final[0]);
    ripemd160(final.data(), final.size(), &final[0]);
    return ((uint32_t) final[0] << 24) | ((uint32_t) final[1] << 16) | ((uint32_t) final[2] << 8) |
           ((uint32_t) final[3]);
}

std::string Secp256K1::publicKeyHex() const {
    return BIP39_Utils::base16Encode(reinterpret_cast<const char *>(pubKey.data()));
}

std::string Secp256K1::privateKeyHex() const {
    return BIP39_Utils::base16Encode(reinterpret_cast<const char *>(privKey.data()));
}

bool Secp256K1::verifyKey() {
    return secp256k1_ec_seckey_verify(ctx, privKey.data());
}

bool Secp256K1::createPublicKey(bool compressed) {
    // Calculate public key.
    secp256k1_pubkey pubkey;
    int ret = secp256k1_ec_pubkey_create(ctx, &pubkey, privKey.data());
    if (ret != 1) {
        return false;
    }

    // Serialize public key.
    size_t outSize = PUBLIC_KEY_SIZE;
    pubKey.resize(outSize);
    secp256k1_ec_pubkey_serialize(
            ctx, pubKey.data(), &outSize, &pubkey,
            compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    pubKey.resize(outSize);

    // Succeed.
    return true;
}

std::tuple<std::vector<uint8_t>, bool> Secp256K1::Sign(const uint8_t *hash) const {
    /* // Make signature.
     secp256k1_ecdsa_signature sig;
     std::vector<unsigned char> temp = privKey;
     temp.insert(temp.end(),'\0');
     int ret = secp256k1_ecdsa_sign(
             ctx, &sig, hash, temp.data(), secp256k1_nonce_function_rfc6979, nullptr);
     if (ret != 1) {
         // Failed to sign.
         return std::make_tuple(std::vector<uint8_t>(), false);
     }

     // Serialize signature.
     std::vector<uint8_t> sigOut(72);
     size_t sigOutSize = 72;
     ret = secp256k1_ecdsa_signature_serialize_der(
             ctx, &sigOut[0], &sigOutSize, &sig);
     if (ret != 1) {
         // Failed to serialize.
         return std::make_tuple(std::vector<uint8_t>(), false);
     }

     // Returns
     sigOut.resize(sigOutSize);
     return std::make_tuple(sigOut, true);*/

    // Make signature.
     secp256k1_ecdsa_signature sig;
     std::vector<unsigned char> temp = privKey;

 //   temp.insert(temp.end(), '\0');
     int ret = secp256k1_ecdsa_sign(
             ctx, &sig, hash, temp.data(), secp256k1_nonce_function_rfc6979, nullptr);

     if (ret != 1) {
         // Failed to sign.
         return std::make_tuple(std::vector<uint8_t>(), false);
     }
     std::vector<uint8_t> sigOut{sig.data, sig.data + 64};
     std::cout << " Simple Signature " << BIP39_Utils::base16Encode(std::string{sigOut.begin(), sigOut.end()})
               << " size " << sigOut.size() << std::endl;


     secp256k1_ecdsa_recoverable_signature sigRecover;
     const unsigned char* seckey = &privKey[0];
     unsigned char arr[32] = {};
     ret = secp256k1_ecdsa_sign_recoverable(
             ctx, &sigRecover, hash, seckey, secp256k1_nonce_function_rfc6979, NULL);
     if (ret != 1) {
         std::cout << "\nthe nonce generation function failed, or the private key was invalid. \n";
         // Failed to serialize.
         return std::make_tuple(std::vector<uint8_t>(), false);
     }

     std::vector<uint8_t> compactSig{sigRecover.data, sigRecover.data + 65};

     std::cout << "Signature recoverable 65 bytes: "
               << BIP39_Utils::base16Encode(std::string{compactSig.begin(), compactSig.end()}) << " size "
               << compactSig.size() << std::endl;

    /*secp256k1_ecdsa_recoverable_signature sigRecover;
    std::string sig = BIP39_Utils::base16Decode(
            "0be2158b2a600b05646c2dfeaa93c3e2909c3eb7b0accbe99218e049e5852672418b18f162657b67a20ce5955fe94c2841f3bad9d740844c4cb5f2ed2cb26d7901");
    std::copy(sig.begin(), sig.end(), sigRecover.data);*/

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pubKey.data(),pubKey.size()))
        std::cout << "\nNot Parsed\n";
    else
        std::cout << "\n Parsed\n";

    secp256k1_ecdsa_recover(ctx, &pubkey, &sigRecover, hash);

    std::vector<uint8_t> Rpubkey{pubkey.data, pubkey.data + 64};
    std::cout << "\nPublicKey recoverable 64 bytes: "
              << BIP39_Utils::base16Encode(std::string{Rpubkey.begin(), Rpubkey.end()}) << " size "
              << Rpubkey.size() << std::endl;
    std::vector<uint8_t> Cpubkey = uncompress(pubKey);
    std::cout << "\nPublicKey: " << BIP39_Utils::base16Encode(std::string{Cpubkey.begin(), Cpubkey.end()})
              << " size " << Rpubkey.size() << std::endl;
    return std::make_tuple(compactSig, true);
}

/** This function is taken from the libsecp256k1 distribution and implements
 *  DER parsing for ECDSA signatures, while supporting an arbitrary subset of
 *  format violations.
 *
 *  Supported violations include negative integers, excessive padding, garbage
 *  at the end, and overly long length descriptors. This is safe to use in
 *  Bitcoin because since the activation of BIP66, signatures are verified to be
 *  strict DER before being passed to this module, and we know it supports all
 *  violations present in the blockchain before that point.
 */
static int
ecdsa_signature_parse_der_lax(const secp256k1_context *ctx, secp256k1_ecdsa_signature *sig, const unsigned char *input,
                              size_t inputlen) {
    size_t rpos, rlen, spos, slen;
    size_t pos = 0;
    size_t lenbyte;
    unsigned char tmpsig[64] = {0};
    int overflow = 0;

    /* Hack to initialize sig with a correctly-parsed but invalid signature. */
    secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);

    /* Sequence tag byte */
    if (pos == inputlen || input[pos] != 0x30) {
        return 0;
    }
    pos++;

    /* Sequence length bytes */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        pos += lenbyte;
    }

    /* Integer tag byte for R */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for R */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        static_assert(sizeof(size_t) >= 4, "size_t too small");
        if (lenbyte >= 4) {
            return 0;
        }
        rlen = 0;
        while (lenbyte > 0) {
            rlen = (rlen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        rlen = lenbyte;
    }
    if (rlen > inputlen - pos) {
        return 0;
    }
    rpos = pos;
    pos += rlen;

    /* Integer tag byte for S */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for S */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        static_assert(sizeof(size_t) >= 4, "size_t too small");
        if (lenbyte >= 4) {
            return 0;
        }
        slen = 0;
        while (lenbyte > 0) {
            slen = (slen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        slen = lenbyte;
    }
    if (slen > inputlen - pos) {
        return 0;
    }
    spos = pos;

    /* Ignore leading zeroes in R */
    while (rlen > 0 && input[rpos] == 0) {
        rlen--;
        rpos++;
    }
    /* Copy R value */
    if (rlen > 32) {
        overflow = 1;
    } else {
        memcpy(tmpsig + 32 - rlen, input + rpos, rlen);
    }

    /* Ignore leading zeroes in S */
    while (slen > 0 && input[spos] == 0) {
        slen--;
        spos++;
    }
    /* Copy S value */
    if (slen > 32) {
        overflow = 1;
    } else {
        memcpy(tmpsig + 64 - slen, input + spos, slen);
    }

    if (!overflow) {
        overflow = !secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    if (overflow) {
        /* Overwrite the result again with a correctly-parsed but invalid
           signature if parsing failed. */
        memset(tmpsig, 0, 64);
        secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    return 1;
}

/**
 * @brief Secp256K1::Verify
 * @param msgHash being verified
 * @param sign input signature (72 bytes)
 * @param pubKey pubKey being used to verify the msg (65 bytes)
 * @return true if success
 */
bool Secp256K1::Verify(const uint8_t *msgHash, const std::vector<uint8_t> &sign, const std::vector<uint8_t> &pubKey) {
    if (pubKey.size() != PUBLIC_KEY_SIZE) {
        throw Secp256K1Exception("Invalid public key size");
    }
    /* if (sign.size() != 72) {
         throw Secp256K1Exception("Invalid signature size");
     }*/

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    // Parse public key.
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pubKey.data(),
                                   pubKey.size())) {
        return false;
    }

    // Parse signature.
    secp256k1_ecdsa_signature sig;
    if (!ecdsa_signature_parse_der_lax(ctx, &sig, sign.data(), sign.size())) {
        return false;
    }

    secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);
    CHECK(secp256k1_ecdsa_verify(ctx, &sig, msgHash, &pubkey));
    bool ret = secp256k1_ecdsa_verify(ctx, &sig, msgHash, &pubkey);
    secp256k1_context_destroy(ctx);
    return ret;
}

Secp256K1 *Secp256K1::instance = nullptr;

Secp256K1 *Secp256K1::getInstance() {
    if (instance == nullptr) {
        instance = new Secp256K1;
    }
    return instance;
}

void Secp256K1::setPrivKey(const std::vector<uint8_t> &privKey) {
    Secp256K1::privKey = privKey;
}

const std::vector<uint8_t> &Secp256K1::getUnComppubKey() const {
    return unComppubKey;
}
