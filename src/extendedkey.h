#ifndef EXTENDEDKEY_H
#define EXTENDEDKEY_H

#include <stdexcept>
#include <stdint.h>
#include <string>
#include <vector>
#include "crypto/base58.h"
#include "secp256k1-cxx.hpp"

#define XPRV 0x0488ade4;
#define XPUB 0x0488b21e;

typedef std::vector<uint8_t> bytes_t;

class ExtendedKey {
public:
    ExtendedKey() = default;

    ExtendedKey(const bytes_t &key, bytes_t chainCode, uint32_t childNum = 0, uint32_t parentFP = 0,
                unsigned char depth = 0);

    static constexpr int HARDENED_INDEX_BEGIN = 0x80000000;
    static constexpr int BITWISE_SEED_LENGTH = 512;

    unsigned char depth() const;

    bytes_t privateKey() const;

    bytes_t chainCode() const;

    bytes_t publicKey() const;

    uint32_t fp() const;

    bytes_t serializedKey(uint32_t version) const;

    ExtendedKey derive(uint32_t i);

    ExtendedKey derivePath(const std::string &path);

    std::string wif(bytes_t extkey);

    std::string wifTokey(std::string wif);

    std::string mainAddr();

private:
    bytes_t m_key; // 33 bytes, first is 0x00
    bytes_t m_chainCode; // 32 bytes
    bytes_t m_publicKey;
    uint32_t m_parentFingerprint;
    uint32_t m_childNum;
    bool m_validateChildKeyCurveN;
    unsigned char m_depth;
    bool m_valid;

    inline bool isPrivate() const { return (m_key.size() == 33 && m_key[0] == 0x00); }
};

#endif // EXTENDEDKEY_H
