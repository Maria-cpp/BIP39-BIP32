//
// Created by pc on 29/1/21.
//
#include <string>
#include <iostream>
#include <vector>
#include "crypto/hmac.h"
#include "secp256k1-cxx.hpp"

constexpr inline bool IsSpace(char c) noexcept {
    return c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v';
}

const signed char p_util_hexdigit[256] = {
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        0xa,
        0xb,
        0xc,
        0xd,
        0xe,
        0xf,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        0xa,
        0xb,
        0xc,
        0xd,
        0xe,
        0xf,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
};

signed char HexDigit(char c) {
    return p_util_hexdigit[(unsigned char) c];
}

std::vector<unsigned char> ParseHex(const char *psz) {
    // convert hex dump to vector
    std::vector<unsigned char> vch;
    while (true) {
        while (IsSpace(*psz))
            psz++;
        signed char c = HexDigit(*psz++);
        if (c == (signed char) -1)
            break;
        unsigned char n = (c << 4);
        c = HexDigit(*psz++);
        if (c == (signed char) -1)
            break;
        n |= c;
        vch.push_back(n);
    }
    return vch;
}

template<typename T>
std::string HexStr(const T itbegin, const T itend) {
    std::string rv;
    static const char hexmap[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    rv.reserve(std::distance(itbegin, itend) * 2);
    for (T it = itbegin; it < itend; ++it) {
        unsigned char val = (unsigned char) (*it);
        rv.push_back(hexmap[val >> 4]);
        rv.push_back(hexmap[val & 15]);
    }
    return rv;
}

std::vector<unsigned char> ParseHex(const std::string &str) {
    return ParseHex(str.c_str());
}


int main() {

    std::string temp ("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");
    std::vector<unsigned char> seed(temp.begin(),temp.end());

    std::vector<unsigned char> hashkey = {'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd'};

    /** Pass the out seed to hmac512 to master key **/
    std::vector<uint8_t> outseed(64);
    hmac_sha512(seed.data(), seed.size(), hashkey.data(), hashkey.size(), &outseed[0]);
    std::vector<unsigned char> privateKey(32),chainCode(32);
    privateKey.assign(outseed.begin(),outseed.begin() + 32);
    chainCode.assign(outseed.begin()+32,outseed.end());

    /** Pass this Private key to ecdsa **/
    Secp256K1::getInstance()->createPublicKeyFromPriv(privateKey);


    for (const auto &itr : Secp256K1::getInstance()->base16Encode({Secp256K1::getInstance()->pubKey.begin(),Secp256K1::getInstance()->pubKey.end()})) {
        std::cout << itr;
    }
    std::cout << "\n";


    return 0;
}