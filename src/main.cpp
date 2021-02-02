//
// Created by pc on 29/1/21.
//
#include <string>
#include <iostream>
#include <vector>
#include "crypto/hmac.h"
#include "secp256k1-cxx.hpp"
#include "masterkey.h"
#include "crypto/base58.h"

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


    std::string seed = "000102030405060708090a0b0c0d0e0f";
    static const std::vector<unsigned char> hashkey = {'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd'};
    auto vseed = ParseHex(seed);
    /** Pass the out seed to hmac512 to master key **/
    std::vector<uint8_t> outseed(64);
    hmac_sha512(hashkey.data(), hashkey.size(), vseed.data(), vseed.size(), &outseed[0]);
    MasterKey k(outseed);
    auto pk = k.getMaster();

    auto prvser = pk->serializedKey(0x0488ade4);
    auto pubser=pk->serializedKey(0x0488b21e);
    std::vector<char> prvkey(128);
    std::vector<char> pubkey(128);

    /** Wallet Import Format
     * Private Key to WIF**/
    std::cout << "\n\t\tWIF \n";
    std::string wif=pk->wif(pk->privateKey());

    /** Wallet Import Format
     *WIF to  Private Key**/
     std::string pKey=pk->wifTokey(wif);

    /** private key B58 and Hex **/
    std::cout << "\n\t\tXPRV & XPUB \n";

    bool suc = base58_encode_check(prvser.data(), prvser.size(), &prvkey[0], prvkey.size());
    std::string prvb58{prvkey.begin(), prvkey.end()};
    std::cout << "Ser Prv B58: " << suc << " " << prvb58 << std::endl;
    std::cout << "Ser Prv hex : " << HexStr(prvser.begin(), prvser.end()) << std::endl;


    /** public key B58 and Hex **/
    suc = base58_encode_check(pubser.data(), pubser.size(), &pubkey[0], pubkey.size());
    std::string pubb58{pubkey.begin(), pubkey.end()};
    std::cout << "Ser pub B58: " << suc << " " << pubb58 << std::endl;
    std::cout << "Ser pub hex : " << HexStr(pubser.begin(), pubser.end()) << std::endl;


    std::cout << "-------------------------------" << std::endl;


    /** Extended key derivation**/

    ExtendedKey ck;
    uint32_t arr[5] = {
            0x80000000,
            1,
            0x80000002,
            2,
            1000000000
    };
    ExtendedKey par = *pk;
    for (int i = 0; i < 5; ++i) {
        std::cout << "\n New child: \n";
        ck = par.derive(arr[i]);
        prvser = ck.serializedKey(0x488ade4);
        pubser=ck.serializedKey(0x0488b21e);
        std::vector<char> cKey(128);
        std::vector<char> pKey(128);

        base58_encode_check(prvser.data(), prvser.size(), &cKey[0], cKey.size());
        base58_encode_check(pubser.data(), pubser.size(), &pKey[0], pKey.size());
        std::cout << "-----------------------------------------------\n";
        std::cout << "CK PRVKey in B58 : " << std::string{cKey.begin(), cKey.end()} << std::endl;
        std::cout << "Ser PRVKey in hex: " << HexStr(prvser.begin(), prvser.end()) << std::endl;
        std::cout << "CK pubKey in B58 : " << std::string{pKey.begin(), pKey.end()} << std::endl;
        std::cout << "Ser pubKey in hex: " << HexStr(pubser.begin(), pubser.end()) << std::endl;
        par = ck;
    }
    return 0;
}