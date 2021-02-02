//
// Created by pc on 22/1/21.
//

#ifndef BIP39_BIP39_H
#define BIP39_BIP39_H

#include <bitset>
#include <string>
#include <vector>
#include "utils.h"
#include "wordlist.h"
#include "../crypto/sha256.h"
#include "mnemonic.h"
#include <sys/random.h>
#include "../crypto/pbkdf2.h"

class MnemonicException : public std::runtime_error {
public:
    MnemonicException(std::string &&msg) : std::runtime_error{std::move(msg)} {}

    const char *what() const noexcept {
        return std::runtime_error::what();
    }
};


class BIP39 {

public:
    BIP39(int wordcount = 12);

    bool validateEntropy(const std::string &entropy);

    Mnemonic Entropy(const std::string &entropy);

    std::string checksum(const std::string &entropy);

    static constexpr size_t len_to_mask(size_t len) noexcept;

    BIP39 generateSecureEntropy();

    static Mnemonic Generate(int wordCount);

    BIP39 wordList(Wordlist *wordlist);

    Mnemonic mnemonic();

    std::string hex2bits(const std::string &hex) noexcept;

    std::string bits2hex(const std::string &bits) noexcept;

    BIP39 useEntropy(const std::string &entropy);

    static Mnemonic
    words(const std::string &words, Wordlist *wordlist = Wordlist::english(), bool verifyChecksum = true);

    Mnemonic reverse(const std::vector<std::string> &words, bool verifyChecksum = true);

    std::vector<uint8_t> seed(Algo algo, const std::string &pass, const std::string &salt, uint32_t iterations, size_t outKeySize);

private:

    int m_wordsCount;
    int m_overallBits;
    int m_checksumBits;
    int m_entropyBits;
    std::string m_entropy;
    std::string m_checksum;
    std::vector<std::bitset<11>> m_rawBinaryChunks;
    std::vector<std::string> m_words;
    Wordlist *m_wordList;
};


#endif //BIP39_BIP39_H
