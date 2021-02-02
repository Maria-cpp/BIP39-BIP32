//
// Created by pc on 22/1/21.
//
#include "iostream"
#include "BIP39/bip39/BIP39.h"
#include "BIP39/bip39/mnemonic.h"
#include "BIP39/crypto/strencodings.h"

int main() {

    Mnemonic m_obj;
    BIP39 obj(12);
    std::string entropy = "063679ca1b28b5cfda9c186b367e271e";
    std::cout<<entropy.length()<<"\n";
    obj = obj.useEntropy(entropy);

//    you can generate random entropy by calling the following function
//    obj=obj.generateSecureEntropy();

    m_obj = obj.mnemonic();
    std::string pass;
    for (auto itr : m_obj.words) {
        pass+=" ";
        pass += itr.data();
    }
    std::cout << "mnemonic phrases:   "<<pass<<"\n";

    std::string addphrase = "MediaPark";
    std::string salt = "mnemonics"+addphrase;

    uint32_t itrCount = 2048;
    size_t outKeySize = 64;
    Algo algo = Algo::SHA512;

    std::vector<uint8_t> outKey(outKeySize);

    outKey=obj.seed(algo, pass, salt, itrCount, outKeySize);

    pass="";

    for (auto itr : outKey) {
        pass += itr;
    }

    std::cout << "raw hash :"<< pass;
    std::cout<<"\nhexadecimal: "<<base16Encode({outKey.begin(),outKey.end()});

    return 0;
}

