#ifndef MASTERKEY_H
#define MASTERKEY_H

#include <vector>
#include "extendedkey.h"
#include "iostream"
#include "secp256k1-cxx.hpp"

class MasterKey
{
public:
    MasterKey(const std::vector<unsigned char>& seed, const std::vector<unsigned char>& hmacKey = {});

    ExtendedKey* getMaster();

private:
    ExtendedKey master;
};

#endif // MASTERKEY_H
