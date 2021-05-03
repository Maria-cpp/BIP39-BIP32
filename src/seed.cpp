//
// Created by pc on 22/1/21.
//
#include "iostream"
#include "bip32/BIP32.h"


int main() {

   BIP32 obj;
   std::cout<<"\n\t\tseed\n";
   std::string entropy= "063679ca1b28b5cfda9c186b367e271e";
   obj.generateSeed(entropy);

}

