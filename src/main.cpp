//
// Created by pc on 29/1/21.
//
#include "bip32/BIP32.h"

int main()
{
   BIP32 obj;
   /*std::cout<<"\n\t\tseed\n";
   std::string entropy="063679ca1b28b5cfda9c186b367e271e";
   std::cout<<"Seed: "<<obj.generateSeed(entropy);
   std::cout<<"\n\n\t\tKeys\n";*/
   obj.generatekeys();


   obj.obj.Generate(12);

   std::vector<uint8_t> prvkey =obj.getPrivateKey();

   std::cout << "\n\nprivate Key : ";
   for (const auto &itr : BIP39_Utils::base16Encode({ prvkey.begin(), prvkey.end()})) {
      std::cout << itr;
   }
   std::cout << "\n";
   std::vector<uint8_t> pubkey =obj.getPublicKey();

   std::cout << "public Key compressed : ";
   for (const auto &itr : BIP39_Utils::base16Encode({ pubkey.begin(), pubkey.end()})) {
      std::cout << itr;
   }
   std::cout << "\n";

   std::vector<uint8_t> uncompressed = obj.getuncompressedPubkey();
    std::string str{uncompressed.begin(),uncompressed.end()};
    std::cout << "public Key uncompressed : "<<BIP39_Utils::base16Encode(str);

    //** Signature *//*
   std::vector<unsigned char> msg={'a', 'b', 'c', '\0'};
   std::string sign=obj.signatureBIP32(msg);

   //** Main Address **//*
   std::string addr = obj.getMaster().mainAddr();

   //** Wallet Import Format
   /* Private Key to WIF**/
   std::cout << "\n\t\tWIF \n";
   std::string wif = obj.getMaster().wif(obj.getPrivateKey());

   //** Wallet Import Format
   /* WIF to  Private Key*/
   std::string pKey =obj.getMaster().wifTokey(wif);

   /** Extended key derivation**/

   ExtendedKey ck;
//    uint32_t arr1[5] = {
//            0x80000000,
//            1,
//            0x80000002,
//            2,
//            1000000000
//    };
   std::string arr = {"0/2147483647'/1/2147483646'/2"};
   ExtendedKey par = obj.getMaster();

//     for (int i = 0; i <=arr->size()-1; i++) {
   std::cout << "\n New child: \n";
   ck = par.derivePath(arr);
   auto prvser = par.serializedKey(0x0488ade4);
   auto pubser = par.serializedKey(0x0488b21e);
   std::vector<char> cKey(128);
   std::vector<char> pubKey(128);

   base58_encode_check(prvser.data(), prvser.size(), &cKey[0], cKey.size());
   base58_encode_check(pubser.data(), pubser.size(), &pubKey[0], pubKey.size());
   std::cout << "-----------------------------------------------\n";
   std::cout << "CK PRVKey in B58 : " << std::string{cKey.begin(), cKey.end()} << std::endl;
   std::cout << "Ser PRVKey in hex: " << obj.HexStr(prvser.begin(), prvser.end()) << std::endl;
   std::cout << "CK pubKey in B58 : " << std::string{pubKey.begin(), pubKey.end()} << std::endl;
   std::cout << "Ser pubKey in hex: " << obj.HexStr(pubser.begin(), pubser.end()) << std::endl;
   //         par = ck;
//     }
   return 0;
}