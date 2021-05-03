add_library(bip32-cxx STATIC extendedkey.cpp masterkey.cpp BIP32.h BIP32.cpp)

#add_executable(BIP32 main.cpp extendedkey.cpp masterkey.cpp BIP32.h BIP32.cpp)
#target_link_libraries(BIP32 secp256k1-cxx)
#add_executable(seed seed.cpp)
#target_include_directories(bip32-cxx PRIVATE ../../)

target_link_libraries(bip32-cxx secp256k1-cxx bip39-cxx )
#target_link_libraries(BIP32 bip39-cxx )
#target_link_libraries(seed bip39-cxx crypto bip32-cxx )