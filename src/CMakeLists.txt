add_subdirectory(bip39)
add_subdirectory(secp256k1-cxx)

add_library(crypto STATIC
        base58.h
        base58.cpp
        sha224.h
        sha224.cpp
        sha256.h
        sha256.cpp
        sha384.h
        sha384.cpp
        sha512.h
        sha512.cpp
        hmac.h
        hmac.cpp
        pbkdf2.h
        pbkdf2.cpp
        sha3.h
        sha3.cpp
        md5.h
        md5.cpp
        sha1.h
        secp256k1-cxx/crypto/ripemd160.h
        secp256k1-cxx/crypto/ripemd160.cpp
        )
target_link_libraries(crypto secpcrypto)
add_library(bip39-cxx STATIC bip39/mnemonic.cpp bip39/wordlist.cpp bip39/utils.h bip39/utils.cpp bip39/BIP39.h bip39/BIP39.cpp)
if(${WIN32})
target_link_libraries(bip39-cxx PRIVATE crypto bcrypt)
else()
    target_link_libraries(bip39-cxx PRIVATE crypto )
endif()
    add_subdirectory(bip32/)

add_executable(BIP32 main.cpp bip32/extendedkey.cpp bip32/masterkey.cpp bip32/BIP32.h bip32/BIP32.cpp)
target_link_libraries(BIP32 secp256k1-cxx)
add_executable(seed seed.cpp)
target_include_directories(bip32-cxx PRIVATE ../../)

target_link_libraries(BIP32 bip39-cxx )
target_link_libraries(seed bip39-cxx crypto bip32-cxx )
