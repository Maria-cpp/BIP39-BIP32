
add_library(cryptobip39
        sha224.cpp
        sha256.cpp
        sha384.cpp
        sha512.cpp
        hmac.cpp
        pbkdf2.cpp
        sha3.cpp
        strencodings.cpp
        ../bip39/utils.cpp
        ../bip39/wordlist.cpp
        ../bip39/mnemonic.cpp
        )
