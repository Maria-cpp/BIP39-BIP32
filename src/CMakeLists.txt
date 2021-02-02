add_subdirectory(secp256k1-cxx)
add_subdirectory(BIP39)
include_directories(secp256k1-cxx)

add_executable(main main.cpp masterkey.h masterkey.cpp extendedkey.h extendedkey.cpp)
TARGET_LINK_LIBRARIES(main secp256k1-cxx)

add_executable(seed seed.cpp BIP39/bip39/BIP39.cpp BIP39/bip39/BIP39.h)
target_link_libraries(seed cryptobip39)