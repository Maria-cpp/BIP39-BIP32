add_subdirectory(secp256k1-cxx)
include_directories(secp256k1-cxx)

add_executable(main main.cpp masterkey.h masterkey.cpp extendedkey.h extendedkey.cpp)
TARGET_LINK_LIBRARIES(main secp256k1-cxx)