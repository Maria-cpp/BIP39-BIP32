add_library(bip39-cxx SHARED BIP39.h BIP39.cpp)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/wordlists/english.txt
        DESTINATION ${CMAKE_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/wordlists/french.txt
        DESTINATION ${CMAKE_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/wordlists/spanish.txt
        DESTINATION ${CMAKE_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/wordlists/italian.txt
        DESTINATION ${CMAKE_BINARY_DIR})

