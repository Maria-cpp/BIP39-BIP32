/**
 * Copyright (c) 2000-2001 Aaron D. Gifford
 * Copyright (c) 2013-2014 Pavol Rusnak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef SHA512_H
#define SHA512_H

#include <array>
#include <cstdint>
#include <vector>
#include "secp256k1-cxx/crypto/sha2.hpp"

//static constexpr size_t SHA512_BLOCK_LENGTH = 128;
static constexpr size_t SHA512_RAW_BYTES_LENGTH = 64;
//static constexpr size_t SHA512_DIGEST_STRING_LENGTH = SHA512_RAW_BYTES_LENGTH * 2 + 1;*/

struct SHA512_CTX {
    std::array<uint64_t, 8> state = {0};
    std::array<uint64_t, 2> bitcount = {0};
    std::array<uint64_t, SHA512_BLOCK_LENGTH / sizeof(uint64_t)> buffer = {0};
};

void sha512_Init(SHA512_CTX* context);
void sha512_Transform(
    const std::array<uint64_t, 8>& state_in,
    const std::array<uint64_t, SHA512_BLOCK_LENGTH / sizeof(uint64_t)>& data,
    uint64_t* state_out);
void sha512_Update(SHA512_CTX* context, const uint8_t*, size_t);
void sha512_Final(SHA512_CTX* context, uint8_t out[SHA512_RAW_BYTES_LENGTH]);

/**
 * @brief takes `data` as input and outputs `out` as hash in raw bytes
 * @param data
 * @param len
 * @param out
 */
void sha512(const uint8_t* in, size_t inSize, uint8_t out[SHA512_RAW_BYTES_LENGTH]);


/**
 * @brief takes `data` as input and outputs `output` as hash in raw bytes
 * @param data
 * @param output
 */
template <typename In>
std::vector<uint8_t> sha512(const In& data)
{
    std::vector<uint8_t> output(SHA512_RAW_BYTES_LENGTH);

    using Type = typename std::decay<decltype(*data.begin())>::type;
    static_assert(std::is_same<Type, uint8_t>::value, "Container should have uint8_t value type");

    sha512(data.data(), data.size(), &output[0]);

    return output;
}

/**
 * @brief takes `data` as input and outputs `output` as hash in raw bytes
 * @param data
 * @param output
 */
template <>
std::vector<uint8_t> sha512<std::string>(const std::string& data);

#endif    // SHA512_H
