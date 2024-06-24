#include <cstdint>
#if defined(_WIN32)
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <immintrin.h>
#include <Windows.h>
#else
#include <x86intrin.h>
#endif
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>
#include <array>
#include <atomic>
#include <mutex>
#include <string>
#include <list>
#include <set>
#include <utility>
#include <chrono>
#include "print.hpp"

void sha256_process_x86(uint32_t state[8], const uint8_t data[], uint32_t length);

namespace
{
    const uint64_t max_position = UINT64_C(1) << (8*6);
    std::atomic<uint64_t> job_counter = 0;
    std::array<uint32_t, 4> best_result { 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU };
    std::mutex best_mutex;
    std::mutex print_mutex;
    uint8_t alphabet[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
}

void print_result(const std::array<uint8_t, 64>& block)
{
    std::array<uint32_t, 8> state {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };
    sha256_process_x86(state.data(), block.data(), 64);

    std::lock_guard lock(print_mutex);
    for(int i = 0; i < 8; i++)
        print("{:08x} ", state[i]);

    for(int i = 0; i < 52; i++)
        print("{:c}", block[i]);
    print("\n");
}

// Check the result to see if it is better than the current best.
// Only the first 128 bits of the hash are checked.
inline void check_result(__m128i state0, const std::array<uint8_t, 64>& block)
{
    alignas(__m128i) uint32_t temp[4];

    _mm_store_si128((__m128i*)temp, state0);

    // Ignore all results where the first 32 bits are not 0
    if(temp[3] != 0)
        return;

    auto result = std::to_array({temp[3], temp[2], temp[1], temp[0]});

    std::lock_guard lock(best_mutex);
    if(result >= best_result)
        return;

    best_result = result;
    print_result(block);
}

//
// Process one chunk
//
// This function will check the hash of 2^24 strings. The bytes at
// position 48-51 in the data block will be changed for each string.
//
// By starting at position 48, the first 12 rounds of the sha256
// calculation can be precalculated.
//
// This function is based on the code by Jeffrey Walton (see
// sha256-x86.cpp).
//
void process_chunk(const std::array<uint8_t, 64>& input_data)
{
    // Number of blocks to process for each iteration in the inner
    // loop. Only 2, 4, 8, 16 and 32 are valid values. 16 seems to
    // work best for me.
    const int num_blocks = 16;

    // Copy the input data
    alignas(__m128i) std::array<std::array<uint8_t, 64>, num_blocks> data;
    std::copy(input_data.begin(), input_data.end(), data[0].begin());

    // Duplicate for each block
    for(int i = 1; i < num_blocks; i++)
        std::copy(data[0].begin(), data[0].end(), data[i].begin());

    const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    // Set initial state
    __m128i initial_STATE0 = _mm_set_epi64x(0x6a09e667bb67ae85, 0x510e527f9b05688c);
    __m128i initial_STATE1 = _mm_set_epi64x(0x3c6ef372a54ff53a, 0x1f83d9ab5be0cd19);

    // Calc first 12 rounds
    __m128i STATE0 = initial_STATE0;
    __m128i STATE1 = initial_STATE1;

    __m128i MSG,MSG0,MSG1,MSG2,TMP;

    //
    // Precalculate the first 12 rounds
    //

    /* Rounds 0-3 */
    MSG = _mm_load_si128((const __m128i*) (data[0].data()+0));
    MSG0 = _mm_shuffle_epi8(MSG, MASK);
    MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Rounds 4-7 */
    MSG1 = _mm_load_si128((const __m128i*) (data[0].data()+16));
    MSG1 = _mm_shuffle_epi8(MSG1, MASK);
    MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    /* Rounds 8-11 */
    MSG2 = _mm_load_si128((const __m128i*) (data[0].data()+32));
    MSG2 = _mm_shuffle_epi8(MSG2, MASK);
    MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    // Save state after round 12
    __m128i round12_STATE0 = STATE0;
    __m128i round12_STATE1 = STATE1;
    __m128i round12_MSG0 = MSG0;
    __m128i round12_MSG1 = MSG1;
    __m128i round12_MSG2 = MSG2;

    __m128i aSTATE0,aSTATE1,aMSG,aMSG0,aMSG1,aMSG2,aMSG3,aTMP;
    __m128i bSTATE0,bSTATE1,bMSG,bMSG0,bMSG1,bMSG2,bMSG3,bTMP;

    for(int i012 = 0; i012 < 64*64*64; i012++)
    {
        // Set the first 3 characters
        uint8_t v0 = alphabet[(i012>>12) & 63];
        uint8_t v1 = alphabet[(i012>>6) & 63];
        uint8_t v2 = alphabet[(i012>>0) & 63];

        for(int i = 0; i < num_blocks; i++)
        {
            data[i][48] = v0;
            data[i][49] = v1;
            data[i][50] = v2;
        }

        // The inner loop
        for(int i3 = 0; i3 < 64; i3 += num_blocks)
        {
            // Set the 4th character
            for(int i = 0; i < num_blocks; i++)
                data[i][51] = alphabet[i3 + i];

            // To speed things up, this loop has been unrolled and
            // calculation of two and two hashes are
            // interleaved. Interleaving is (probably) faster because
            // each operation in the sha256 usually depends on the
            // previous one.

#define V3_INNER(N)  \
            /* Set start state */ \
            aSTATE0 = round12_STATE0; \
            bSTATE0 = round12_STATE0; \
            aSTATE1 = round12_STATE1; \
            bSTATE1 = round12_STATE1; \
            aMSG0 = round12_MSG0; \
            bMSG0 = round12_MSG0; \
            aMSG1 = round12_MSG1; \
            bMSG1 = round12_MSG1; \
            aMSG2 = round12_MSG2; \
            bMSG2 = round12_MSG2; \
            \
            /* Rounds 12-15 */ \
            aMSG3 = _mm_load_si128((const __m128i*) (data[(N)+0].data()+48)); \
            bMSG3 = _mm_load_si128((const __m128i*) (data[(N)+1].data()+48)); \
            aMSG3 = _mm_shuffle_epi8(aMSG3, MASK); \
            bMSG3 = _mm_shuffle_epi8(bMSG3, MASK); \
            aMSG = _mm_add_epi32(aMSG3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL)); \
            bMSG = _mm_add_epi32(bMSG3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL)); \
            aSTATE1 = _mm_sha256rnds2_epu32(aSTATE1, aSTATE0, aMSG); \
            bSTATE1 = _mm_sha256rnds2_epu32(bSTATE1, bSTATE0, bMSG); \
            aTMP = _mm_alignr_epi8(aMSG3, aMSG2, 4); \
            bTMP = _mm_alignr_epi8(bMSG3, bMSG2, 4); \
            aMSG0 = _mm_add_epi32(aMSG0, aTMP); \
            bMSG0 = _mm_add_epi32(bMSG0, bTMP); \
            aMSG0 = _mm_sha256msg2_epu32(aMSG0, aMSG3); \
            bMSG0 = _mm_sha256msg2_epu32(bMSG0, bMSG3); \
            aMSG = _mm_shuffle_epi32(aMSG, 0x0E); \
            bMSG = _mm_shuffle_epi32(bMSG, 0x0E); \
            aSTATE0 = _mm_sha256rnds2_epu32(aSTATE0, aSTATE1, aMSG); \
            bSTATE0 = _mm_sha256rnds2_epu32(bSTATE0, bSTATE1, bMSG); \
            aMSG2 = _mm_sha256msg1_epu32(aMSG2, aMSG3); \
            bMSG2 = _mm_sha256msg1_epu32(bMSG2, bMSG3); \
            \
            /* Rounds 16-19 */ \
            aMSG = _mm_add_epi32(aMSG0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL)); \
            bMSG = _mm_add_epi32(bMSG0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL)); \
            aSTATE1 = _mm_sha256rnds2_epu32(aSTATE1, aSTATE0, aMSG); \
            bSTATE1 = _mm_sha256rnds2_epu32(bSTATE1, bSTATE0, bMSG); \
            aTMP = _mm_alignr_epi8(aMSG0, aMSG3, 4); \
            bTMP = _mm_alignr_epi8(bMSG0, bMSG3, 4); \
            aMSG1 = _mm_add_epi32(aMSG1, aTMP); \
            bMSG1 = _mm_add_epi32(bMSG1, bTMP); \
            aMSG1 = _mm_sha256msg2_epu32(aMSG1, aMSG0); \
            bMSG1 = _mm_sha256msg2_epu32(bMSG1, bMSG0); \
            aMSG = _mm_shuffle_epi32(aMSG, 0x0E); \
            bMSG = _mm_shuffle_epi32(bMSG, 0x0E); \
            aSTATE0 = _mm_sha256rnds2_epu32(aSTATE0, aSTATE1, aMSG); \
            bSTATE0 = _mm_sha256rnds2_epu32(bSTATE0, bSTATE1, bMSG); \
            aMSG3 = _mm_sha256msg1_epu32(aMSG3, aMSG0); \
            bMSG3 = _mm_sha256msg1_epu32(bMSG3, bMSG0); \
            \
            /* Rounds 20-23 */ \
            aMSG = _mm_add_epi32(aMSG1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL)); \
            bMSG = _mm_add_epi32(bMSG1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL)); \
            aSTATE1 = _mm_sha256rnds2_epu32(aSTATE1, aSTATE0, aMSG); \
            bSTATE1 = _mm_sha256rnds2_epu32(bSTATE1, bSTATE0, bMSG); \
            aTMP = _mm_alignr_epi8(aMSG1, aMSG0, 4); \
            bTMP = _mm_alignr_epi8(bMSG1, bMSG0, 4); \
            aMSG2 = _mm_add_epi32(aMSG2, aTMP); \
            bMSG2 = _mm_add_epi32(bMSG2, bTMP); \
            aMSG2 = _mm_sha256msg2_epu32(aMSG2, aMSG1); \
            bMSG2 = _mm_sha256msg2_epu32(bMSG2, bMSG1); \
            aMSG = _mm_shuffle_epi32(aMSG, 0x0E); \
            bMSG = _mm_shuffle_epi32(bMSG, 0x0E); \
            aSTATE0 = _mm_sha256rnds2_epu32(aSTATE0, aSTATE1, aMSG); \
            bSTATE0 = _mm_sha256rnds2_epu32(bSTATE0, bSTATE1, bMSG); \
            aMSG0 = _mm_sha256msg1_epu32(aMSG0, aMSG1); \
            bMSG0 = _mm_sha256msg1_epu32(bMSG0, bMSG1); \
            \
            /* Rounds 24-27 */ \
            aMSG = _mm_add_epi32(aMSG2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL)); \
            bMSG = _mm_add_epi32(bMSG2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL)); \
            aSTATE1 = _mm_sha256rnds2_epu32(aSTATE1, aSTATE0, aMSG); \
            bSTATE1 = _mm_sha256rnds2_epu32(bSTATE1, bSTATE0, bMSG); \
            aTMP = _mm_alignr_epi8(aMSG2, aMSG1, 4); \
            bTMP = _mm_alignr_epi8(bMSG2, bMSG1, 4); \
            aMSG3 = _mm_add_epi32(aMSG3, aTMP); \
            bMSG3 = _mm_add_epi32(bMSG3, bTMP); \
            aMSG3 = _mm_sha256msg2_epu32(aMSG3, aMSG2); \
            bMSG3 = _mm_sha256msg2_epu32(bMSG3, bMSG2); \
            aMSG = _mm_shuffle_epi32(aMSG, 0x0E); \
            bMSG = _mm_shuffle_epi32(bMSG, 0x0E); \
            aSTATE0 = _mm_sha256rnds2_epu32(aSTATE0, aSTATE1, aMSG); \
            bSTATE0 = _mm_sha256rnds2_epu32(bSTATE0, bSTATE1, bMSG); \
            aMSG1 = _mm_sha256msg1_epu32(aMSG1, aMSG2); \
            bMSG1 = _mm_sha256msg1_epu32(bMSG1, bMSG2); \
            \
            /* Rounds 28-31 */ \
            aMSG = _mm_add_epi32(aMSG3, _mm_set_epi64x(0x1429296706CA6351ULL,  0xD5A79147C6E00BF3ULL)); \
            bMSG = _mm_add_epi32(bMSG3, _mm_set_epi64x(0x1429296706CA6351ULL,  0xD5A79147C6E00BF3ULL)); \
            aSTATE1 = _mm_sha256rnds2_epu32(aSTATE1, aSTATE0, aMSG); \
            bSTATE1 = _mm_sha256rnds2_epu32(bSTATE1, bSTATE0, bMSG); \
            aTMP = _mm_alignr_epi8(aMSG3, aMSG2, 4); \
            bTMP = _mm_alignr_epi8(bMSG3, bMSG2, 4); \
            aMSG0 = _mm_add_epi32(aMSG0, aTMP); \
            bMSG0 = _mm_add_epi32(bMSG0, bTMP); \
            aMSG0 = _mm_sha256msg2_epu32(aMSG0, aMSG3); \
            bMSG0 = _mm_sha256msg2_epu32(bMSG0, bMSG3); \
            aMSG = _mm_shuffle_epi32(aMSG, 0x0E); \
            bMSG = _mm_shuffle_epi32(bMSG, 0x0E); \
            aSTATE0 = _mm_sha256rnds2_epu32(aSTATE0, aSTATE1, aMSG); \
            bSTATE0 = _mm_sha256rnds2_epu32(bSTATE0, bSTATE1, bMSG); \
            aMSG2 = _mm_sha256msg1_epu32(aMSG2, aMSG3); \
            bMSG2 = _mm_sha256msg1_epu32(bMSG2, bMSG3); \
            \
            /* Rounds 32-35 */ \
            aMSG = _mm_add_epi32(aMSG0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL)); \
            bMSG = _mm_add_epi32(bMSG0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL)); \
            aSTATE1 = _mm_sha256rnds2_epu32(aSTATE1, aSTATE0, aMSG); \
            bSTATE1 = _mm_sha256rnds2_epu32(bSTATE1, bSTATE0, bMSG); \
            aTMP = _mm_alignr_epi8(aMSG0, aMSG3, 4); \
            bTMP = _mm_alignr_epi8(bMSG0, bMSG3, 4); \
            aMSG1 = _mm_add_epi32(aMSG1, aTMP); \
            bMSG1 = _mm_add_epi32(bMSG1, bTMP); \
            aMSG1 = _mm_sha256msg2_epu32(aMSG1, aMSG0); \
            bMSG1 = _mm_sha256msg2_epu32(bMSG1, bMSG0); \
            aMSG = _mm_shuffle_epi32(aMSG, 0x0E); \
            bMSG = _mm_shuffle_epi32(bMSG, 0x0E); \
            aSTATE0 = _mm_sha256rnds2_epu32(aSTATE0, aSTATE1, aMSG); \
            bSTATE0 = _mm_sha256rnds2_epu32(bSTATE0, bSTATE1, bMSG); \
            aMSG3 = _mm_sha256msg1_epu32(aMSG3, aMSG0); \
            bMSG3 = _mm_sha256msg1_epu32(bMSG3, bMSG0); \
            \
            /* Rounds 36-39 */ \
            aMSG = _mm_add_epi32(aMSG1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL)); \
            bMSG = _mm_add_epi32(bMSG1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL)); \
            aSTATE1 = _mm_sha256rnds2_epu32(aSTATE1, aSTATE0, aMSG); \
            bSTATE1 = _mm_sha256rnds2_epu32(bSTATE1, bSTATE0, bMSG); \
            aTMP = _mm_alignr_epi8(aMSG1, aMSG0, 4); \
            bTMP = _mm_alignr_epi8(bMSG1, bMSG0, 4); \
            aMSG2 = _mm_add_epi32(aMSG2, aTMP); \
            bMSG2 = _mm_add_epi32(bMSG2, bTMP); \
            aMSG2 = _mm_sha256msg2_epu32(aMSG2, aMSG1); \
            bMSG2 = _mm_sha256msg2_epu32(bMSG2, bMSG1); \
            aMSG = _mm_shuffle_epi32(aMSG, 0x0E); \
            bMSG = _mm_shuffle_epi32(bMSG, 0x0E); \
            aSTATE0 = _mm_sha256rnds2_epu32(aSTATE0, aSTATE1, aMSG); \
            bSTATE0 = _mm_sha256rnds2_epu32(bSTATE0, bSTATE1, bMSG); \
            aMSG0 = _mm_sha256msg1_epu32(aMSG0, aMSG1); \
            bMSG0 = _mm_sha256msg1_epu32(bMSG0, bMSG1); \
            \
            /* Rounds 40-43 */ \
            aMSG = _mm_add_epi32(aMSG2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL)); \
            bMSG = _mm_add_epi32(bMSG2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL)); \
            aSTATE1 = _mm_sha256rnds2_epu32(aSTATE1, aSTATE0, aMSG); \
            bSTATE1 = _mm_sha256rnds2_epu32(bSTATE1, bSTATE0, bMSG); \
            aTMP = _mm_alignr_epi8(aMSG2, aMSG1, 4); \
            bTMP = _mm_alignr_epi8(bMSG2, bMSG1, 4); \
            aMSG3 = _mm_add_epi32(aMSG3, aTMP); \
            bMSG3 = _mm_add_epi32(bMSG3, bTMP); \
            aMSG3 = _mm_sha256msg2_epu32(aMSG3, aMSG2); \
            bMSG3 = _mm_sha256msg2_epu32(bMSG3, bMSG2); \
            aMSG = _mm_shuffle_epi32(aMSG, 0x0E); \
            bMSG = _mm_shuffle_epi32(bMSG, 0x0E); \
            aSTATE0 = _mm_sha256rnds2_epu32(aSTATE0, aSTATE1, aMSG); \
            bSTATE0 = _mm_sha256rnds2_epu32(bSTATE0, bSTATE1, bMSG); \
            aMSG1 = _mm_sha256msg1_epu32(aMSG1, aMSG2); \
            bMSG1 = _mm_sha256msg1_epu32(bMSG1, bMSG2); \
            \
            /* Rounds 44-47 */ \
            aMSG = _mm_add_epi32(aMSG3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL)); \
            bMSG = _mm_add_epi32(bMSG3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL)); \
            aSTATE1 = _mm_sha256rnds2_epu32(aSTATE1, aSTATE0, aMSG); \
            bSTATE1 = _mm_sha256rnds2_epu32(bSTATE1, bSTATE0, bMSG); \
            aTMP = _mm_alignr_epi8(aMSG3, aMSG2, 4); \
            bTMP = _mm_alignr_epi8(bMSG3, bMSG2, 4); \
            aMSG0 = _mm_add_epi32(aMSG0, aTMP); \
            bMSG0 = _mm_add_epi32(bMSG0, bTMP); \
            aMSG0 = _mm_sha256msg2_epu32(aMSG0, aMSG3); \
            bMSG0 = _mm_sha256msg2_epu32(bMSG0, bMSG3); \
            aMSG = _mm_shuffle_epi32(aMSG, 0x0E); \
            bMSG = _mm_shuffle_epi32(bMSG, 0x0E); \
            aSTATE0 = _mm_sha256rnds2_epu32(aSTATE0, aSTATE1, aMSG); \
            bSTATE0 = _mm_sha256rnds2_epu32(bSTATE0, bSTATE1, bMSG); \
            aMSG2 = _mm_sha256msg1_epu32(aMSG2, aMSG3); \
            bMSG2 = _mm_sha256msg1_epu32(bMSG2, bMSG3); \
            \
            /* Rounds 48-51 */ \
            aMSG = _mm_add_epi32(aMSG0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL)); \
            bMSG = _mm_add_epi32(bMSG0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL)); \
            aSTATE1 = _mm_sha256rnds2_epu32(aSTATE1, aSTATE0, aMSG); \
            bSTATE1 = _mm_sha256rnds2_epu32(bSTATE1, bSTATE0, bMSG); \
            aTMP = _mm_alignr_epi8(aMSG0, aMSG3, 4); \
            bTMP = _mm_alignr_epi8(bMSG0, bMSG3, 4); \
            aMSG1 = _mm_add_epi32(aMSG1, aTMP); \
            bMSG1 = _mm_add_epi32(bMSG1, bTMP); \
            aMSG1 = _mm_sha256msg2_epu32(aMSG1, aMSG0); \
            bMSG1 = _mm_sha256msg2_epu32(bMSG1, bMSG0); \
            aMSG = _mm_shuffle_epi32(aMSG, 0x0E); \
            bMSG = _mm_shuffle_epi32(bMSG, 0x0E); \
            aSTATE0 = _mm_sha256rnds2_epu32(aSTATE0, aSTATE1, aMSG); \
            bSTATE0 = _mm_sha256rnds2_epu32(bSTATE0, bSTATE1, bMSG); \
            aMSG3 = _mm_sha256msg1_epu32(aMSG3, aMSG0); \
            bMSG3 = _mm_sha256msg1_epu32(bMSG3, bMSG0); \
            \
            /* Rounds 52-55 */ \
            aMSG = _mm_add_epi32(aMSG1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL)); \
            bMSG = _mm_add_epi32(bMSG1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL)); \
            aSTATE1 = _mm_sha256rnds2_epu32(aSTATE1, aSTATE0, aMSG); \
            bSTATE1 = _mm_sha256rnds2_epu32(bSTATE1, bSTATE0, bMSG); \
            aTMP = _mm_alignr_epi8(aMSG1, aMSG0, 4); \
            bTMP = _mm_alignr_epi8(bMSG1, bMSG0, 4); \
            aMSG2 = _mm_add_epi32(aMSG2, aTMP); \
            bMSG2 = _mm_add_epi32(bMSG2, bTMP); \
            aMSG2 = _mm_sha256msg2_epu32(aMSG2, aMSG1); \
            bMSG2 = _mm_sha256msg2_epu32(bMSG2, bMSG1); \
            aMSG = _mm_shuffle_epi32(aMSG, 0x0E); \
            bMSG = _mm_shuffle_epi32(bMSG, 0x0E); \
            aSTATE0 = _mm_sha256rnds2_epu32(aSTATE0, aSTATE1, aMSG); \
            bSTATE0 = _mm_sha256rnds2_epu32(bSTATE0, bSTATE1, bMSG); \
            \
            /* Rounds 56-59 */ \
            aMSG = _mm_add_epi32(aMSG2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL)); \
            bMSG = _mm_add_epi32(bMSG2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL)); \
            aSTATE1 = _mm_sha256rnds2_epu32(aSTATE1, aSTATE0, aMSG); \
            bSTATE1 = _mm_sha256rnds2_epu32(bSTATE1, bSTATE0, bMSG); \
            aTMP = _mm_alignr_epi8(aMSG2, aMSG1, 4); \
            bTMP = _mm_alignr_epi8(bMSG2, bMSG1, 4); \
            aMSG3 = _mm_add_epi32(aMSG3, aTMP); \
            bMSG3 = _mm_add_epi32(bMSG3, bTMP); \
            aMSG3 = _mm_sha256msg2_epu32(aMSG3, aMSG2); \
            bMSG3 = _mm_sha256msg2_epu32(bMSG3, bMSG2); \
            aMSG = _mm_shuffle_epi32(aMSG, 0x0E); \
            bMSG = _mm_shuffle_epi32(bMSG, 0x0E); \
            aSTATE0 = _mm_sha256rnds2_epu32(aSTATE0, aSTATE1, aMSG); \
            bSTATE0 = _mm_sha256rnds2_epu32(bSTATE0, bSTATE1, bMSG); \
            \
            /* Rounds 60-63 */ \
            aMSG = _mm_add_epi32(aMSG3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL)); \
            bMSG = _mm_add_epi32(bMSG3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL)); \
            aSTATE1 = _mm_sha256rnds2_epu32(aSTATE1, aSTATE0, aMSG); \
            bSTATE1 = _mm_sha256rnds2_epu32(bSTATE1, bSTATE0, bMSG); \
            aMSG = _mm_shuffle_epi32(aMSG, 0x0E); \
            bMSG = _mm_shuffle_epi32(bMSG, 0x0E); \
            aSTATE0 = _mm_sha256rnds2_epu32(aSTATE0, aSTATE1, aMSG); \
            bSTATE0 = _mm_sha256rnds2_epu32(bSTATE0, bSTATE1, bMSG); \
            \
            /* Combine state  */ \
            aSTATE0 = _mm_add_epi32(aSTATE0, initial_STATE0); \
            bSTATE0 = _mm_add_epi32(bSTATE0, initial_STATE0); \
            \
            check_result(aSTATE0, data[(N)+0]);    \
            check_result(bSTATE0, data[(N)+1]);

            V3_INNER(0);
            if constexpr(num_blocks >= 4)
            {
                V3_INNER(2);
            }
            if constexpr(num_blocks >= 8)
            {
                V3_INNER(4);
                V3_INNER(6);
            }
            if constexpr(num_blocks >= 16)
            {
                V3_INNER(8);
                V3_INNER(10);
                V3_INNER(12);
                V3_INNER(14);
            }
            if constexpr(num_blocks >= 32)
            {
                V3_INNER(16);
                V3_INNER(18);
                V3_INNER(20);
                V3_INNER(22);
                V3_INNER(24);
                V3_INNER(26);
                V3_INNER(28);
                V3_INNER(30);
            }
        }
    }
}

void thread_func(const std::array<uint8_t, 64>& input_block, uint64_t job_limit)
{
    // Make a copy of the input block
    alignas(__m128i) std::array<uint8_t, 64> block = input_block;

    // Run the loop as long as there are jobs
    for(;;)
    {
        uint64_t counter = job_counter.fetch_add(1U);
        if(counter >= job_limit)
            break;
        if(counter > 0 && (counter & 65535) == 0)
        {
            std::lock_guard lock(print_mutex);
            print("Progress: {}\n", counter);
        }
        // Write counter as 8 character string (backwards)
        for(int i = 47; i > 47-8; i--)
        {
            block[i] = alphabet[counter % 64U];
            counter /= 64U;
        }

        process_chunk(block);
    }
}

void run(
    const std::array<uint8_t, 64>& block,
    unsigned long num_threads,
    uint64_t start, uint64_t end)
{
    print("Running with {} threads from {} to {}\n", num_threads, start, end);

    job_counter = start;
    std::vector<std::thread> threads;
    for(unsigned int i = 0; i < num_threads; i++)
        threads.push_back(std::thread(thread_func, block, end));

    for(auto& thread : threads)
        thread.join();
}

// Create the prefix, which is username/seed/ padded with /'s up to 40 bytes
std::array<uint8_t, 40> create_padded_prefix(
    const std::string& username,
    const std::string& seed)
{
    std::string temp = username;
    temp += "/";
    temp += seed;
    temp += "/";

    std::array<uint8_t, 40> output;
    if(temp.size() > output.size())
        throw std::runtime_error("username/prefix too long");

    size_t i = 0;
    for(; i < temp.size(); i++)
        output[i] = uint8_t(temp[i]);
    for(;i < output.size(); i++)
        output[i] = '/';
    return output;
}

std::array<uint8_t, 64> create_block(
    const std::array<uint8_t, 40>& prefix)
{
    std::array<uint8_t, 64> block { 0 };

    // Put the prefix at the beginning
    std::copy(prefix.begin(), prefix.end(), block.begin());

    // Set end padding and size
    const uint16_t size = 52 * 8;
    block[52] = 0x80;
    block[62] = size >> 8;
    block[63] = size & 255;
    return block;
}

template<typename T>
T pop(std::list<T>& list)
{
    T output = list.front();
    list.pop_front();
    return output;
}

template<typename T> T parse(const std::string& str);

template<> unsigned long parse<unsigned long>(const std::string& str)
{
    if(!str.empty() && str[0] == '-')
        throw std::runtime_error(std::format("Invalid integer '{}'", str));
    std::size_t num_processed;
    auto value = std::stoul(str, &num_processed, 0);
    if(num_processed != str.size())
        throw std::runtime_error(std::format("Invalid integer '{}'", str));
    return value;
}

template<> unsigned long long parse<unsigned long long>(const std::string& str)
{
    if(!str.empty() && str[0] == '-')
        throw std::runtime_error(std::format("Invalid integer '{}'", str));
    std::size_t num_processed;
    auto value = std::stoul(str, &num_processed, 0);
    if(num_processed != str.size())
        throw std::runtime_error(std::format("Invalid integer '{}'", str));
    return value;
}

void validate_string(const std::string& string)
{
    std::set<char> valid_chars;
    for(uint8_t* ptr = alphabet; ptr != alphabet+64; ++ptr)
        valid_chars.insert(*ptr);

    for(auto ch : string)
    {
        if(!valid_chars.contains(ch))
            throw std::runtime_error(std::format("Invalid characters in '{}'", string));
    }
}

[[noreturn]] void print_help_and_exit(const std::string& program)
{
    print("Usage: {} [-b] [-t num] [-s start] [-e end] username seed\n", program);
    print("  -b/--benchmark    : Run benchmark\n");
    print("  -t/--threads num  : Set number of threads\n");
    print("  -s/--start num    : Set start position\n");
    print("  -e/--end num      : Set end position\n");
    print("");
    std::exit(0);
}

auto parse_arguments(int argc, char** argv)
{
    struct
    {
        unsigned long num_threads = std::max(1U, std::thread::hardware_concurrency());
        uint64_t start = 0;
        uint64_t end = max_position;
        std::string user;
        std::string seed;
    } output;

    std::list<std::string> args;
    for(int i = 1; i < argc; i++)
        args.push_back(argv[i]);

    bool start_or_end_set = false;
    bool benchmark = false;
    while(!args.empty())
    {
        auto arg = pop(args);
        if(arg.empty())
            continue;

        if(arg[0] != '-')
        {
            args.push_front(arg);
            break;
        }
        if(arg == "-h" || arg == "--help")
        {
            print_help_and_exit(argv[0]);
        }
        else if(arg == "-b" || arg == "--benchmark")
        {
            benchmark = true;
        }
        else if(arg == "-t" || arg == "--threads")
        {
            if(args.empty())
                throw std::runtime_error("Missing number of threads argument");
            output.num_threads = parse<unsigned long>(pop(args));
            if(output.num_threads < 1)
                throw std::runtime_error("Minimum number of threads is 1");
        }
        else if(arg == "-s" || arg == "--start")
        {
            if(args.empty())
                throw std::runtime_error("Missing start position argument");
            output.start = parse<uint64_t>(pop(args));
            if(output.start >= max_position)
                throw std::runtime_error(std::format("Start position must be less than {}", max_position));
            start_or_end_set = true;
        }
        else if(arg == "-e" || arg == "--end")
        {
            if(args.empty())
                throw std::runtime_error("Missing end position argument");
            output.end = parse<uint64_t>(pop(args));
            if(output.end > max_position)
                throw std::runtime_error(std::format("End position must be less than or equal to {}", max_position));
            start_or_end_set = true;
        }
        else
        {
            throw std::runtime_error(std::format("Invalid argument '{}'", arg));
        }
    }

    if(benchmark)
    {
        if(!args.empty())
           throw std::runtime_error("Can't set username and seed when running benchmark");
        if(benchmark && start_or_end_set)
            throw std::runtime_error("Can't set start/end position when running benchmark");
        output.start = 0;
        output.end = 4096;
        output.user = "benchmark";
        output.seed = "shallenge";
    }
    else
    {
        if(args.size() < 2)
            throw std::runtime_error("Missing user and/or seed");
        if(args.size() > 2)
            throw std::runtime_error("Too many arguments");
        output.user = pop(args);
        output.seed = pop(args);

        if(output.start >= output.end)
            throw std::runtime_error("Start position must be less than end position");
    }

    validate_string(output.user);
    validate_string(output.seed);

    return output;
}

int main(int argc, char** argv)
{
    try
    {
        auto settings = parse_arguments(argc, argv);
        auto block = create_block(create_padded_prefix(settings.user, settings.seed));

        auto start_time = std::chrono::high_resolution_clock::now();
        run(block, settings.num_threads, settings.start, settings.end);
        auto end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> duration = {end_time - start_time};
        uint64_t num = std::max(UINT64_C(1), (settings.end - settings.start) << 24);

        print("{:.2f}s {:.0f}MH/s\n", duration.count(), (num / duration.count()) / 1e6);
    }
    catch(std::exception& e)
    {
        print("Error: {}\n", e.what());
    }
    return 0;
}
