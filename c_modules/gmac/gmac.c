/*
 *  Copyright (C) 2018-2025 Texas Instruments Incorporated
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *    Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 *    Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the
 *    distribution.
 *
 *    Neither the name of Texas Instruments Incorporated nor the names of
 *    its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>


#if defined(_WIN32)
#  define DLL_EXPORT_API __declspec(dllexport)
#else
#  define DLL_EXPORT_API
#endif


#define DEFAULT_ARRAY_SIZE (4U)

/**
 * @brief Print an array of type uint32_t
 * 
 * @param arr pointer to the array
 * @param sz size of the array
 */
void printArray32(uint32_t *arr, size_t sz)
{
    for (uint8_t i = 0; i < sz; i++)
    {
        printf("%d ", arr[i]);
    }
    printf("\r\n");
}

/**
 * @brief Print an array of type uint64_t
 * 
 * @param arr pointer to the array
 * @param sz size of the array
 */
void printArray64(uint64_t *arr, size_t sz)
{
    for (uint8_t i = 0; i < sz; i++)
    {
        printf("%" PRIu64 "\n", arr[i]);
    }
    printf("\r\n");
}

/**
 * @brief reverse an array of type uint32_t
 * 
 * @param arr pointer to the array
 * @param sz size of the array
 */
void reverseArray32(uint32_t *arr, size_t size)
{
    size_t end = size /2 ;
    for(size_t i =0; i < end; i++)
    {
        uint32_t tmp = arr[i];
        arr[i] = arr[size-1-i];
        arr[size-1-i] = tmp;
    }
}

/**
 * @brief reverse an array of type uint64_t
 * 
 * @param arr pointer to the array
 * @param sz size of the array
 */
void reverseArray64(uint64_t *arr, size_t size)
{
    size_t end = size /2 ;
    for(size_t i =0; i < end; i++)
    {
        uint64_t tmp = arr[i];
        arr[i] = arr[size-1-i];
        arr[size-1-i] = tmp;
    }
}

/**
 * @brief reverse bits of uint32_t number
 * 
 * @param n number
 * @return reversed number
 */
uint32_t reverseBits32(uint32_t n)
{
    uint32_t reversed= 0 ;
    for(uint8_t i = 0; i < 32; i++)
    {
        if((n & (1UL<<i)) != 0)
        {
            reversed = reversed | (1UL << (31-i));
        }
    }
    return reversed;
}

/**
 * @brief reverse bits of uint64_t number
 * 
 * @param n number
 * @return reversed number
 */
uint64_t reverseBits64(uint64_t n) {
    uint64_t reversed= 0 ;
    for(uint8_t i = 0; i < 64; i++)
    {
        if((n & (1ULL<<i)) != 0)
        {
            reversed = reversed | (1ULL << (63-i));
        }
    }
    return reversed;
}

/**
 * @brief reverse the bit order of an array
 * 
 * @param arr pointer to the array
 * @param sz size of the array
 */
void reverseBitOrder32(uint32_t *arr, size_t size)
{
    reverseArray32(arr, size);
    for (int i = 0; i < size; i++)
    {
        arr[i] = reverseBits32(arr[i]);
    }
}


/**
 * @brief reverse the bit order of an array
 * 
 * @param arr pointer to the array
 * @param sz size of the array
 */
void reverseBitOrder64(uint64_t *arr, size_t size)
{
    reverseArray64(arr, size);
    for (int i = 0; i < size; i++)
    {
        arr[i] = reverseBits64(arr[i]);
    }
}

/**
 * @brief Function to calculate ghash of given data
 * 
 * Use this function to generate ghash of a given 128bit 
 * long bit stream. This function assumes this 128bit
 * stream is stored in dataIn argument which is an array
 * of uint32_t[4]. User has to make sure that dataIn len
 * is of 4 as this function does not performs the checks.
 * 
 * Similar logic is for the key. keyA is also 128bit long 
 * bit stream and is split as uint64_t[2]. User need to 
 * make sure that this array's lenght is 2 as this function
 * does not performs any check on the length of this array.
 * 
 * Final output is also 128bit and is stored in an array of 
 * type uint32_t[4]. Again user need to make sure that output
 * is of length 4.
 * 
 * @param dataIn 128bit long bit stream.
 * @param keyA 128bti long bit stream containing key.
 * @param output 128bit array where ghash will be stored. 
 */
DLL_EXPORT_API void cGhash(uint32_t *dataIn, uint64_t *keyA, uint32_t *output)
{
    uint64_t a_hi[32] = {0};
    uint64_t a_lo[32] = {0};
    uint64_t z_hi[32] = {0};
    uint64_t z_lo[32] = {0};

    uint64_t rresult_hi = 0;
    uint64_t rresult_lo = 0;

    uint64_t bit_mul = 0;
    uint64_t wz_lo = 0;
    uint64_t wz_hi = 0;

    for (unsigned int i = 0; i < DEFAULT_ARRAY_SIZE; i++)
    {
        uint32_t data_in = dataIn[3 - i];
        for (unsigned int bits = 0; bits < 32; bits++)
        {
            a_hi[bits] = ((uint64_t)((data_in >> (31UL - bits)) & 1UL)) * (keyA[1]);
            a_lo[bits] = ((uint64_t)((data_in >> (31UL - bits)) & 1UL)) * (keyA[0]);
        }

        for (unsigned int j = 0; j < 32; j++)
        {
            z_lo[j] = z_hi[j] = 0ULL;
            if (j == 0)
            {
                /*bit 0*/
                bit_mul = (a_lo[0] & 1ULL) ^ (rresult_hi >> 63ULL);
                wz_lo = (wz_lo & (~(1ULL))) | (bit_mul & 1ULL);
                /*bit 1*/
                bit_mul = (rresult_lo & 0x1ULL) ^ ((a_lo[0] >> 0x1ULL) & 0x1ULL) ^ (rresult_hi >> 63ULL);
                wz_lo = (wz_lo & ~((0x1ULL) << 1ULL)) | ((bit_mul & 0x11ULL) << 1ULL);
                /*bit 2*/
                bit_mul = ((rresult_lo >> 0x1ULL) & 0x1ULL) ^ ((a_lo[0] >> 0x2ULL) & 0x1ULL) ^ (rresult_hi >> 63ULL);
                wz_lo = (wz_lo & ~((0x1ULL) << 2ULL)) | ((bit_mul & 0x1ULL) << 0x2ULL);
                /*bit 3:6*/
                for (uint64_t k = 3ULL; k < 7ULL; k++)
                {
                    bit_mul = ((rresult_lo >> (k - 1)) & 1ULL) ^ ((a_lo[0] >> k) & 1ULL);
                    wz_lo = (wz_lo & ~(1ULL << k)) | ((bit_mul & 1ULL) << k);
                }
                /*bit 7*/
                bit_mul = ((rresult_lo >> 0x6ULL) & 0x1ULL) ^ ((a_lo[0] >> 0x7ULL) & 0x1ULL) ^ (rresult_hi >> 63ULL);
                wz_lo = (wz_lo & ~((0x1ULL) << 7ULL)) | ((bit_mul & 0x1ULL) << 0x7ULL);
                for (uint64_t k = 8ULL; k < 128ULL; k++)
                {
                    if (k <= 63ULL)
                    {
                        bit_mul = ((rresult_lo >> (k - 1ULL)) & 1ULL) ^ ((a_lo[0] >> k) & 1ULL);
                        wz_lo = (wz_lo & ~(1ULL << (k % 64ULL))) | ((bit_mul & 1ULL) << (k % 64ULL));
                    }
                    else if (k == 64ULL)
                    {
                        bit_mul = ((rresult_lo >> (k - 1ULL)) & 1ULL) ^ ((a_hi[0] >> (k % 64ULL)) & 1ULL);
                        wz_hi = (wz_hi & ~(1ULL << (k % 64ULL))) | ((bit_mul & 1ULL) << (k % 64ULL));
                    }
                    else
                    {
                        bit_mul = ((rresult_hi >> ((k - 1ULL) % 64ULL)) & 1ULL) ^ ((a_hi[0] >> (k % 64ULL)) & 1ULL);
                        wz_hi = (wz_hi & ~(1ULL << (k % 64ULL))) | ((bit_mul & 1ULL) << (k % 64ULL));
                    }
                }
                if (i == 0)
                {
                    z_hi[0] = a_hi[0];
                    z_lo[0] = a_lo[0];
                }
                else
                {
                    z_hi[0] = wz_hi;
                    z_lo[0] = wz_lo;
                }
            }
            else
            {
                /*bit 0*/
                bit_mul = (a_lo[j] & 0x1ULL) ^ (z_hi[j - 1ULL] >> 63ULL);
                z_lo[j] = z_lo[j] | (bit_mul & 0x1ULL);

                /*bit 1*/
                bit_mul = (z_lo[j - 1] & 0x1ULL) ^ ((a_lo[j] >> 0x1ULL) & 0x1ULL) ^ (z_hi[j - 1ULL] >> 63ULL);
                z_lo[j] = z_lo[j] | ((bit_mul & 0x1) << 0x1);

                /*bit 2*/
                bit_mul = ((z_lo[j - 1] >> 0x1ULL) & 0x1ULL) ^ ((a_lo[j] >> 0x2ULL) & 0x1ULL) ^ (z_hi[j - 1ULL] >> 63ULL);
                z_lo[j] = z_lo[j] | ((bit_mul & 0x1ULL) << 0x2ULL);

                /* bit 3:6 */
                for (uint64_t k = 3ULL; k < 7ULL; k++)
                {
                    bit_mul = ((z_lo[j - 1ULL] >> (k - 1ULL)) & 1ULL) ^ ((a_lo[j] >> k) & 1ULL);
                    z_lo[j] = z_lo[j] | ((bit_mul & 1ULL) << k);
                }

                /* bit 7 */
                bit_mul = ((z_lo[j - 1ULL] >> 6ULL) & 1ULL) ^ ((a_lo[j] >> 7ULL) & 1ULL) ^ (z_hi[j - 1ULL] >> 63ULL);
                z_lo[j] = z_lo[j] | ((bit_mul & 1ULL) << 7ULL);

                /* bit 8 */
                for (uint64_t k = 8ULL; k < 128ULL; k++)
                {
                    if (k <= 63ULL)
                    {
                        bit_mul = ((z_lo[j - 1ULL] >> (k - 1ULL)) & 1ULL) ^ ((a_lo[j] >> k) & 1ULL);
                        z_lo[j] = z_lo[j] | ((bit_mul & 1ULL) << k);
                    }
                    else if (k == 64ULL)
                    {
                        bit_mul = ((z_lo[j - 1] >> (k - 1ULL)) & 1ULL) ^ ((a_hi[j] >> (k % 64ULL)) & 1ULL);
                        z_hi[j] = z_hi[j] | ((bit_mul & 1ULL) << (k % 64ULL));
                    }
                    else
                    {
                        bit_mul = ((z_hi[j - 1ULL] >> ((k - 1ULL) % 64ULL)) & 1ULL) ^ ((a_hi[j] >> (k % 64ULL)) & 1ULL);
                        z_hi[j] = z_hi[j] | ((bit_mul & 1ULL) << (k % 64ULL));
                    }
                }
            }
        }

        rresult_hi = z_hi[31];
        rresult_lo = z_lo[31];
    }

    output[0] = (rresult_lo & 0xFFFFFFFFUL);
    output[1] = (rresult_lo >> 32) & 0xFFFFFFFFUL;
    output[2] = rresult_hi & 0xFFFFFFFFUL;
    output[3] = (rresult_hi >> 32) & 0xFFFFFFFFUL;
}

/**
 * @brief Function to generate gmac
 * 
 * Here all args are of length 128bit and other than 
 * keyA, all args are of type uint32_t[4]. User need 
 * to make sure that lenght of each array is of size 
 * 4 as this function performs no check on this. 
 * 
 * Similar argument is for keyA.
 * 
 * @param ctLow lower 128bits of counter value.
 * @param ctHigh upper 128bits of counter value.
 * @param aesData aes data.
 * @param keyA Key to perform gmac for the given data.
 * @param output array to save the results.
 */
DLL_EXPORT_API void cGmac(uint32_t *ctLow, uint32_t *ctHigh, uint32_t *aesData, uint64_t *keyA, uint32_t *output)
{
    uint32_t ghash_lo[4] = {0};
    uint32_t ghash_hi[4] = {0};

    uint32_t xored_input_hi[4] = {0};

    /*change the bit order*/
    reverseBitOrder32(ctLow, 4);
    reverseBitOrder32(ctHigh, 4);
    reverseBitOrder64(keyA, 2);

    /* stage 1 */
    cGhash(ctLow, (uint64_t *)keyA, ghash_lo);

    for (unsigned char i = 0; i < 4; i++)
    {
        xored_input_hi[i] = ctHigh[i] ^ ghash_lo[i];
    }
    /* stage 2 */
    cGhash(xored_input_hi, (uint64_t *)keyA, ghash_hi);

    reverseBitOrder32(ghash_hi, DEFAULT_ARRAY_SIZE);

    for (unsigned char i = 0; i < 4; i++)
    {
        output[i] = aesData[i] ^ ghash_hi[i];
    }
}
