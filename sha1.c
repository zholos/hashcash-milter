/*
 * Part of Hashcash Milter version 0.1.2 from <http://althenia.net/hashcash>.
 *
 * Copyright 2010 Andrey Zholos.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "sha1.h"

#undef S
#define S(n, x) ((x) << (n) | (x) >> (32 - n))

void sha1_update(struct sha1_info* info) {
    uint32_t a, b, c, d, e, f, r;
    uint32_t u[16];
    uint32_t* w = &u[15];

    a = info->digest[0];
    b = info->digest[1];
    c = info->digest[2];
    d = info->digest[3];
    e = info->digest[4];

#undef M
#define M(i, a, b, c, d, e, f) \
      R(i,   a, b, c, d, e, f) \
      R(i+1, f, a, b, c, d, e) \
      R(i+2, e, f, a, b, c, d) \
      R(i+3, d, e, f, a, b, c) \
      R(i+4, c, d, e, f, a, b) \
      R(i+5, b, c, d, e, f, a)

#undef R
#define R(i, a, b, c, d, e, f) \
    f = S(5, a) + (b & (c ^ d) ^ d) + e + W(i) + 0x5a827999; \
    b = S(30, b);

#undef W
#define W(i) \
    (w[0-(i)] = info->data[i])

    M(0,  a, b, c, d, e, f)
    M(6,  a, b, c, d, e, f)
    R(12, a, b, c, d, e, f)
    R(13, f, a, b, c, d, e)
    R(14, e, f, a, b, c, d)
    R(15, d, e, f, a, b, c)

#undef W
#define W(i) \
    (r = w[0-(i+13)%16] ^ w[0-(i+8)%16] ^ w[0-(i+2)%16] ^ w[0-(i)%16], \
         w[0-(i)%16] = S(1, r))

    R(16, c, d, e, f, a, b)
    R(17, b, c, d, e, f, a)
    R(18, a, b, c, d, e, f)
    R(19, f, a, b, c, d, e)

#undef R
#define R(i, a, b, c, d, e, f) \
    f = S(5, a) + (b ^ c ^ d) + e + W(i) + 0x6ed9eba1; \
    b = S(30, b);

    M(20, e, f, a, b, c, d)
    M(26, e, f, a, b, c, d)
    M(32, e, f, a, b, c, d)
    R(38, e, f, a, b, c, d)
    R(39, d, e, f, a, b, c)

#undef R
#define R(i, a, b, c, d, e, f) \
    f = S(5, a) + (b & c | (b | c) & d) + e + W(i) + 0x8f1bbcdc; \
    b = S(30, b);

    M(40, c, d, e, f, a, b)
    M(46, c, d, e, f, a, b)
    M(52, c, d, e, f, a, b)
    R(58, c, d, e, f, a, b)
    R(59, b, c, d, e, f, a)

#undef R
#define R(i, a, b, c, d, e, f) \
    f = S(5, a) + (b ^ c ^ d) + e + W(i) + 0xca62c1d6; \
    b = S(30, b);

    M(60, a, b, c, d, e, f)
    M(66, a, b, c, d, e, f)
    M(72, a, b, c, d, e, f)
    R(78, a, b, c, d, e, f)
    R(79, f, a, b, c, d, e)

    info->digest[0] += e;
    info->digest[1] += f;
    info->digest[2] += a;
    info->digest[3] += b;
    info->digest[4] += c;
}

void sha1_begin(struct sha1_info* info) {
    int i;

    info->digest[0] = 0x67452301;
    info->digest[1] = 0xefcdab89;
    info->digest[2] = 0x98badcfe;
    info->digest[3] = 0x10325476;
    info->digest[4] = 0xc3d2e1f0;
    for (i = 0; i < 16; i++)
        info->data[i] = 0;
    info->size = 0;
}

void sha1_char(struct sha1_info* info, char data) {
    int i;

    info->data[info->size % 64 / 4] |=
        ((uint32_t)(unsigned char)data) << (3 - info->size % 4) * 8;
    if (++info->size % 64 == 0) {
        sha1_update(info);
        for (i = 0; i < 16; i++)
            info->data[i] = 0;
    }
}

void sha1_string(struct sha1_info* info, const char* data, size_t len) {
    size_t i;

    for (i = 0; i < len; i++)
        sha1_char(info, data[i]);
}

void sha1_done(struct sha1_info* info) {
    int i;

    info->data[info->size % 64 / 4] |=
        ((uint32_t)(unsigned char)'\200') << (3 - info->size % 4) * 8;
    if (info->size % 64 >= 56) {
        sha1_update(info);
        for (i = 0; i < 14; i++)
            info->data[i] = 0;
    }
    info->data[14] = info->size >> (32 - 3);
    info->data[15] = info->size << 3;
    sha1_update(info);
}

const char check_data[] =
    "cqlbzjiheywnpfktxrgmvuodasXFQVNAOTGDMSWIBPJCHRLUKZEY4268710935+=/";

const uint32_t check_hash[] = {
    0xda39a3ee, 0x5e6b4b0d, 0x3255bfef, 0x95601890, 0xafd80709,
    0x84a51684, 0x1ba77a5b, 0x4648de2c, 0xd0dfcb30, 0xea46dbb4,
    0x018d644a, 0x17b71b65, 0xcef51fa0, 0xa523a293, 0xf2b3266f,
    0xfdd400e5, 0xcc657385, 0x8bf7a3df, 0x79d50cf2, 0xd57be9be
};

const uint32_t check_xor[] = {
    0xafb2c16c, 0x3b093896, 0x631b16e7, 0x6cbf125a, 0xdc58ec67
};

int sha1_check() {
    int i, j;
    struct sha1_info info;
    uint32_t xor[5];

    for (j = 0; j < 5; j++)
        xor[j] = 0;

    for (i = 0; i < 196; i++) {
        sha1_begin(&info);
        for (j = i; j >= (int)(sizeof check_data - 1);
                j -= sizeof check_data - 1)
            sha1_string(&info, check_data, sizeof check_data - 1);
        sha1_string(&info, check_data, j);
        sha1_done(&info);

        if (i < 4)
            for (j = 0; j < 5; j++)
                if (info.digest[j] != check_hash[5*i+j])
                    return -1;

        for (j = 0; j < 5; j++)
            xor[j] ^= info.digest[j];
    };

    for (j = 0; j < 5; j++)
        if (xor[j] != check_xor[j])
            return -1;

    return 0;
}


#ifdef TEST
#include <stdio.h>
#include <string.h>

void print_hash(const char* data, size_t len) {
    int i, j;

    struct sha1_info info;
    sha1_begin(&info);
    sha1_string(&info, data, len);
    sha1_done(&info);

    for (i = 0; i < 5; i++)
        printf("%08x", info.digest[i]);
    putchar('\n');
}

int main() {
    char data[1024];
    char* s;

    while (fgets(data, sizeof(data), stdin) != NULL) {
        if ((s = strchr(data, '\n')) != NULL)
            *s = '\0';
        print_hash(data, strlen(data));
    }

    return 0;
}
#endif /* TEST */
