#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define GET_BYTE(b, i) (b >> (i * 8)) & 0xFF
#define slr(t, l, r) ((t << l) ^ (t >> r))

#define BIGENDIAN(bytes, start) \
    (bytes[i] << 24) |          \
        (bytes[i + 1] << 16) |  \
        (bytes[i + 2] << 8) |   \
        (bytes[i + 3])

static const int32_t const
    sha256_constants[] = {
        0x428A2F98,
        0x71374491,
        0xB5C0FBCF,
        0xE9B5DBA5,
        0x3956C25B,
        0x59F111F1,
        0x923F82A4,
        0xAB1C5ED5,
        0xD807AA98,
        0x12835B01,
        0x243185BE,
        0x550C7DC3,
        0x72BE5D74,
        0x80DEB1FE,
        0x9BDC06A7,
        0xC19BF174,
        0xE49B69C1,
        0xEFBE4786,
        0x0FC19DC6,
        0x240CA1CC,
        0x2DE92C6F,
        0x4A7484AA,
        0x5CB0A9DC,
        0x76F988DA,
        0x983E5152,
        0xA831C66D,
        0xB00327C8,
        0xBF597FC7,
        0xC6E00BF3,
        0xD5A79147,
        0x06CA6351,
        0x14292967,
        0x27B70A85,
        0x2E1B2138,
        0x4D2C6DFC,
        0x53380D13,
        0x650A7354,
        0x766A0ABB,
        0x81C2C92E,
        0x92722C85,
        0xA2BFE8A1,
        0xA81A664B,
        0xC24B8B70,
        0xC76C51A3,
        0xD192E819,
        0xD6990624,
        0xF40E3585,
        0x106AA070,
        0x19A4C116,
        0x1E376C08,
        0x2748774C,
        0x34B0BCB5,
        0x391C0CB3,
        0x4ED8AA4A,
        0x5B9CCA4F,
        0x682E6FF3,
        0x748F82EE,
        0x78A5636F,
        0x84C87814,
        0x8CC70208,
        0x90BEFFFA,
        0xA4506CEB,
        0xBEF9A3F7,
        0xC67178F2,
};

static const int32_t const
    sha256_iv[] = {
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
};

uint8_t *sha256(const uint8_t *key)
{
#define SHA256_SIZE 64

    uint8_t bytes[SHA256_SIZE];
    memset(bytes, 0, sizeof(uint8_t) * SHA256_SIZE);
    bytes[10] = 0x80;
    bytes[63] = 80;

    for (int i = 0; i < 10; i++)
    {
        bytes[i] = key[i];
    }

    uint32_t tmp[SHA256_SIZE];

    for (int i = 0; i < 16; i++)
    {
        tmp[i] = BIGENDIAN(bytes, i * 4);
    }

    for (int i = 16; i < SHA256_SIZE; i++)
    {
        int32_t t0 = tmp[i - 15];
        int32_t td = tmp[i - 2];

        int32_t t0_1 = slr(t0, 0x0e, 0x12);
        int32_t t0_2 = slr(t0, 0x19, 0x07);
        int32_t t0_3 = t0 >> 0x03;

        int32_t td_1 = slr(td, 0x0f, 0x11);
        int32_t td_2 = slr(td, 0x0d, 0x13);
        int32_t td_3 = td >> 0x0a;

        tmp[i] = (tmp[i - 0x07] + (t0_1 ^ t0_2 ^ t0_3) + tmp[i - 0x10] + (td_1 ^ td_2 ^ td_3));
    }

    int32_t sbuf[8];

    memcpy(sbuf, sha256_iv, sizeof(uint8_t) * 8);

    for (int i = 0; i < SHA256_SIZE; i++)
    {
        int32_t s6 = sha256_iv[6];
        int32_t s5 = sha256_iv[5];
        int32_t s4 = sha256_iv[4];
        int32_t value = sha256_constants[i] + tmp[i] + sbuf[7] + ((~s4 & s6) ^ (s5 & s4)) + (slr(s4, 0x15, 0x0b) ^ slr(s4, 0x07, 0x19) ^ slr(s4, 0x1a, 0x06));
        sbuf[7] = s6;
        sbuf[6] = s5;
        sbuf[5] = s4;
        sbuf[4] = sbuf[3] + value;

        int32_t s0 = sbuf[0];
        int32_t s1 = sbuf[1];
        int32_t s2 = sbuf[2];

        sbuf[3] = s2;
        sbuf[2] = s1;
        sbuf[1] = s0;
        sbuf[0] = (slr(s0, 0x13, 0x0d) ^ slr(s0, 0x0a, 0x16) ^ slr(s0, 0x1e, 0x02)) +
                  (((s1 ^ s0) & s2) ^ (s1 & s0)) + tmp;
    }

    uint8_t *result = calloc(sizeof(uint8_t), 32);

    for (int i = 0; i < 8; i++)
    {
        int32_t value = sbuf[i] + sha256_iv[i];
        result[i] = GET_BYTE(value, 3);
        result[i + 1] = GET_BYTE(value, 2);
        result[i + 2] = GET_BYTE(value, 1);
        result[i + 3] = GET_BYTE(value, 0);
    }

    return result;
}

int main(int32_t argc, char *argv[])
{
}