
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


char globalHashStr[65];

// SHA-256 transform function
static void SHA256Transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; i++, j += 4)
        m[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3]);
    for (; i < 64; i++)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}


// Initialize the SHA-256 context
void SHA256Init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen[0] = 0;
    ctx->bitlen[1] = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

// Update the SHA-256 hash with the provided data
void SHA256Update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            SHA256Transform(ctx, ctx->data);

            // Increment bit length correctly
            ctx->bitlen[0] += 512;
            if (ctx->bitlen[0] < 512) {  // Check for overflow
                ctx->bitlen[1]++;
            }

            ctx->datalen = 0;
        }
    }
}

// Finalize the SHA-256 hash and output the result
void SHA256Final(SHA256_CTX *ctx, uint8_t hash[SHA256_DIGEST_SIZE]) {
    uint i = ctx->datalen;

    // Padding the data to 56-byte boundary (512-bit block)
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) {
            ctx->data[i++] = 0x00;
        }
    }
    else {
        ctx->data[i++] = 0x80;
        while (i < 64) {
            ctx->data[i++] = 0x00;
        }
        SHA256Transform(ctx, ctx->data);
        // Clear the data array after processing 512-bit block
        for (i = 0; i < 56; ++i) {
            ctx->data[i] = 0;
        }
    }

    // Update the bit length (in 64-bit format: ctx->bitlen[0] is the lower part, ctx->bitlen[1] is the higher part)
    DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], ctx->datalen * 8);

    // Encode the bit length into the last 8 bytes of ctx->data
    ctx->data[63] = (ctx->bitlen[0]) & 0xFF;
    ctx->data[62] = (ctx->bitlen[0] >> 8) & 0xFF;
    ctx->data[61] = (ctx->bitlen[0] >> 16) & 0xFF;
    ctx->data[60] = (ctx->bitlen[0] >> 24) & 0xFF;
    ctx->data[59] = (ctx->bitlen[1]) & 0xFF;
    ctx->data[58] = (ctx->bitlen[1] >> 8) & 0xFF;
    ctx->data[57] = (ctx->bitlen[1] >> 16) & 0xFF;
    ctx->data[56] = (ctx->bitlen[1] >> 24) & 0xFF;

    // Perform the final transformation with the bit length
    SHA256Transform(ctx, ctx->data);

    // Convert the state to the final hash output
    for (i = 0; i < 8; ++i) {
        hash[i * 4 + 0] = (ctx->state[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = (ctx->state[i]) & 0xFF;
    }
}

// SHA256Hex function to compute SHA256 hash
void SHA256Hex(unsigned char* data, char* globalHashStr, size_t dataLen) {
    SHA256_CTX ctx;
    unsigned char hash[SHA256_DIGEST_SIZE];

    // Initialize SHA256 context
    SHA256Init(&ctx);

    // Update the SHA256 context with the binary data
    SHA256Update(&ctx, data, dataLen);

    // Finalize the hash computation
    SHA256Final(&ctx, hash);

    // Loop through each byte of the hash
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
        // Convert the high nibble (most significant 4 bits) to hex
        globalHashStr[i * 2]     = (hash[i] >> 4) + ((hash[i] >> 4) < 10 ? '0' : 'a' - 10);
        // Convert the low nibble (least significant 4 bits) to hex
        globalHashStr[i * 2 + 1] = (hash[i] & 0x0F) + ((hash[i] & 0x0F) < 10 ? '0' : 'a' - 10);
    }

    // Null-terminate the string
    globalHashStr[64] = '\0';
}

/**************Test Function**********************/

int main()
{        unsigned char hexData[] = { 0x48, 0x69, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20,
               0x69, 0x73, 0x20, 0x4e, 0x69, 0x68, 0x61, 0x61, 0x6c };  // Hexadecimal data as an array of bytes

        SHA256Hex(hexData, globalHashStr, sizeof(hexData));  // Get the SHA256 hash as a hex string
}
