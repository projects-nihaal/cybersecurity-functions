#include "aes_ecb_mac.h"

#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
#define AES_NUM_ROUNDS 10
#define AES_KEY_SCHEDULE_SIZE (AES_NUM_ROUNDS + 1) * AES_BLOCK_SIZE
#define const_Bsize 16
#define AES_MAX_ROUNDS 14

unsigned char out[const_Bsize];
unsigned char globalEncryptOutput[65];
unsigned char globalDecryptOutput[65];
unsigned char key_schedule[AES_KEY_SCHEDULE_SIZE];


// Main Functions
unsigned char* aes_128_encrypt(unsigned char* in, unsigned char* out, unsigned char* key)
{
    unsigned char w[16 * (AES_MAX_ROUNDS + 1)];
    unsigned char Nk = 4, Nr = 10;

    // Key expansion
    KeyExpansion(key, w, Nk, Nr);

    // Perform encryption
    Cipher(in, out, w, Nk, Nr);

    return out;  // Return the output buffer
}

unsigned char* aes_128_decrypt(unsigned char* in, unsigned char* out, unsigned char* key)
{
    unsigned char w[16 * (AES_MAX_ROUNDS + 1)]; // Static array, no dynamic allocation
    unsigned char Nk = 4, Nr = 10;

    // Key expansion
    KeyExpansion(key, w, Nk, Nr);

    // Perform decryption
    InvCipher(in, out, w, Nk, Nr);

    return out;
}

// The Cipher
void Cipher(unsigned char* in, unsigned char* out, unsigned char* w, unsigned char Nk, unsigned char Nr)
{
    unsigned char state[Nk][4];
    for (int i = 0; i < 16; i++) {
        state[i / 4][i % 4] = in[i];
    }

    AddRoundKey(state, w);
    for (int round = 0; round < Nr; round++) {
        SubBytes(state);
        ShiftRows(state);
        if (round != (Nr - 1))
            MixColumns(state);
        AddRoundKey(state, (unsigned char*)(w + (round + 1) * 16));
    }
    for (int i = 0; i < Nk * 4; i++) {
        out[i] = state[i / 4][i % 4];
    }
}

void InvCipher(unsigned char* in, unsigned char* out, unsigned char* w, unsigned char Nk, unsigned char Nr)
{
    unsigned char state[Nk][4];
    for (int i = 0; i < 16; i++) {
        state[i / 4][i % 4] = in[i];
    }

    AddRoundKey(state, w + (Nr * 16));
    for (int round = Nr - 1; round >= 0; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, (unsigned char*)(w + round * 16));
        if (round)
            InvMixColumns(state);
    }
    for (int i = 0; i < Nk * 4; i++) {
        out[i] = state[i / 4][i % 4];
    }
}

// Key Expansion
void KeyExpansion(unsigned char* key, unsigned char* w, unsigned char Nk, unsigned char Nr)
{
    unsigned char tmp[4];
    for (int i = 0; i < 4 * Nk; i++) {
        w[i] = key[i];
    }
    for (int i = 4 * Nk; i < 4 * (Nr + 1) * 4; i += 4) {
        for (int j = 0; j < 4; j++) {
            tmp[j] = w[i - 4 + j];
        }
        if (i % (Nk * 4) == 0) {
            SubWord(RotWord(tmp));
            for (int j = 0; j < 4; j++) {
                tmp[j] ^= Rcon[i / Nk + j];
            }
        } else if (Nk > 6 && (i % (Nk * 4)) == 16) {
            SubWord(tmp);
        }
        for (int j = 0; j < 4; j++)
            w[i + j] = w[i - Nk * 4 + j] ^ tmp[j];
    }
}

unsigned char* SubWord(unsigned char* word)
{
    for (int i = 0; i < 4; i++) {
        word[i] = sbox[word[i]];
    }
    return word;
}

unsigned char* RotWord(unsigned char* word)
{
    unsigned char tmp[4];
    for (int i = 0; i < 4; i++)
    {
        tmp[i] = word[i];
    }
    for (int i = 0; i < 4; i++)
    {
        word[i] = tmp[(i + 1) % 4];
    }
    return word;
}

void SubBytes(unsigned char state[4][4])
{
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[col][row] = sbox[state[col][row]];
        }
    }
}

void InvSubBytes(unsigned char state[4][4])
{
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[col][row] = invsbox[state[col][row]];
        }
    }
}

void ShiftRows(unsigned char state[4][4])
{
    unsigned char tmp[4];
    for (int row = 1; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            tmp[col] = state[(row + col) % 4][row];
        }
        for (int col = 0; col < 4; col++) {
            state[col][row] = tmp[col];
        }
    }
}

void InvShiftRows(unsigned char state[4][4])
{
    unsigned char tmp[4];
    for (int row = 1; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            tmp[(row + col) % 4] = state[col][row];
        }
        for (int col = 0; col < 4; col++) {
            state[col][row] = tmp[col];
        }
    }
}

void MixColumns(unsigned char state[4][4])
{
    unsigned char tmp[4];
    unsigned char matmul[][4] = {
        0x02, 0x03, 0x01, 0x01,
        0x01, 0x02, 0x03, 0x01,
        0x01, 0x01, 0x02, 0x03,
        0x03, 0x01, 0x01, 0x02
    };
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            tmp[row] = state[col][row];
        }
        for (int i = 0; i < 4; i++) {
            state[col][i] = 0x00;
            for (int j = 0; j < 4; j++) {
                state[col][i] ^= mul(matmul[i][j], tmp[j]);
            }
        }
    }
}

void InvMixColumns(unsigned char state[4][4])
{
    unsigned char tmp[4];
    unsigned char matmul[][4] = {
        0x0e, 0x0b, 0x0d, 0x09,
        0x09, 0x0e, 0x0b, 0x0d,
        0x0d, 0x09, 0x0e, 0x0b,
        0x0b, 0x0d, 0x09, 0x0e
    };
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            tmp[row] = state[col][row];
        }
        for (int i = 0; i < 4; i++) {
            state[col][i] = 0x00;
            for (int j = 0; j < 4; j++) {
                state[col][i] ^= mul(matmul[i][j], tmp[j]);
            }
        }
    }
}

unsigned char mul(unsigned char a, unsigned char b)
{
    unsigned char sb[4];
    unsigned char out = 0;
    sb[0] = b;
    for (int i = 1; i < 4; i++) {
        sb[i] = sb[i - 1] << 1;
        if (sb[i - 1] & 0x80) {
            sb[i] ^= 0x1b;
        }
    }
    for (int i = 0; i < 4; i++) {
        if (a >> i & 0x01) {
            out ^= sb[i];
        }
    }
    return out;
}

void AddRoundKey(unsigned char state[4][4], unsigned char* key)
{
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[col][row] ^= key[col * 4 + row];
        }
    }
}

/* cmac.c code */


void aes_cmac(unsigned char* in, unsigned int length, unsigned char* out, unsigned char* key)
{
    unsigned char K1[const_Bsize], K2[const_Bsize];
    GenerateSubkey(key, K1, K2);
    int n = (length / const_Bsize);
    bool flag = false;
    if (length % const_Bsize != 0) {
        n++;
    }

    if (n == 0) {
        n = 1;
    } else if (length % const_Bsize == 0) {
        flag = true;
    }

    unsigned char M[n][const_Bsize];

    for (int i = 0; i < n * const_Bsize; i++) {
        M[0][i] = 0;
    }

    for (int i = 0; i < length; i++) {
        M[0][i] = in[i];
    }

    if (!flag) {
        M[0][length] = 0x80;  
    }

    if (flag) {
        block_xor(M[n - 1], M[n - 1], K1);
    } else {
        block_xor(M[n - 1], M[n - 1], K2);
    }

    unsigned char X[const_Bsize] = {0};
    unsigned char Y[const_Bsize];

    for (int i = 0; i < n - 1; i++) {
        block_xor(Y, M[i], X);
        aes_128_encrypt(Y, X, key);
    }

    block_xor(Y, M[n - 1], X);
    aes_128_encrypt(Y, out, key);

    return out;
}

bool verify_mac(unsigned char* in, unsigned int length, unsigned char* out, unsigned char* key)
{
    bool flag = true;
    unsigned char result[16];
    aes_cmac(in, length, result, key);
    for (int i = 0; i < const_Bsize; i++) {
        if (!(result[i] ^ out[i])) {
            flag = false;
            break;
        }
    }
    return flag;
}

// Generate the Sub keys
void GenerateSubkey(unsigned char* key, unsigned char* K1, unsigned char* K2)
{
    unsigned char const_Zero[16] = {0};
    unsigned char const_Rb[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87};
    unsigned char L[16];

    aes_128_encrypt(const_Zero, L, key);
    block_leftshift(K1, L);
    if (L[0] & 0x80) {
        block_xor(K1, K1, const_Rb);
    }

    block_leftshift(K2, K1);
    if (K1[0] & 0x80) {
        block_xor(K2, K2, const_Rb);
    }
}


/* utils.c */

void block_xor(unsigned char* dst, unsigned char* a, unsigned char* b)
{
    for (int j = 0; j < 16; j++) {
        dst[j] = a[j] ^ b[j];
    }
}

void block_leftshift(unsigned char* dst, unsigned char* src)
{
    unsigned char ovf = 0x00;
    for (int i = 15; i >= 0; i--) {
        dst[i] = src[i] << 1;
        dst[i] |= ovf;
        ovf = (src[i] & 0x80) ? 1 : 0;
    }
}

void ecb_encrypt(unsigned char* in, unsigned char* key, unsigned char* (*some_encrypt)(unsigned char* in, unsigned char* out, unsigned char* key), unsigned int* n)
{
    unsigned int length = strlen((char*)in) + 1;
    *n = (length + 15) / 16;

    unsigned char M[*n][16];
    for (int i = 0; i < *n; i++) {
        for (int j = 0; j < 16; j++) {
            M[i][j] = 0x00;
        }
    }

       for (int i = 0; i < length && i < (*n) * 16; i++) {
        M[i / 16][i % 16] = in[i];
    }

      for (int i = 0; i < *n; i++) {
        some_encrypt(M[i], globalEncryptOutput + (i * 16), key);  // Store the result in the global array
    }
}


void ecb_decrypt(unsigned char* in, unsigned char* key, unsigned char* (*some_decrypt)(unsigned char* in, unsigned char* out, unsigned char* key), unsigned int* n)
{
    unsigned int length = strlen((char*)in) + 1;
    *n = (length + 15) / 16;

    unsigned char M[*n][16];
    for (int i = 0; i < *n; i++) {
        for (int j = 0; j < 16; j++) {
            M[i][j] = 0x00;
        }
    }

     for (int i = 0; i < length && i < (*n) * 16; i++) {
        M[i / 16][i % 16] = in[i];
    }

        for (int i = 0; i < *n; i++) {
        some_decrypt(M[i], globalDecryptOutput + (i * 16), key);  // Store the result in the global array
    }
}
void run()
{
    unsigned char key[] = {
        0x31, 0x50, 0x10, 0x47,
        0x17, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    unsigned char message[] = {

        0x43,0x79,0x62,0x65,0x72,0x20,0x63,0x79,0x62,0x65,0x72,0x20,0x68,0x65,0x72,0x65,0x20,0x61,0x6e,0x64,0x20,0x74,0x68,0x65,0x72,0x65,0x21
    };

    aes_cmac(message, strlen((char*)message) + 1, (unsigned char*)out, key);

    unsigned int n = 0;
    ecb_encrypt(message, key, aes_128_encrypt, &n);
    ecb_decrypt(globalEncryptOutput, key, aes_128_decrypt, &n);

/******************Test Function************/
int main()
{   run();
}
