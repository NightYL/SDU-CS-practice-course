#include "sm4.h"
#include <cstring>
#include <stdexcept>
#include <immintrin.h>
#include <vector>

// S�ж���
const uint8_t SM4::Sbox[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

// ϵͳ����FK
const uint32_t SM4::FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

// �̶�����CK
const uint32_t SM4::CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};



// ��̬��ʼ����
\
void SM4::SM4TableInitializer() {
    for (int i = 0; i < 256; i++) {
        // ����T��
        uint32_t w0 = static_cast<uint32_t>(SM4::Sbox[i]) << 24;
        SM4::T0[i] = SM4::L(w0);
        uint32_t w1 = static_cast<uint32_t>(SM4::Sbox[i]) << 16;
        SM4::T1[i] = SM4::L(w1);
        uint32_t w2 = static_cast<uint32_t>(SM4::Sbox[i]) << 8;
        SM4::T2[i] = SM4::L(w2);
        uint32_t w3 = static_cast<uint32_t>(SM4::Sbox[i]);
        SM4::T3[i] = SM4::L(w3);

        // ����T'��
        SM4::T0_prime[i] = SM4::LPrime(w0);
        SM4::T1_prime[i] = SM4::LPrime(w1);
        SM4::T2_prime[i] = SM4::LPrime(w2);
        SM4::T3_prime[i] = SM4::LPrime(w3);
    }
};


// ���캯��
SM4::SM4(const uint8_t* key, Mode mode) : mode(mode) {
    // ��ʼ��IV
    memset(iv, 0, 16);

    // ��Կ��չ
    keyExpansion(key);
}

// ���ó�ʼ����
void SM4::setIV(const uint8_t* iv) {
    memcpy(this->iv, iv, 16);
}

// ��Կ��չ
void SM4::keyExpansion(const uint8_t* key) {
    uint32_t K[36];

    // ����Կת��Ϊ4��32λ��
    K[0] = bytesToWord(key) ^ FK[0];
    K[1] = bytesToWord(key + 4) ^ FK[1];
    K[2] = bytesToWord(key + 8) ^ FK[2];
    K[3] = bytesToWord(key + 12) ^ FK[3];

    // ����32������Կ
    for (int i = 0; i < 32; i++) {
        K[i + 4] = K[i] ^ TPrime(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
        rk[i] = K[i + 4];
    }
}

// �ֺ���F
uint32_t SM4::F(uint32_t X0, uint32_t X1, uint32_t X2, uint32_t X3, uint32_t rk) {
    return X0 ^ T(X1 ^ X2 ^ X3 ^ rk);
}

// �����Ա任��
uint32_t SM4::tau(uint32_t a) {
    uint8_t bytes[4];
    wordToBytes(a, bytes);

    // ��ÿ���ֽ�Ӧ��S�б任
    bytes[0] = S(bytes[0]);
    bytes[1] = S(bytes[1]);
    bytes[2] = S(bytes[2]);
    bytes[3] = S(bytes[3]);

    return bytesToWord(bytes);
}

// ���Ա任L
uint32_t SM4::L(uint32_t b) {
    return b ^
        ((b << 2) | (b >> 30)) ^  // ѭ������2λ
        ((b << 10) | (b >> 22)) ^ // ѭ������10λ
        ((b << 18) | (b >> 14)) ^ // ѭ������18λ
        ((b << 24) | (b >> 8));   // ѭ������24λ
}

// ���Ա任L'
uint32_t SM4::LPrime(uint32_t b) {
    return b ^
        ((b << 13) | (b >> 19)) ^  // ѭ������13λ
        ((b << 23) | (b >> 9));    // ѭ������23λ
}

// �����Ա任S
uint8_t SM4::S(uint8_t inch) {
    return Sbox[inch];
}

// 32λ�������Ա任T
uint32_t SM4::T(uint32_t a) {
    return L(tau(a));
}

// 32λ�������Ա任T'
uint32_t SM4::TPrime(uint32_t a) {
    return LPrime(tau(a));
}

////-----------T table ����-----BEGIN-----------
//// T������ʹ��Ԥ�����T��
//uint32_t SM4::T(uint32_t a) {
//    return T0[(a >> 24) & 0xFF] ^
//        T1[(a >> 16) & 0xFF] ^
//        T2[(a >> 8) & 0xFF] ^
//        T3[a & 0xFF];//}
//
//// T'������ʹ��Ԥ�����T'��
//uint32_t SM4::TPrime(uint32_t a) {
//    return T0_prime[(a >> 24) & 0xFF] ^
//        T1_prime[(a >> 16) & 0xFF] ^
//        T2_prime[(a >> 8) & 0xFF] ^
//        T3_prime[a & 0xFF];
//}
////-----------T table ����-----END-------------

// ���ܵ�������
void SM4::encryptBlock(const uint8_t* input, uint8_t* output) {
    uint32_t X[36];

    // ������ת��Ϊ4��32λ��
    X[0] = bytesToWord(input);
    X[1] = bytesToWord(input + 4);
    X[2] = bytesToWord(input + 8);
    X[3] = bytesToWord(input + 12);

    // 32�ֵ���
    for (int i = 0; i < 32; i++) {
        X[i + 4] = F(X[i], X[i + 1], X[i + 2], X[i + 3], rk[i]);
    }

    // ����任
    uint32_t outputWords[4] = { X[35], X[34], X[33], X[32] };

    // ת��Ϊ�ֽ�����
    wordToBytes(outputWords[0], output);
    wordToBytes(outputWords[1], output + 4);
    wordToBytes(outputWords[2], output + 8);
    wordToBytes(outputWords[3], output + 12);
}

// ���ܵ�������
void SM4::decryptBlock(const uint8_t* input, uint8_t* output) {
    uint32_t X[36];

    // ������ת��Ϊ4��32λ��
    X[0] = bytesToWord(input);
    X[1] = bytesToWord(input + 4);
    X[2] = bytesToWord(input + 8);
    X[3] = bytesToWord(input + 12);

    // 32�ֵ�����ʹ����������Կ
    for (int i = 0; i < 32; i++) {
        X[i + 4] = F(X[i], X[i + 1], X[i + 2], X[i + 3], rk[31 - i]);
    }

    // ����任
    uint32_t outputWords[4] = { X[35], X[34], X[33], X[32] };

    // ת��Ϊ�ֽ�����
    wordToBytes(outputWords[0], output);
    wordToBytes(outputWords[1], output + 4);
    wordToBytes(outputWords[2], output + 8);
    wordToBytes(outputWords[3], output + 12);
}

// �ֽ�����ת32λ�޷�������
uint32_t SM4::bytesToWord(const uint8_t* bytes) {
    return (static_cast<uint32_t>(bytes[0]) << 24) |
        (static_cast<uint32_t>(bytes[1]) << 16) |
        (static_cast<uint32_t>(bytes[2]) << 8) |
        static_cast<uint32_t>(bytes[3]);
}

// 32λ�޷�������ת�ֽ�����
void SM4::wordToBytes(uint32_t word, uint8_t* bytes) {
    bytes[0] = static_cast<uint8_t>((word >> 24) & 0xFF);
    bytes[1] = static_cast<uint8_t>((word >> 16) & 0xFF);
    bytes[2] = static_cast<uint8_t>((word >> 8) & 0xFF);
    bytes[3] = static_cast<uint8_t>(word & 0xFF);
}

// ���ܺ���
int SM4::encrypt(const uint8_t* plaintext, int length, uint8_t* ciphertext) {
    if (length <= 0 || !plaintext || !ciphertext) {
        throw std::invalid_argument("Invalid input parameters");
    }

    int blockCount = (length + 15) / 16;  // ������Ҫ�Ŀ���
    uint8_t inputBlock[16] = { 0 };
    uint8_t outputBlock[16] = { 0 };
    uint8_t currentIV[16];
    memcpy(currentIV, iv, 16);
    // SM4TableInitializer(); //ѡ��ʹ��T�����

    for (int i = 0; i < blockCount; i++) {
        // �������ݵ������
        int bytesToCopy = (i == blockCount - 1) ? (length % 16) : 16;
        if (bytesToCopy == 0) bytesToCopy = 16;
        memcpy(inputBlock, plaintext + i * 16, bytesToCopy);

        // ��������һ������Ҫ���
        if (i == blockCount - 1 && length % 16 != 0) {
            uint8_t padValue = 16 - (length % 16);
            for (int j = bytesToCopy; j < 16; j++) {
                inputBlock[j] = padValue;
            }
        }

        // ����ģʽ����
        if (mode == CBC) {
            // CBCģʽ��Ҫ��IV���
            for (int j = 0; j < 16; j++) {
                inputBlock[j] ^= currentIV[j];
            }
        }

        // ���ܵ�ǰ��
        encryptBlock(inputBlock, outputBlock);

        // ���ƽ�������
        memcpy(ciphertext + i * 16, outputBlock, 16);

        // ����IV��CBCģʽ��
        if (mode == CBC) {
            memcpy(currentIV, outputBlock, 16);
        }
    }

    return blockCount * 16;
}

// ���ܺ���
int SM4::decrypt(const uint8_t* ciphertext, int length, uint8_t* plaintext) {
    if (length <= 0 || length % 16 != 0 || !ciphertext || !plaintext) {
        throw std::invalid_argument("Invalid input parameters");
    }

    int blockCount = length / 16;  // �������
    uint8_t inputBlock[16] = { 0 };
    uint8_t outputBlock[16] = { 0 };
    uint8_t currentIV[16];
    memcpy(currentIV, iv, 16);
    uint8_t prevBlock[16];

    for (int i = 0; i < blockCount; i++) {
        // ���Ƶ�ǰ��
        memcpy(inputBlock, ciphertext + i * 16, 16);
        memcpy(prevBlock, inputBlock, 16);

        // ���ܵ�ǰ��
        decryptBlock(inputBlock, outputBlock);

        // ����ģʽ����
        if (mode == CBC) {
            // CBCģʽ��Ҫ��IV���
            for (int j = 0; j < 16; j++) {
                outputBlock[j] ^= currentIV[j];
            }
            // ����IVΪǰһ�����Ŀ�
            memcpy(currentIV, prevBlock, 16);
        }

        // ���ƽ�������
        memcpy(plaintext + i * 16, outputBlock, 16);
    }

    // �������
    uint8_t padValue = plaintext[length - 1];
    if (padValue > 16) {
        throw std::runtime_error("Invalid padding");
    }

    // ��֤���
    for (int i = length - padValue; i < length; i++) {
        if (plaintext[i] != padValue) {
            throw std::runtime_error("Invalid padding");
        }
    }

    return length - padValue;
}

//-------------SIMD �Ż�--------------------

void SM4::encryptBlocksAVX2(const uint8_t* inputs, uint8_t* outputs, int blockCount) {
    int i = 0;
    alignas(32) uint8_t tempIn[4][16];
    alignas(32) uint8_t tempOut[4][16];

    // ÿ�ִ���4����
    for (; i + 3 < blockCount; i += 4) {
        // ����4���飨�Ƕ��룩
        __m128i in0 = _mm_loadu_si128((__m128i*)(inputs + (i + 0) * 16));
        __m128i in1 = _mm_loadu_si128((__m128i*)(inputs + (i + 1) * 16));
        __m128i in2 = _mm_loadu_si128((__m128i*)(inputs + (i + 2) * 16));
        __m128i in3 = _mm_loadu_si128((__m128i*)(inputs + (i + 3) * 16));

        // ������ʱ��������ʹ encryptBlock ���ã�
        _mm_store_si128((__m128i*)tempIn[0], in0);
        _mm_store_si128((__m128i*)tempIn[1], in1);
        _mm_store_si128((__m128i*)tempIn[2], in2);
        _mm_store_si128((__m128i*)tempIn[3], in3);

        // ��ÿ������� encryptBlock
        for (int j = 0; j < 4; j++) {
            encryptBlock(tempIn[j], tempOut[j]);
        }

        // д�ؽ��
        _mm_storeu_si128((__m128i*)(outputs + (i + 0) * 16), _mm_load_si128((__m128i*)tempOut[0]));
        _mm_storeu_si128((__m128i*)(outputs + (i + 1) * 16), _mm_load_si128((__m128i*)tempOut[1]));
        _mm_storeu_si128((__m128i*)(outputs + (i + 2) * 16), _mm_load_si128((__m128i*)tempOut[2]));
        _mm_storeu_si128((__m128i*)(outputs + (i + 3) * 16), _mm_load_si128((__m128i*)tempOut[3]));
    }

    // ����ʣ���
    for (; i < blockCount; i++) {
        encryptBlock(inputs + i * 16, outputs + i * 16);
    }
}


int SM4::encrypt_simd(const uint8_t* plaintext, int length, uint8_t* ciphertext) {
    if (length <= 0 || !plaintext || !ciphertext) {
        throw std::invalid_argument("Invalid input parameters");
    }

    int blockCount = (length + 15) / 16;
    int paddedLength = blockCount * 16;

    // ��������������������������䣩
    std::vector<uint8_t> paddedInput(paddedLength, 0);
    memcpy(paddedInput.data(), plaintext, length);

    // ��� PKCS#7 ���
    uint8_t padValue = paddedLength - length;
    for (int i = length; i < paddedLength; i++) {
        paddedInput[i] = padValue;
    }

    if (mode == ECB) {
        // ֱ��ʹ�� SIMD �Ż��Ķ����ܺ���
        encryptBlocksAVX2(paddedInput.data(), ciphertext, blockCount);
    }
    else if (mode == CBC) {
        // CBC ģʽ������鴮�м���
        uint8_t inputBlock[16] = { 0 };
        uint8_t outputBlock[16] = { 0 };
        uint8_t currentIV[16];
        memcpy(currentIV, iv, 16);

        for (int i = 0; i < blockCount; i++) {
            memcpy(inputBlock, paddedInput.data() + i * 16, 16);

            // CBCģʽ��Ҫ��IV���
            for (int j = 0; j < 16; j++) {
                inputBlock[j] ^= currentIV[j];
            }

            encryptBlock(inputBlock, outputBlock);
            memcpy(ciphertext + i * 16, outputBlock, 16);

            memcpy(currentIV, outputBlock, 16);  // ����IV
        }
    }
    else {
        throw std::runtime_error("Unsupported mode");
    }

    return paddedLength;
}



void SM4::decryptBlocksAVX2(const uint8_t* inputs, uint8_t* outputs, int blockCount) {
    int i = 0;
    alignas(32) uint8_t tempIn[4][16];
    alignas(32) uint8_t tempOut[4][16];

    for (; i + 3 < blockCount; i += 4) {
        __m128i in0 = _mm_loadu_si128((__m128i*)(inputs + (i + 0) * 16));
        __m128i in1 = _mm_loadu_si128((__m128i*)(inputs + (i + 1) * 16));
        __m128i in2 = _mm_loadu_si128((__m128i*)(inputs + (i + 2) * 16));
        __m128i in3 = _mm_loadu_si128((__m128i*)(inputs + (i + 3) * 16));

        _mm_store_si128((__m128i*)tempIn[0], in0);
        _mm_store_si128((__m128i*)tempIn[1], in1);
        _mm_store_si128((__m128i*)tempIn[2], in2);
        _mm_store_si128((__m128i*)tempIn[3], in3);

        for (int j = 0; j < 4; j++) {
            decryptBlock(tempIn[j], tempOut[j]);
        }

        _mm_storeu_si128((__m128i*)(outputs + (i + 0) * 16), _mm_load_si128((__m128i*)tempOut[0]));
        _mm_storeu_si128((__m128i*)(outputs + (i + 1) * 16), _mm_load_si128((__m128i*)tempOut[1]));
        _mm_storeu_si128((__m128i*)(outputs + (i + 2) * 16), _mm_load_si128((__m128i*)tempOut[2]));
        _mm_storeu_si128((__m128i*)(outputs + (i + 3) * 16), _mm_load_si128((__m128i*)tempOut[3]));
    }

    for (; i < blockCount; i++) {
        decryptBlock(inputs + i * 16, outputs + i * 16);
    }
}

int SM4::decrypt_simd(const uint8_t* ciphertext, int length, uint8_t* plaintext) {
    if (length <= 0 || length % 16 != 0 || !ciphertext || !plaintext) {
        throw std::invalid_argument("Invalid input parameters");
    }

    int blockCount = length / 16;

    if (mode == ECB) {
        // ֱ���� SIMD ����
        decryptBlocksAVX2(ciphertext, plaintext, blockCount);
    }
    else if (mode == CBC) {
        // ���� CBC ģʽ��ÿ����Ҫǰһ�����Ŀ�������
        uint8_t inputBlock[16] = { 0 };
        uint8_t outputBlock[16] = { 0 };
        uint8_t currentIV[16];
        uint8_t prevBlock[16];
        memcpy(currentIV, iv, 16);

        for (int i = 0; i < blockCount; i++) {
            memcpy(inputBlock, ciphertext + i * 16, 16);
            memcpy(prevBlock, inputBlock, 16);

            decryptBlock(inputBlock, outputBlock);

            for (int j = 0; j < 16; j++) {
                outputBlock[j] ^= currentIV[j];
            }

            memcpy(currentIV, prevBlock, 16);
            memcpy(plaintext + i * 16, outputBlock, 16);
        }
    }

    // ������
    uint8_t padValue = plaintext[length - 1];
    if (padValue > 16 || padValue == 0) {
        throw std::runtime_error("Invalid padding");
    }

    for (int i = length - padValue; i < length; i++) {
        if (plaintext[i] != padValue) {
            throw std::runtime_error("Invalid padding");
        }
    }

    return length - padValue;
}

//-------------SM4-GCM����ģʽ--------------

// Galois��˷� GF(2^128)
void galois_mult(const uint8_t* X, const uint8_t* Y, uint8_t* result) {
    uint8_t Z[16] = { 0 };
    uint8_t V[16];
    memcpy(V, Y, 16);

    for (int i = 0; i < 128; i++) {
        int byteIndex = i / 8;
        int bitIndex = 7 - (i % 8);
        if ((X[byteIndex] >> bitIndex) & 1) {
            for (int j = 0; j < 16; j++) {
                Z[j] ^= V[j];
            }
        }

        bool lsb = V[15] & 1;
        for (int j = 15; j > 0; j--) {
            V[j] = (V[j] >> 1) | ((V[j - 1] & 1) << 7);
        }
        V[0] >>= 1;
        if (lsb) V[0] ^= 0xe1;
    }
    memcpy(result, Z, 16);
}

// GHASH(AAD, C)
void ghash(const uint8_t* H, const std::vector<uint8_t>& aad, const std::vector<uint8_t>& ciphertext, uint8_t* output) {
    std::vector<uint8_t> X(16, 0);

    auto ghash_update = [&](const std::vector<uint8_t>& data) {
        for (size_t i = 0; i < data.size(); i += 16) {
            uint8_t block[16] = { 0 };
            size_t len = std::min((size_t)16, data.size() - i);
            memcpy(block, &data[i], len);
            for (int j = 0; j < 16; j++) {
                X[j] ^= block[j];
            }
            galois_mult(X.data(), H, X.data());
        }
        };

    ghash_update(aad);
    ghash_update(ciphertext);

    uint8_t lenBlock[16] = { 0 };
    uint64_t aad_bits = aad.size() * 8;
    uint64_t ct_bits = ciphertext.size() * 8;
    for (int i = 0; i < 8; i++) lenBlock[7 - i] = (aad_bits >> (i * 8)) & 0xFF;
    for (int i = 0; i < 8; i++) lenBlock[15 - i] = (ct_bits >> (i * 8)) & 0xFF;

    for (int j = 0; j < 16; j++) {
        X[j] ^= lenBlock[j];
    }
    galois_mult(X.data(), H, X.data());

    memcpy(output, X.data(), 16);
}

// ���Ӽ�����
void increment_counter(uint8_t* counter) {
    for (int i = 15; i >= 12; i--) {
        if (++counter[i]) break;
    }
}


// GCM����
bool SM4::sm4_gcm_encrypt(
    SM4& sm4,
    const uint8_t* plaintext, int plaintext_len,
    const uint8_t* aad, int aad_len,
    const uint8_t* iv, int iv_len,
    uint8_t* ciphertext,
    uint8_t* tag, int tag_len)
{
    if (iv_len != 12 || tag_len != 16) return false;

    uint8_t H[16] = { 0 };
    sm4.encryptBlock(H, H);  // H = E_K(0)

    uint8_t J0[16];
    memcpy(J0, iv, 12);
    J0[12] = J0[13] = J0[14] = 0;
    J0[15] = 1;

    uint8_t counter[16];
    memcpy(counter, J0, 16);
    std::vector<uint8_t> ct;

    for (int i = 0; i < plaintext_len; i += 16) {
        uint8_t keystream[16] = { 0 };
        sm4.encryptBlock(counter, keystream);
        increment_counter(counter);

        int len = std::min(16, plaintext_len - i);
        for (int j = 0; j < len; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        }
        ct.insert(ct.end(), &ciphertext[i], &ciphertext[i + len]);
    }

    uint8_t S[16];
    ghash(H, std::vector<uint8_t>(aad, aad + aad_len), ct, S);

    uint8_t EkJ0[16];
    sm4.encryptBlock(J0, EkJ0);

    for (int i = 0; i < 16; i++) {
        tag[i] = S[i] ^ EkJ0[i];
    }

    return true;
}

// GCM����
bool SM4::sm4_gcm_decrypt(
    SM4& sm4,
    const uint8_t* ciphertext, int ciphertext_len,
    const uint8_t* aad, int aad_len,
    const uint8_t* iv, int iv_len,
    const uint8_t* tag, int tag_len,
    uint8_t* plaintext)
{
    if (iv_len != 12 || tag_len != 16) return false;

    uint8_t H[16] = { 0 };
    sm4.encryptBlock(H, H);  // H = E_K(0)

    uint8_t J0[16];
    memcpy(J0, iv, 12);
    J0[12] = J0[13] = J0[14] = 0;
    J0[15] = 1;

    uint8_t counter[16];
    memcpy(counter, J0, 16);
    std::vector<uint8_t> pt;

    for (int i = 0; i < ciphertext_len; i += 16) {
        uint8_t keystream[16] = { 0 };
        sm4.encryptBlock(counter, keystream);
        increment_counter(counter);

        int len = std::min(16, ciphertext_len - i);
        for (int j = 0; j < len; j++) {
            plaintext[i + j] = ciphertext[i + j] ^ keystream[j];
        }
        pt.insert(pt.end(), &plaintext[i], &plaintext[i + len]);
    }

    uint8_t S[16];
    ghash(H, std::vector<uint8_t>(aad, aad + aad_len), std::vector<uint8_t>(ciphertext, ciphertext + ciphertext_len), S);

    uint8_t EkJ0[16];
    sm4.encryptBlock(J0, EkJ0);

    uint8_t computedTag[16];
    for (int i = 0; i < 16; i++) {
        computedTag[i] = S[i] ^ EkJ0[i];
    }

    return memcmp(computedTag, tag, 16) == 0;
}