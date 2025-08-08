#ifndef SM4_H
#define SM4_H
#include <vector>
#include <cstdint>
#include <string>

// SM4算法实现类
class SM4 {
public:
    // 加密模式
    enum Mode {
        ECB,    // ECB模式
        CBC     // CBC模式
    };

    // 构造函数，传入密钥
    SM4(const uint8_t* key, Mode mode = ECB);

    // 析构函数
    ~SM4() = default;

    // 设置CBC模式的初始向量
    void setIV(const uint8_t* iv);

    // 加密函数，返回加密后的数据长度
    int encrypt(const uint8_t* plaintext, int length, uint8_t* ciphertext);

    // 加密单组数据
    void encryptBlock(const uint8_t* input, uint8_t* output);

    // 解密单组数据
    void decryptBlock(const uint8_t* input, uint8_t* output);

    // 解密函数，返回解密后的数据长度
    int decrypt(const uint8_t* ciphertext, int length, uint8_t* plaintext);

    // 预计算的T表（加速用）
    uint32_t T0[256];
    uint32_t T1[256];
    uint32_t T2[256];
    uint32_t T3[256];
    uint32_t T0_prime[256];
    uint32_t T1_prime[256];
    uint32_t T2_prime[256];
    uint32_t T3_prime[256];

    //初始化
    void SM4TableInitializer();


    //simd 优化
    void encryptBlocksAVX2(const uint8_t* inputs, uint8_t* outputs, int blockCount);

    int encrypt_simd(const uint8_t* plaintext, int length, uint8_t* ciphertext);

    void decryptBlocksAVX2(const uint8_t* inputs, uint8_t* outputs, int blockCount);

    int decrypt_simd(const uint8_t* ciphertext, int length, uint8_t* plaintext);

    // GCM工作模式
    bool sm4_gcm_encrypt(
        SM4& sm4,
        const uint8_t* plaintext, int plaintext_len,
        const uint8_t* aad, int aad_len,
        const uint8_t* iv, int iv_len,
        uint8_t* ciphertext,
        uint8_t* tag, int tag_len);

    bool sm4_gcm_decrypt(
        SM4& sm4,
        const uint8_t* ciphertext, int ciphertext_len,
        const uint8_t* aad, int aad_len,
        const uint8_t* iv, int iv_len,
        const uint8_t* tag, int tag_len,
        uint8_t* plaintext);

private:
    // S盒
    static const uint8_t Sbox[256];

    // 系统参数FK
    static const uint32_t FK[4];

    // 固定参数CK
    static const uint32_t CK[32];

    // 轮密钥
    uint32_t rk[32];

    // 初始向量
    uint8_t iv[16];

    // 加密模式
    Mode mode;

    // 密钥扩展函数
    void keyExpansion(const uint8_t* key);

    // 轮函数
    uint32_t F(uint32_t X0, uint32_t X1, uint32_t X2, uint32_t X3, uint32_t rk);

    // 非线性变换τ
    uint32_t tau(uint32_t a);

    // 线性变换L
    uint32_t L(uint32_t b);

    // 线性变换L'，用于密钥扩展
    uint32_t LPrime(uint32_t b);

    // 非线性变换S
    uint8_t S(uint8_t inch);

    // 32位异或非线性变换
    uint32_t T(uint32_t a);

    // 32位异或非线性变换，用于密钥扩展
    uint32_t TPrime(uint32_t a);

    // 字节数组转32位无符号整数
    uint32_t bytesToWord(const uint8_t* bytes);

    // 32位无符号整数转字节数组
    void wordToBytes(uint32_t word, uint8_t* bytes);







};

#endif // SM4_H

