#ifndef SM4_H
#define SM4_H
#include <vector>
#include <cstdint>
#include <string>

// SM4�㷨ʵ����
class SM4 {
public:
    // ����ģʽ
    enum Mode {
        ECB,    // ECBģʽ
        CBC     // CBCģʽ
    };

    // ���캯����������Կ
    SM4(const uint8_t* key, Mode mode = ECB);

    // ��������
    ~SM4() = default;

    // ����CBCģʽ�ĳ�ʼ����
    void setIV(const uint8_t* iv);

    // ���ܺ��������ؼ��ܺ�����ݳ���
    int encrypt(const uint8_t* plaintext, int length, uint8_t* ciphertext);

    // ���ܵ�������
    void encryptBlock(const uint8_t* input, uint8_t* output);

    // ���ܵ�������
    void decryptBlock(const uint8_t* input, uint8_t* output);

    // ���ܺ��������ؽ��ܺ�����ݳ���
    int decrypt(const uint8_t* ciphertext, int length, uint8_t* plaintext);

    // Ԥ�����T�������ã�
    uint32_t T0[256];
    uint32_t T1[256];
    uint32_t T2[256];
    uint32_t T3[256];
    uint32_t T0_prime[256];
    uint32_t T1_prime[256];
    uint32_t T2_prime[256];
    uint32_t T3_prime[256];

    //��ʼ��
    void SM4TableInitializer();


    //simd �Ż�
    void encryptBlocksAVX2(const uint8_t* inputs, uint8_t* outputs, int blockCount);

    int encrypt_simd(const uint8_t* plaintext, int length, uint8_t* ciphertext);

    void decryptBlocksAVX2(const uint8_t* inputs, uint8_t* outputs, int blockCount);

    int decrypt_simd(const uint8_t* ciphertext, int length, uint8_t* plaintext);

    // GCM����ģʽ
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
    // S��
    static const uint8_t Sbox[256];

    // ϵͳ����FK
    static const uint32_t FK[4];

    // �̶�����CK
    static const uint32_t CK[32];

    // ����Կ
    uint32_t rk[32];

    // ��ʼ����
    uint8_t iv[16];

    // ����ģʽ
    Mode mode;

    // ��Կ��չ����
    void keyExpansion(const uint8_t* key);

    // �ֺ���
    uint32_t F(uint32_t X0, uint32_t X1, uint32_t X2, uint32_t X3, uint32_t rk);

    // �����Ա任��
    uint32_t tau(uint32_t a);

    // ���Ա任L
    uint32_t L(uint32_t b);

    // ���Ա任L'��������Կ��չ
    uint32_t LPrime(uint32_t b);

    // �����Ա任S
    uint8_t S(uint8_t inch);

    // 32λ�������Ա任
    uint32_t T(uint32_t a);

    // 32λ�������Ա任��������Կ��չ
    uint32_t TPrime(uint32_t a);

    // �ֽ�����ת32λ�޷�������
    uint32_t bytesToWord(const uint8_t* bytes);

    // 32λ�޷�������ת�ֽ�����
    void wordToBytes(uint32_t word, uint8_t* bytes);







};

#endif // SM4_H

