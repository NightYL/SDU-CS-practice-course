#ifndef SM4_H
#define SM4_H

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

private:
    // S��
    static const uint8_t Sbox[256];

    // ��S��
    static const uint8_t invSbox[256];

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

    // �������Ա任S
    uint8_t invS(uint8_t inch);

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

