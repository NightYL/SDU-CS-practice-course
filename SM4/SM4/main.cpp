#include "sm4.h"
#include <iostream>
using namespace std;
#include <iomanip>
#include <cstring>
#include <chrono>

// 打印字节数组
void printBytes(const uint8_t* data, int length, const std::string& label) {
    std::cout << label << ": ";
    for (int i = 0; i < length; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl;
}

int main() {
    try {
        // 测试数据
        const uint8_t key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
        const uint8_t iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
        const uint8_t plaintext[] = {
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98,
            0x76, 0x54, 0x32, 0x10,
            0x01, 0x23, 0x45, 0x67,
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF
        };
        size_t plaintext_length = sizeof(plaintext) / sizeof(plaintext[0]);

        // 输出长度
        printf("plaintext 的长度为 %zu 字节\n", plaintext_length);
        printf("明文:\t");
        for (size_t i = 0; i < plaintext_length; i++) {
            if ((i % 16 == 0) && (i != 0))
            {
                cout << endl;
                cout << "\t";
            }
            printf("%2X ", plaintext[i]);
        }
        cout << endl;
        // ECB模式的SM4
        SM4 sm4_ecb(key, SM4::ECB);
        uint8_t* ciphertext_ecb = new uint8_t[plaintext_length];

        int padding_len=sm4_ecb.encrypt(plaintext, plaintext_length,ciphertext_ecb);

        printf("密文:\t");
        for (size_t i = 0; i < padding_len; i++) {
            if ((i % 16 == 0) && (i != 0))
            {
                cout << endl;
                cout << "\t";
            }
            printf("%2X ", ciphertext_ecb[i]);

        }
        cout << endl;
        uint8_t* de_ecb = new uint8_t[padding_len];
        sm4_ecb.decrypt(ciphertext_ecb, padding_len,de_ecb);

        printf("解密:\t");
        for (size_t i = 0; i < padding_len; i++) {
            if ((i % 16 == 0) && (i != 0))
            {
                cout << endl;
                cout << "\t";
            }
            printf("%2X ", de_ecb[i]);
        }

        cout << endl;
    }
    catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
