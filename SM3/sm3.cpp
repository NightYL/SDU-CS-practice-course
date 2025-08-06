#define _CRT_SECURE_NO_WARNINGS  
#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <algorithm>

using namespace std;

// 定义无符号32位整数类型
typedef unsigned int uint32;
// 定义无符号64位整数类型
typedef unsigned long long uint64;

// SM3初始向量
const uint32 IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

// 常量Tj
const uint32 T[64] = {
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
};

// 循环左移
inline uint32 ROTL(uint32 x, int n) {
    return (x << n) | (x >> (32 - n));
}

// 布尔函数
inline uint32 FF0(uint32 x, uint32 y, uint32 z) {
    return x ^ y ^ z;
}

inline uint32 FF1(uint32 x, uint32 y, uint32 z) {
    return (x & y) | (x & z) | (y & z);
}

inline uint32 GG0(uint32 x, uint32 y, uint32 z) {
    return x ^ y ^ z;
}

inline uint32 GG1(uint32 x, uint32 y, uint32 z) {
    return (x & y) | (~x & z);
}

// 置换函数
inline uint32 P0(uint32 x) {
    return x ^ ROTL(x, 9) ^ ROTL(x, 17);
}

inline uint32 P1(uint32 x) {
    return x ^ ROTL(x, 15) ^ ROTL(x, 23);
}

// 消息填充
vector<uint8_t> padding(const vector<uint8_t>& msg) {
    vector<uint8_t> padded = msg;

    // 填充1
    padded.push_back(0x80);

    // 填充0，使得长度模512等于448
    size_t len = padded.size() * 8;
    size_t pad_len = (448 - len % 512 + 512) % 512;
    pad_len /= 8;
    padded.insert(padded.end(), pad_len, 0x00);

    // 填充原始消息长度（以比特为单位）
    uint64_t msg_len = msg.size() * 8;
    for (int i = 7; i >= 0; --i) {
        padded.push_back((msg_len >> (i * 8)) & 0xFF);
    }

    return padded;
}

// 消息扩展
void expand(const uint32 W[16], uint32 W1[68], uint32 W2[64]) {
    // 扩展为68个字
    for (int i = 0; i < 16; ++i) {
        W1[i] = W[i];
    }
    for (int i = 16; i < 68; ++i) {
        W1[i] = P1(W1[i - 16] ^ W1[i - 9] ^ ROTL(W1[i - 3], 15)) ^ ROTL(W1[i - 13], 7) ^ W1[i - 6];
    }

    // 扩展为64个字
    for (int i = 0; i < 64; ++i) {
        W2[i] = W1[i] ^ W1[i + 4];
    }
}

// 压缩函数
void compress(uint32 V[8], const uint32 B[16]) {
    uint32 W1[68], W2[64];
    expand(B, W1, W2);

    uint32 A = V[0], b = V[1], C = V[2], D = V[3];
    uint32 E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; ++j) {
        uint32 SS1 = ROTL(ROTL(A, 12) + E + ROTL(T[j], j), 7);
        uint32 SS2 = SS1 ^ ROTL(A, 12);
        // 使用重命名后的b
        uint32 TT1 = (j < 16 ? FF0(A, b, C) : FF1(A, b, C)) + D + SS2 + W2[j];
        uint32 TT2 = (j < 16 ? GG0(E, F, G) : GG1(E, F, G)) + H + SS1 + W1[j];
        D = C;
        C = ROTL(b, 9);  
        b = A;           
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    V[0] ^= A;
    V[1] ^= b;  
    V[2] ^= C;
    V[3] ^= D;
    V[4] ^= E;
    V[5] ^= F;
    V[6] ^= G;
    V[7] ^= H;
}

// 计算SM3哈希值
string sm3(const vector<uint8_t>& msg) {
    // 消息填充
    vector<uint8_t> padded = padding(msg);
    size_t block_num = padded.size() / 64;  // 每个块64字节 512 bit

    // 初始化哈希值
    uint32 V[8];
    memcpy(V, IV, 8 * sizeof(uint32));

    // 处理每个消息块
    for (size_t i = 0; i < block_num; ++i) {
        // 将64字节转换为16个32位整数（大端模式）
        uint32 B[16];
        for (int j = 0; j < 16; ++j) {
            B[j] = (padded[i * 64 + j * 4] << 24) |
                (padded[i * 64 + j * 4 + 1] << 16) |
                (padded[i * 64 + j * 4 + 2] << 8) |
                padded[i * 64 + j * 4 + 3];
        }

        // 压缩函数
        compress(V, B);
    }

    // 将哈希值转换为十六进制字符串
    char hex[65];
    for (int i = 0; i < 8; ++i) {
        sprintf(hex + i * 8, "%08x", V[i]);
    }
    hex[64] = '\0';

    return string(hex);
}

// 辅助函数：字符串转字节向量
vector<uint8_t> str_to_bytes(const string& s) {
    return vector<uint8_t>(s.begin(), s.end());
}

// 辅助函数：十六进制字符串转字节向量
vector<uint8_t> hex_to_bytes(const string& hex) {
    vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.size(); i += 2) {
        char c1 = hex[i];
        char c2 = hex[i + 1];

        uint8_t b = ((c1 >= '0' && c1 <= '9') ? (c1 - '0') :
            (c1 >= 'a' && c1 <= 'f') ? (c1 - 'a' + 10) :
            (c1 >= 'A' && c1 <= 'F') ? (c1 - 'A' + 10) : 0) << 4;

        b |= ((c2 >= '0' && c2 <= '9') ? (c2 - '0') :
            (c2 >= 'a' && c2 <= 'f') ? (c2 - 'a' + 10) :
            (c2 >= 'A' && c2 <= 'F') ? (c2 - 'A' + 10) : 0);

        bytes.push_back(b);
    }
    return bytes;
}

int main() {
    // 测试示例
    string test_str = "abc";
    vector<uint8_t> test_bytes = str_to_bytes(test_str);
    string hash = sm3(test_bytes);

    cout << "输入字符串: " << test_str << endl;
    cout << "SM3哈希值: " << hash << endl;

    // 验证已知结果（abc的SM3哈希值应为66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0）
    if (hash == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0") {
        cout << "测试通过: 哈希值正确" << endl;
    }
    else {
        cout << "测试失败: 哈希值不正确" << endl;
    }

    return 0;
}
