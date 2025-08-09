#define _CRT_SECURE_NO_WARNINGS  
#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <algorithm>
#include <iomanip>

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

// 左循环移位
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

    // 填充0，使得长度对512取余448
    size_t len = padded.size() * 8;
    size_t pad_len = (448 - len % 512 + 512) % 512;
    pad_len /= 8;
    padded.insert(padded.end(), pad_len, 0x00);

    // 填充原始消息长度（64位大端序单位比特）
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
        // 使用正确名称的b
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
        // 将64字节转换为16个32位整数（大端序）
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

// 辅助函数：字符串转字节数组
vector<uint8_t> str_to_bytes(const string& s) {
    return vector<uint8_t>(s.begin(), s.end());
}

// 辅助函数：十六进制字符串转字节数组
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

// 使用自定义IV计算SM3（用于长度扩展攻击）
string sm3_with_custom_iv(const vector<uint8_t>& msg, const uint32 custom_IV[8], uint64_t original_length_bits) {
    vector<uint8_t> padded = msg;

    // 计算总长度（原始消息 + 新消息）
    uint64_t total_bits = original_length_bits + msg.size() * 8;

    // 添加填充位
    padded.push_back(0x80);

    // 计算需要填充的0的数量
    size_t current_bits = total_bits + 8; // +8 for the 0x80 byte
    size_t pad_bits = (448 - current_bits % 512 + 512) % 512;

    for (size_t i = 0; i < pad_bits / 8; ++i) {
        padded.push_back(0x00);
    }

    // 添加总长度（64位大端序）
    for (int i = 7; i >= 0; --i) {
        padded.push_back((total_bits >> (i * 8)) & 0xFF);
    }

    size_t block_num = padded.size() / 64;

    // 使用自定义IV
    uint32 V[8];
    memcpy(V, custom_IV, 8 * sizeof(uint32));

    // 处理每个消息块
    for (size_t i = 0; i < block_num; ++i) {
        uint32 B[16];
        for (int j = 0; j < 16; ++j) {
            B[j] = (padded[i * 64 + j * 4] << 24) |
                (padded[i * 64 + j * 4 + 1] << 16) |
                (padded[i * 64 + j * 4 + 2] << 8) |
                padded[i * 64 + j * 4 + 3];
        }
        compress(V, B);
    }

    // 转换为十六进制字符串
    char hex[65];
    for (int i = 0; i < 8; ++i) {
        sprintf(hex + i * 8, "%08x", V[i]);
    }
    hex[64] = '\0';

    return string(hex);
}

// 辅助函数：打印字节数组的十六进制表示
void print_hex(const vector<uint8_t>& data, const string& label) {
    cout << label << ": ";
    for (uint8_t byte : data) {
        cout << hex << setw(2) << setfill('0') << (int)byte;
    }
    cout << dec << endl;
}

int main() {

    // 1. 基础测试
    cout << "1. 基础SM3测试:" << endl;
    string test_str = "abc";
    vector<uint8_t> test_bytes = str_to_bytes(test_str);
    string hash = sm3(test_bytes);

    cout << "输入字符串: " << test_str << endl;
    cout << "SM3哈希值: " << hash << endl;

    // 验证测试向量（abc的SM3哈希值应该是66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0）
    if (hash == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0") {
        cout << "测试通过: 哈希值正确" << endl;
    }
    else {
        cout << "测试失败: 哈希值不正确" << endl;
    }
    cout << endl;

    // 2. 长度扩展攻击演示
    cout << "2. 长度扩展攻击演示:" << endl;

    // 原始消息
    string original_msg = "secret_key_unknown_to_attacker";
    vector<uint8_t> original_bytes = str_to_bytes(original_msg);
    string original_hash = sm3(original_bytes);

    cout << "原始消息: " << original_msg << endl;
    cout << "原始哈希值: " << original_hash << endl;

    // 获取原始消息填充后的完整内容
    vector<uint8_t> padded_original = padding(original_bytes);
    cout << "原始消息长度: " << original_bytes.size() << " 字节" << endl;
    cout << "填充后长度: " << padded_original.size() << " 字节" << endl;

    // 攻击者想要追加的消息
    string append_msg = "||admin=true";
    vector<uint8_t> append_bytes = str_to_bytes(append_msg);

    cout << "要追加的消息: " << append_msg << endl;

    // 将原始哈希值转换为IV
    uint32 custom_IV[8];
    for (int i = 0; i < 8; ++i) {
        sscanf(original_hash.c_str() + i * 8, "%08x", &custom_IV[i]);
    }

    // 执行长度扩展攻击
    uint64_t original_bits = original_bytes.size() * 8;
    // 注意：这里需要考虑原始消息填充后的长度
    uint64_t padded_original_bits = padded_original.size() * 8;

    string extended_hash = sm3_with_custom_iv(append_bytes, custom_IV, padded_original_bits);

    cout << "扩展哈希值 (攻击结果): " << extended_hash << endl;

    // 3. 验证攻击结果
    cout << endl << "3. 验证攻击结果:" << endl;

    // 构造完整的消息：原始消息 + 填充 + 追加消息
    vector<uint8_t> full_message = padded_original;
    full_message.insert(full_message.end(), append_bytes.begin(), append_bytes.end());

    string correct_hash = sm3(full_message);

    cout << "完整消息哈希值 (正常计算): " << correct_hash << endl;

    if (extended_hash == correct_hash) {
        cout << "长度扩展攻击成功!" << endl;
    }
    else {
        cout << "长度扩展攻击失败!" << endl;
    }

    // 展示完整的攻击消息内容
    cout << endl << "5. 完整扩展消息内容:" << endl;
    print_hex(full_message, "完整消息 (十六进制)");

    return 0;
}