#define _CRT_SECURE_NO_WARNINGS  
#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <cmath>
#include <random>
#include <chrono>
#include <map>
#include <set>

using namespace std;

typedef unsigned int uint32;
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
inline uint32 FF0(uint32 x, uint32 y, uint32 z) { return x ^ y ^ z; }
inline uint32 FF1(uint32 x, uint32 y, uint32 z) { return (x & y) | (x & z) | (y & z); }
inline uint32 GG0(uint32 x, uint32 y, uint32 z) { return x ^ y ^ z; }
inline uint32 GG1(uint32 x, uint32 y, uint32 z) { return (x & y) | (~x & z); }

// 置换函数
inline uint32 P0(uint32 x) { return x ^ ROTL(x, 9) ^ ROTL(x, 17); }
inline uint32 P1(uint32 x) { return x ^ ROTL(x, 15) ^ ROTL(x, 23); }

// 消息填充
vector<uint8_t> padding(const vector<uint8_t>& msg) {
    vector<uint8_t> padded = msg;
    padded.push_back(0x80);

    size_t len = padded.size() * 8;
    size_t pad_len = (448 - len % 512 + 512) % 512;
    pad_len /= 8;
    padded.insert(padded.end(), pad_len, 0x00);

    uint64_t msg_len = msg.size() * 8;
    for (int i = 7; i >= 0; --i) {
        padded.push_back((msg_len >> (i * 8)) & 0xFF);
    }
    return padded;
}

// 消息扩展
void expand(const uint32 W[16], uint32 W1[68], uint32 W2[64]) {
    for (int i = 0; i < 16; ++i) W1[i] = W[i];
    for (int i = 16; i < 68; ++i) {
        W1[i] = P1(W1[i - 16] ^ W1[i - 9] ^ ROTL(W1[i - 3], 15)) ^ ROTL(W1[i - 13], 7) ^ W1[i - 6];
    }
    for (int i = 0; i < 64; ++i) W2[i] = W1[i] ^ W1[i + 4];
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
        uint32 TT1 = (j < 16 ? FF0(A, b, C) : FF1(A, b, C)) + D + SS2 + W2[j];
        uint32 TT2 = (j < 16 ? GG0(E, F, G) : GG1(E, F, G)) + H + SS1 + W1[j];
        D = C; C = ROTL(b, 9); b = A; A = TT1;
        H = G; G = ROTL(F, 19); F = E; E = P0(TT2);
    }

    V[0] ^= A; V[1] ^= b; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

// SM3哈希计算
string sm3_hash(const vector<uint8_t>& msg) {
    vector<uint8_t> padded = padding(msg);
    size_t block_num = padded.size() / 64;

    uint32 V[8];
    memcpy(V, IV, 8 * sizeof(uint32));

    for (size_t i = 0; i < block_num; ++i) {
        uint32 B[16];
        for (int j = 0; j < 16; ++j) {
            B[j] = (padded[i * 64 + j * 4] << 24) | (padded[i * 64 + j * 4 + 1] << 16) |
                (padded[i * 64 + j * 4 + 2] << 8) | padded[i * 64 + j * 4 + 3];
        }
        compress(V, B);
    }

    char hex[65];
    for (int i = 0; i < 8; ++i) {
        sprintf(hex + i * 8, "%08x", V[i]);
    }
    hex[64] = '\0';
    return string(hex);
}

// 辅助函数
vector<uint8_t> str_to_bytes(const string& s) {
    return vector<uint8_t>(s.begin(), s.end());
}

vector<uint8_t> hex_to_bytes(const string& hex) {
    vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.size(); i += 2) {
        char c1 = hex[i], c2 = hex[i + 1];
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

// Merkle树节点结构
struct MerkleNode {
    string hash;
    shared_ptr<MerkleNode> left;
    shared_ptr<MerkleNode> right;
    int index;  // 叶子节点的索引

    MerkleNode(const string& h, int idx = -1) : hash(h), left(nullptr), right(nullptr), index(idx) {}
};

// 审计路径结构
struct AuditPath {
    vector<string> hashes;
    vector<bool> directions;  // true表示右侧，false表示左侧

    void addNode(const string& hash, bool is_right) {
        hashes.push_back(hash);
        directions.push_back(is_right);
    }
};

// 包含性证明结构
struct InclusionProof {
    int leaf_index;
    string leaf_hash;
    AuditPath audit_path;
    string tree_root;

    InclusionProof(int idx, const string& hash, const string& root)
        : leaf_index(idx), leaf_hash(hash), tree_root(root) {}
};

// 非包含性证明结构  
struct NonInclusionProof {
    string target_hash;
    int left_index;
    int right_index;
    InclusionProof left_proof;
    InclusionProof right_proof;
    string tree_root;

    NonInclusionProof(const string& target, int left_idx, int right_idx,
        const InclusionProof& left, const InclusionProof& right, const string& root)
        : target_hash(target), left_index(left_idx), right_index(right_idx),
        left_proof(left), right_proof(right), tree_root(root) {}
};

// RFC 6962 Merkle树实现
class MerkleTree {
private:
    vector<string> leaves;
    shared_ptr<MerkleNode> root;
    map<string, int> leaf_index_map;  // 哈希值到索引的映射

    // RFC 6962: MTH函数 - Merkle Tree Hash
    string mth(const vector<string>& leaf_hashes) {
        if (leaf_hashes.empty()) {
            return sm3_hash(str_to_bytes(""));  // 空树的哈希
        }
        if (leaf_hashes.size() == 1) {
            // RFC 6962: MTH({d(0)}) = SHA-256(0x00 || d(0))
            vector<uint8_t> data;
            data.push_back(0x00);  // 叶子节点前缀
            vector<uint8_t> leaf_data = hex_to_bytes(leaf_hashes[0]);
            data.insert(data.end(), leaf_data.begin(), leaf_data.end());
            return sm3_hash(data);
        }

        // RFC 6962: MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
        // 找到最大的2的幂次小于等于n
        size_t k = 1;
        while (k < leaf_hashes.size()) k <<= 1;
        k >>= 1;

        vector<string> left_hashes(leaf_hashes.begin(), leaf_hashes.begin() + k);
        vector<string> right_hashes(leaf_hashes.begin() + k, leaf_hashes.end());

        string left_hash = mth(left_hashes);
        string right_hash = mth(right_hashes);

        vector<uint8_t> data;
        data.push_back(0x01);  // 内部节点前缀
        vector<uint8_t> left_data = hex_to_bytes(left_hash);
        vector<uint8_t> right_data = hex_to_bytes(right_hash);
        data.insert(data.end(), left_data.begin(), left_data.end());
        data.insert(data.end(), right_data.begin(), right_data.end());

        return sm3_hash(data);
    }

    // 构建树结构（用于路径提取）
    shared_ptr<MerkleNode> build_tree(const vector<string>& leaf_hashes, int start_index = 0) {
        if (leaf_hashes.empty()) {
            return nullptr;
        }

        if (leaf_hashes.size() == 1) {
            vector<uint8_t> data;
            data.push_back(0x00);
            vector<uint8_t> leaf_data = hex_to_bytes(leaf_hashes[0]);
            data.insert(data.end(), leaf_data.begin(), leaf_data.end());
            string hash = sm3_hash(data);
            return make_shared<MerkleNode>(hash, start_index);
        }

        size_t k = 1;
        while (k < leaf_hashes.size()) k <<= 1;
        k >>= 1;

        vector<string> left_hashes(leaf_hashes.begin(), leaf_hashes.begin() + k);
        vector<string> right_hashes(leaf_hashes.begin() + k, leaf_hashes.end());

        auto left_child = build_tree(left_hashes, start_index);
        auto right_child = build_tree(right_hashes, start_index + k);

        string left_hash = left_child->hash;
        string right_hash = right_child->hash;

        vector<uint8_t> data;
        data.push_back(0x01);
        vector<uint8_t> left_data = hex_to_bytes(left_hash);
        vector<uint8_t> right_data = hex_to_bytes(right_hash);
        data.insert(data.end(), left_data.begin(), left_data.end());
        data.insert(data.end(), right_data.begin(), right_data.end());

        string hash = sm3_hash(data);
        auto node = make_shared<MerkleNode>(hash);
        node->left = left_child;
        node->right = right_child;

        return node;
    }

    // 提取审计路径
    bool extract_audit_path(shared_ptr<MerkleNode> node, int target_index, AuditPath& path) {
        if (!node) return false;

        // 叶子节点
        if (!node->left && !node->right) {
            return node->index == target_index;
        }

        // 检查左子树
        if (node->left && extract_audit_path(node->left, target_index, path)) {
            if (node->right) {
                path.addNode(node->right->hash, true);  // 右侧兄弟节点
            }
            return true;
        }

        // 检查右子树
        if (node->right && extract_audit_path(node->right, target_index, path)) {
            if (node->left) {
                path.addNode(node->left->hash, false);  // 左侧兄弟节点
            }
            return true;
        }

        return false;
    }

public:
    // 构造函数
    MerkleTree(const vector<string>& leaf_data) {
        // 计算叶子哈希值
        for (size_t i = 0; i < leaf_data.size(); ++i) {
            string leaf_hash = sm3_hash(str_to_bytes(leaf_data[i]));
            leaves.push_back(leaf_hash);
            leaf_index_map[leaf_hash] = i;
        }

        // 构建树
        root = build_tree(leaves);
    }

    // 获取根哈希
    string get_root() const {
        return root ? root->hash : "";
    }

    // 生成包含性证明
    InclusionProof generate_inclusion_proof(int leaf_index) {
        if (leaf_index < 0 || leaf_index >= leaves.size()) {
            throw invalid_argument("叶子索引超出范围");
        }

        string leaf_hash = leaves[leaf_index];
        InclusionProof proof(leaf_index, leaf_hash, get_root());

        extract_audit_path(root, leaf_index, proof.audit_path);

        return proof;
    }

    // 验证包含性证明
    bool verify_inclusion_proof(const InclusionProof& proof) {
        vector<uint8_t> data;
        data.push_back(0x00);  // 叶子节点前缀
        vector<uint8_t> leaf_data = hex_to_bytes(proof.leaf_hash);
        data.insert(data.end(), leaf_data.begin(), leaf_data.end());
        string current_hash = sm3_hash(data);

        // 沿着审计路径计算根哈希
        for (size_t i = 0; i < proof.audit_path.hashes.size(); ++i) {
            vector<uint8_t> node_data;
            node_data.push_back(0x01);  // 内部节点前缀

            vector<uint8_t> current_data = hex_to_bytes(current_hash);
            vector<uint8_t> sibling_data = hex_to_bytes(proof.audit_path.hashes[i]);

            if (proof.audit_path.directions[i]) {  // 兄弟节点在右侧
                node_data.insert(node_data.end(), current_data.begin(), current_data.end());
                node_data.insert(node_data.end(), sibling_data.begin(), sibling_data.end());
            }
            else {  // 兄弟节点在左侧
                node_data.insert(node_data.end(), sibling_data.begin(), sibling_data.end());
                node_data.insert(node_data.end(), current_data.begin(), current_data.end());
            }

            current_hash = sm3_hash(node_data);
        }

        return current_hash == proof.tree_root;
    }

    // 生成非包含性证明
    NonInclusionProof generate_non_inclusion_proof(const string& target_data) {
        string target_hash = sm3_hash(str_to_bytes(target_data));

        // 查找目标哈希在排序后的位置
        vector<pair<string, int>> sorted_leaves;
        for (size_t i = 0; i < leaves.size(); ++i) {
            sorted_leaves.push_back({ leaves[i], i });
        }
        sort(sorted_leaves.begin(), sorted_leaves.end());

        // 找到目标应该插入的位置
        int insert_pos = 0;
        for (const auto& leaf : sorted_leaves) {
            if (leaf.first < target_hash) {
                insert_pos++;
            }
            else {
                break;
            }
        }

        // 选择左右邻居
        int left_idx = max(0, insert_pos - 1);
        int right_idx = min((int)sorted_leaves.size() - 1, insert_pos);

        // 如果目标就是某个叶子，证明失败
        if (sorted_leaves[left_idx].first == target_hash || sorted_leaves[right_idx].first == target_hash) {
            throw invalid_argument("目标数据已存在于树中");
        }

        // 生成左右邻居的包含性证明
        InclusionProof left_proof = generate_inclusion_proof(sorted_leaves[left_idx].second);
        InclusionProof right_proof = generate_inclusion_proof(sorted_leaves[right_idx].second);

        return NonInclusionProof(target_hash, sorted_leaves[left_idx].second,
            sorted_leaves[right_idx].second, left_proof, right_proof, get_root());
    }

    // 验证非包含性证明
    bool verify_non_inclusion_proof(const NonInclusionProof& proof) {
        // 验证左右证明
        if (!verify_inclusion_proof(proof.left_proof) || !verify_inclusion_proof(proof.right_proof)) {
            return false;
        }

        // 验证目标哈希在左右之间
        return proof.left_proof.leaf_hash < proof.target_hash &&
            proof.target_hash < proof.right_proof.leaf_hash;
    }

    // 获取树的统计信息
    void print_stats() {
        cout << "Merkle树统计信息:" << endl;
        cout << "叶子节点数量: " << leaves.size() << endl;
        cout << "树深度: " << (int)ceil(log2(leaves.size())) << endl;
        cout << "根哈希: " << get_root() << endl;
        cout << endl;
    }
};

int main() {
    cout << "------------- 基于SM3的RFC6962 Merkle树实现 ----------------" << endl << endl;

    // 生成测试数据（10万个叶子节点）
    const int LEAF_COUNT = 100000;
    cout << "正在生成 " << LEAF_COUNT << " 个叶子节点..." << endl;

    vector<string> leaf_data;
    leaf_data.reserve(LEAF_COUNT);

    auto start_time = chrono::high_resolution_clock::now();

    for (int i = 0; i < LEAF_COUNT; ++i) {
        leaf_data.push_back("data_entry_" + to_string(i) + "_" + to_string(rand()));
    }

    cout << "数据生成完成，开始构建Merkle树..." << endl;

    // 构建Merkle树
    MerkleTree tree(leaf_data);

    auto end_time = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);

    cout << "Merkle树构建完成，耗时: " << duration.count() << " 毫秒" << endl << endl;

    // 打印树的统计信息
    tree.print_stats();

    // 测试包含性证明
    cout << "=== 包含性证明测试 ===" << endl;

    vector<int> test_indices = { 0, 1000, 50000, 99999, 12345 };

    for (int idx : test_indices) {
        cout << "测试叶子节点 " << idx << ":" << endl;

        try {
            auto proof_start = chrono::high_resolution_clock::now();
            InclusionProof proof = tree.generate_inclusion_proof(idx);
            auto proof_end = chrono::high_resolution_clock::now();
            auto proof_duration = chrono::duration_cast<chrono::microseconds>(proof_end - proof_start);

            cout << "  生成证明耗时: " << proof_duration.count() << " 微秒" << endl;
            cout << "  审计路径长度: " << proof.audit_path.hashes.size() << endl;

            auto verify_start = chrono::high_resolution_clock::now();
            bool is_valid = tree.verify_inclusion_proof(proof);
            auto verify_end = chrono::high_resolution_clock::now();
            auto verify_duration = chrono::duration_cast<chrono::microseconds>(verify_end - verify_start);

            cout << "  验证耗时: " << verify_duration.count() << " 微秒" << endl;
            cout << "  验证结果: " << (is_valid ? "通过" : "失败") << endl;
        }
        catch (const exception& e) {
            cout << "  错误: " << e.what() << endl;
        }
        cout << endl;
    }

    // 测试非包含性证明
    cout << "------------ 非包含性证明测试 ------------" << endl;

    vector<string> non_existent_data = {
        "non_existent_data_1",
        "fake_entry_12345",
        "missing_data_xyz",
        "absent_record_999"
    };

    for (const string& data : non_existent_data) {
        cout << "测试不存在的数据: " << data << endl;

        try {
            auto proof_start = chrono::high_resolution_clock::now();
            NonInclusionProof proof = tree.generate_non_inclusion_proof(data);
            auto proof_end = chrono::high_resolution_clock::now();
            auto proof_duration = chrono::duration_cast<chrono::microseconds>(proof_end - proof_start);

            cout << "  生成证明耗时: " << proof_duration.count() << " 微秒" << endl;
            cout << "  左邻居索引: " << proof.left_index << endl;
            cout << "  右邻居索引: " << proof.right_index << endl;

            auto verify_start = chrono::high_resolution_clock::now();
            bool is_valid = tree.verify_non_inclusion_proof(proof);
            auto verify_end = chrono::high_resolution_clock::now();
            auto verify_duration = chrono::duration_cast<chrono::microseconds>(verify_end - verify_start);

            cout << "  验证耗时: " << verify_duration.count() << " 微秒" << endl;
            cout << "  验证结果: " << (is_valid ? "通过" : "失败") << endl;
        }
        catch (const exception& e) {
            cout << "  错误: " << e.what() << endl;
        }
        cout << endl;
    }

    // 性能总结
    cout << "---------- 性能总结 -----------" << endl;
    cout << "- 支持 " << LEAF_COUNT << " 个叶子节点" << endl;
    cout << "- 审计路径长度: " << (int)ceil(log2(LEAF_COUNT)) << " 个哈希值" << endl;
    cout << "- 证明大小: " << (int)ceil(log2(LEAF_COUNT)) * 32 << " 字节" << endl;

    return 0;
}