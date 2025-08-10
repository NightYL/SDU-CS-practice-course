import hashlib, random, math
from functools import reduce


def is_prime(n, k=8):
    """ Miller-Rabin 素数测试（概率测试）"""
    if n < 2: return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # 将 n-1 写成 d * 2^s 形式
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    def try_composite(a):
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            return False
        for _ in range(s-1):
            x = (x*x) % n
            if x == n-1:
                return False
        return True
    for _ in range(k):
        a = random.randrange(2, n-2)
        if try_composite(a):
            return False
    return True

def gen_prime(bits):
    """ 生成 bits 位素数 """
    while True:
        p = random.getrandbits(bits) | (1 << (bits-1)) | 1
        if is_prime(p):
            return p

def egcd(a,b):
    """ 扩展欧几里得算法 """
    if b==0: return (a,1,0)
    g,x1,y1 = egcd(b, a%b)
    return (g, y1, x1 - (a//b)*y1)

def inv(a,m):
    """ 求模逆 """
    g,x,y = egcd(a,m)
    if g != 1:
        raise Exception("没有模逆")
    return x % m

def lcm(a,b):
    """ 最小公倍数 """
    return a//math.gcd(a,b)*b


# 简单的 Paillier 同态加密实现（用于加密 t_j）
class PaillierPublicKey:
    def __init__(self, n, g):
        self.n = n
        self.nsqr = n*n
        self.g = g

class PaillierPrivateKey:
    def __init__(self, p, q, lam, mu):
        self.p = p; self.q = q; self.lam = lam; self.mu = mu

def paillier_keygen(bits=256):
    """
    生成 Paillier 公私钥
    """
    p = gen_prime(bits//2)
    q = gen_prime(bits//2)
    n = p*q
    g = n + 1
    lam = lcm(p-1, q-1)
    nsqr = n*n
    x = pow(g, lam, nsqr)
    L = (x - 1) // n
    mu = inv(L % n, n)
    return PaillierPublicKey(n, g), PaillierPrivateKey(p, q, lam, mu)

def paillier_encrypt(pk:PaillierPublicKey, m):
    """ Paillier 加密 """
    n = pk.n
    nsqr = pk.nsqr
    while True:
        r = random.randrange(1, n)
        if math.gcd(r, n) == 1:
            break
    c = (pow(pk.g, m, nsqr) * pow(r, n, nsqr)) % nsqr
    return c

def paillier_decrypt(pk:PaillierPublicKey, sk:PaillierPrivateKey, c):
    """ Paillier 解密 """
    n = pk.n; nsqr = pk.nsqr
    x = pow(c, sk.lam, nsqr)
    L = (x - 1) // n
    m = (L * sk.mu) % n
    return m

def paillier_add(pk:PaillierPublicKey, c1, c2):
    """ 同态加法（密文相乘等于明文相加） """
    return (c1 * c2) % pk.nsqr

def paillier_randomize(pk:PaillierPublicKey, c):
    """ 密文随机化，防止重放与关联 """
    n = pk.n; nsqr = pk.nsqr
    while True:
        r = random.randrange(1, n)
        if math.gcd(r, n) == 1:
            break
    return (c * pow(r, n, nsqr)) % nsqr


# 构造 DDH 群：取素数 P，使用 Z_P^* 作为乘法群
def setup_group(bits=256):
    """ 生成群参数（演示用） """
    P = gen_prime(bits)
    # 选取生成元 g（简单扫描）
    for cand in range(2, 1000):
        if pow(cand, (P-1)//2, P) != 1:
            return P, cand
    return P, 2

def hash_to_group(seed: bytes, x: str, P: int):
    """ 模拟随机预言机 H：将字符串映射到群元素 """
    h = hashlib.sha256(seed + x.encode()).digest()
    v = int.from_bytes(h, 'big') % P
    if v == 0:
        v = 1
    return v


# 协议实现
def protocol_demo(P1_items, P2_pairs, group_bits=256, paillier_bits=512, seed=b'common-seed'):
    # -------- 系统初始化 --------
    P, gen = setup_group(group_bits)  # 群参数
    k1 = random.randrange(2, P-1)     # P1 的私有指数
    k2 = random.randrange(2, P-1)     # P2 的私有指数
    pk, sk = paillier_keygen(paillier_bits)  # P2 的 Paillier 密钥

    # ===== Round 1: P1 -> P2 =====
    # 对每个 v_i 计算 H(v_i)^{k1} 并打乱
    P1_hashed = [pow(hash_to_group(seed, v, P), k1, P) for v in P1_items]
    random.shuffle(P1_hashed)

    # ===== Round 2: P2 =====
    # 1) 对 P1 发来的元素再做 k2 次幂
    Z = [pow(x, k2, P) for x in P1_hashed]
    random.shuffle(Z)
    # 2) 对 P2 的 (wj, tj) 计算 H(wj)^{k2} 和 AEnc(tj)
    P2_list = []
    for (w, t) in P2_pairs:
        elem = pow(hash_to_group(seed, w, P), k2, P)
        c = paillier_encrypt(pk, t)
        P2_list.append((elem, c))
    random.shuffle(P2_list)

    # ===== Round 3: P1 =====
    # 1) 对 P2 的元素做 k1 次幂
    P2_upgraded = [(pow(elem, k1, P), c) for (elem, c) in P2_list]
    # 2) 找交集：Z 中出现的就是交集元素
    setZ = set(Z)
    intersect_indices = [i for i, (elem,c) in enumerate(P2_upgraded) if elem in setZ]
    # 3) 对交集的密文同态相加
    if not intersect_indices:
        encrypted_sum = paillier_encrypt(pk, 0)
    else:
        csum = 1
        for i in intersect_indices:
            csum = paillier_add(pk, csum, P2_upgraded[i][1])
        encrypted_sum = paillier_randomize(pk, csum)

    # ===== Round 4: P2 =====
    # P2 解密得到交集和
    SJ = paillier_decrypt(pk, sk, encrypted_sum)

    # 返回结果
    intersect_items = [P2_pairs[i][0] for i in intersect_indices]
    return {
        "P1_items": P1_items,
        "P2_pairs": P2_pairs,
        "intersection_keys": intersect_items,
        "intersection_indices_in_P2": intersect_indices,
        "intersection_sum_decrypted_by_P2": SJ
    }


# 测试运行
if __name__ == "__main__":
    # P1 拥有的集合
    P1_items = ["alice@example.com", "bob@example.com", "carol@site"]
    # P2 拥有的 (标识符, 关联值)
    P2_pairs = [
        ("david@site", 3),
        ("carol@site", 5),
        ("eve@x", 7),
        ("alice@example.com", 2)
    ]
    out = protocol_demo(P1_items, P2_pairs, group_bits=256, paillier_bits=512, seed=b"session-001")
    print("P1 集合:", out["P1_items"])
    print("P2 集合(带值):", out["P2_pairs"])
    print("交集标识符(来自P2):", out["intersection_keys"])
    print("交集索引(P2中的位置):", out["intersection_indices_in_P2"])
    print("交集值的和(P2解密):", out["intersection_sum_decrypted_by_P2"])
