import os
import hashlib
from math import gcd

# secp256k1 参数
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

# ---------- 基本运算 ----------
def modinv(a, m):
    """扩展欧几里得求模逆（返回 a^{-1} mod m）"""
    if a == 0:
        return None
    a %= m
    lm, hm = 1, 0
    low, high = a, m
    while low > 1:
        r = high // low
        nm = hm - lm * r
        new = high - low * r
        hm, lm = lm, nm
        high, low = low, new
    return lm % m

def point_add(Pt, Qt):
    if Pt == (0,0):
        return Qt
    if Qt == (0,0):
        return Pt
    x1,y1 = Pt; x2,y2 = Qt
    if x1 == x2 and (y1 + y2) % P == 0:
        return (0,0)
    if Pt == Qt:
        lam = (3 * x1 * x1 + A) * modinv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * modinv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)

def scalar_mul(k, Pt):
    if k % N == 0 or Pt == (0,0):
        return (0,0)
    if k < 0:
        return scalar_mul(-k, (Pt[0], (-Pt[1]) % P))
    R = (0,0)
    addend = Pt
    while k:
        if k & 1:
            R = point_add(R, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return R

# ---------- ECDSA 签名/验证 ----------
def sha256_int(msg: bytes) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), 'big')

def ecdsa_sign_with_k(d, msg: bytes, k):
    """使用给定 k 做签名"""
    R = scalar_mul(k, G)
    r = R[0] % N
    if r == 0:
        raise ValueError("r == 0")
    e = sha256_int(msg) % N
    s = (modinv(k, N) * (e + d * r)) % N
    if s == 0:
        raise ValueError("s == 0")
    return (r, s)

def ecdsa_verify(Q, msg: bytes, sig):
    r, s = sig
    if not (1 <= r < N and 1 <= s < N):
        return False
    e = sha256_int(msg) % N
    w = modinv(s, N)
    u1 = (e * w) % N
    u2 = (r * w) % N
    P1 = scalar_mul(u1, G)
    P2 = scalar_mul(u2, Q)
    X = point_add(P1, P2)
    return X != (0,0) and (X[0] % N) == r

# ---------- 攻击/PoC ----------
def recover_privkey_from_k_reuse(sig1, sig2, m1, m2):
    """已知两条签名 (r,s1), (r,s2) 且 r 相同（即复用了 k），恢复 k 与私钥 d"""
    r, s1 = sig1
    _, s2 = sig2
    if r != sig2[0]:
        raise ValueError("r 不相同, 不能用 k 重用攻击")
    e1 = sha256_int(m1) % N
    e2 = sha256_int(m2) % N
    # k = (e1 - e2) / (s1 - s2) mod N
    denom = (s1 - s2) % N
    inv = modinv(denom, N)
    k = ((e1 - e2) * inv) % N
    # d = (s1 * k - e1) / r mod N
    d = ((s1 * k - e1) * modinv(r, N)) % N
    return k, d

def brute_force_k_for_small_nonce(r, s, e, max_k=1<<20):
    """当 k 的范围很小（低熵）时，暴力枚举 k 恢复私钥：
       已知 r,s,e：尝试 k in [1, max_k) 找到满足 r == (k*G).x % N 的 k"""
    for k in range(1, max_k):
        R = scalar_mul(k, G)
        if R[0] % N == r:
            # 得到 k，计算 d = (s*k - e)/r mod N
            d = ((s * k - e) * modinv(r, N)) % N
            return k, d
    return None, None

# ---------- 演示主流程 ----------
def demo():
    print("----------- ECDSA 签名误用 PoC 演示 --------------\n")
    # 生成私钥 d 与公钥 Q
    d = int.from_bytes(os.urandom(32), 'big') % N
    if d == 0:
        d = 1
    Q = scalar_mul(d, G)
    print("生成私钥 d (hex):", hex(d))
    print("对应公钥 Qx (hex):", hex(Q[0]))
    print()

    # ---------------- 1) k 重用攻击 ----------------
    print(">> 演示 1：k 重用攻击（两个不同消息使用相同 k）")
    # 模拟开发者错误：对两个消息复用了同一个 k
    k_bad = int.from_bytes(os.urandom(16), 'big') % N  # 随机但被复用
    if k_bad == 0:
        k_bad = 1
    m1 = b"Transaction A: pay 10 BTC to Alice"
    m2 = b"Transaction B: pay 5 BTC to Bob"

    sig1 = ecdsa_sign_with_k(d, m1, k_bad)
    sig2 = ecdsa_sign_with_k(d, m2, k_bad)
    print("签名1(r,s):", (hex(sig1[0]), hex(sig1[1])))
    print("签名2(r,s):", (hex(sig2[0]), hex(sig2[1])))

    # 攻击者拿到 sig1, sig2，尝试恢复 k 与私钥
    if sig1[0] == sig2[0]:
        k_rec, d_rec = recover_privkey_from_k_reuse(sig1, sig2, m1, m2)
        print("恢复的 k:", hex(k_rec))
        print("恢复的私钥 d_rec:", hex(d_rec))
        print("是否恢复成功", d_rec == d)
    else:
        print("r 不相同（极小概率），无法用此方法恢复")

    print("\n")

    # ---------------- 2) 低熵/小 k 攻击 ----------------
    print(">> 演示 2：低熵/小 k 攻击（随机数 k 只有少量可能值）")
    # 制造一个非常弱的 k（例如 k < 2^16），
    small_k = 12345  # 举例小 k
    m3 = b"Small-nonce message"
    sig3 = ecdsa_sign_with_k(d, m3, small_k)
    print("弱随机签名 (r,s):", (hex(sig3[0]), hex(sig3[1])))
    # 攻击者知道签名和消息，可以暴力枚举小范围 k
    e3 = sha256_int(m3) % N
    k_found, d_found = brute_force_k_for_small_nonce(sig3[0], sig3[1], e3, max_k=1<<16)
    if k_found:
        print("暴力枚举恢复 k:", k_found)
        print("暴力枚举恢复私钥 ", hex(d_found), "是否成功",d_found == d)
    else:
        print("在给定范围内未找到 k（可能 k 不在该范围）")

    print("\n")

    # ---------------- 3) 缓解与验证 ----------------
    print(">> 演示 3：缓解措施 - 使用 RFC6979 确定性 k 或安全 RNG")
    # 简单示例：用 Python 的 os.urandom 生成 k（crypto RNG），或用成熟库（示例）
    safe_k = int.from_bytes(os.urandom(32), 'big') % N
    if safe_k == 0:
        safe_k = 1
    m4 = b"Safe-random message"
    sig4 = ecdsa_sign_with_k(d, m4, safe_k)
    print("使用安全 k 签名 (r,s):", (hex(sig4[0]), hex(sig4[1])))


if __name__ == "__main__":
    demo()
