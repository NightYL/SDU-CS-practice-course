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


def modinv(a, m):
    """扩展欧几里得模逆"""
    if a == 0:
        return None
    a %= m
    if a < 0:
        a += m
    # extended gcd
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

# --- ECDSA 签名/验证 ---
def sha256_int(msg: bytes) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), 'big')

def ecdsa_sign_with_k(d, msg: bytes, k):
    """使用指定 k 进行签名"""
    R = scalar_mul(k, G)
    r = R[0] % N
    if r == 0:
        raise ValueError("r == 0, choose different k")
    e = sha256_int(msg) % N
    s = (modinv(k, N) * (e + d * r)) % N
    if s == 0:
        raise ValueError("s == 0, choose different k")
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

# --- 演示流程 ---
def demo_k_reuse_attack():
    # 1) 生成密钥对
    d = int.from_bytes(os.urandom(32), 'big') % N
    if d == 0:
        d = 1
    Q = scalar_mul(d, G)
    print("生成的私钥 d (hex):", hex(d))
    print("对应公钥 Qx,Qy (hex):", hex(Q[0]), hex(Q[1]))

    # 2) 选一个随机 k 并用它对两条不同消息签名
    k = int.from_bytes(os.urandom(32), 'big') % N
    if k == 0:
        k = 1
    m1 = b"Message number one - test"
    m2 = b"Message number two - different content"

    sig1 = ecdsa_sign_with_k(d, m1, k)
    sig2 = ecdsa_sign_with_k(d, m2, k)
    print("\n签名1 (r,s):", (hex(sig1[0]), hex(sig1[1])))
    print("签名2 (r,s):", (hex(sig2[0]), hex(sig2[1])))

    # 3) 攻击者拿到这两个签名后，检测 r 相同 -> 说明可能重用了 k
    r1, s1 = sig1
    r2, s2 = sig2
    if r1 != r2:
        print("\nr 不相同，无法用此方法恢复 k")
        return
    print("\nr 相同，继续恢复 k 和私钥")

    e1 = sha256_int(m1) % N
    e2 = sha256_int(m2) % N

    # k = (e1 - e2) / (s1 - s2) mod N
    denom = (s1 - s2) % N
    inv_denom = modinv(denom, N)
    k_rec = ((e1 - e2) * inv_denom) % N
    print("恢复的 k:", hex(k_rec))

    # 恢复私钥 d = (s1*k - e1) / r mod N
    inv_r = modinv(r1, N)
    d_rec = ((s1 * k_rec - e1) * inv_r) % N
    print("恢复的私钥 d_rec:", hex(d_rec))

    if d_rec == d:
        print("\n成功恢复私钥")
    else:
        print("\n恢复失败")

    # 4) 用恢复的私钥为另一条消息签名
    forged_msg = b"Hello World"
    forged_sig = ecdsa_sign_with_k(d_rec, forged_msg, k_rec)
    print("\n伪造签名 (r,s):", (hex(forged_sig[0]), hex(forged_sig[1])))
    valid = ecdsa_verify(Q, forged_msg, forged_sig)
    print("用公钥验证伪造签名是否有效:", valid)


if __name__ == "__main__":
    demo_k_reuse_attack()
