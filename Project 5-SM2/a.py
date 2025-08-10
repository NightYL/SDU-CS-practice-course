import os
import struct


# SM2 椭圆曲线参数
p  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b  = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
n  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123


# 基本数论与椭圆曲线运算
def inv_mod(x, m=p):
    """模逆（扩展欧几里得），保证 0 < x < m"""
    if x == 0:
        raise ZeroDivisionError('division by zero')
    lm, hm = 1, 0
    low, high = x % m, m
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % m

def is_on_curve(P):
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + a * x + b)) % p == 0

def point_add(P, Q):
    """椭圆曲线点加法，P,Q 为 (x,y) 或 None 表示无穷点"""
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + a) * inv_mod(2 * y1, p) % p
    else:
        lam = (y2 - y1) * inv_mod(x2 - x1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mul(k, P):
    """Double-and-add，返回 k*P"""
    if k % n == 0 or P is None:
        return None
    if k < 0:
        return scalar_mul(-k, (P[0], (-P[1]) % p))
    R = None
    addend = P
    while k:
        if k & 1:
            R = point_add(R, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return R



def int_to_bytes(x: int, size=None):
    if x is None:
        return None
    if size is None:
        size = (x.bit_length() + 7) // 8
    return x.to_bytes(size, 'big')

def bytes_to_int(b: bytes):
    return int.from_bytes(b, 'big')

def point_to_bytes(P, compress=False):
    """返回未压缩公钥 bytes：04 || x || y"""
    if P is None:
        return b''
    x, y = P
    xb = int_to_bytes(x, 32)
    yb = int_to_bytes(y, 32)
    return b'\x04' + xb + yb

def bytes_to_point(b):
    """从未压缩字节 04||x||y 恢复点"""
    if len(b) == 0:
        return None
    assert b[0] == 4 and len(b) == 65
    x = bytes_to_int(b[1:33])
    y = bytes_to_int(b[33:65])
    return (x, y)


# SM3 哈希
IV = [
    0x7380166F,
    0x4914B2B9,
    0x172442D7,
    0xDA8A0600,
    0xA96F30BC,
    0x163138AA,
    0xE38DEE4D,
    0xB0FB0E4E
]

T_j = [0x79CC4519] * 16 + [0x7A879D8A] * 48

def _rotl(x, n):
    """左循环移位，n 取模 32 防止负移位或过大移位"""
    n = n % 32
    x &= 0xFFFFFFFF
    if n == 0:
        return x
    return ((x << n) & 0xFFFFFFFF) | ((x & 0xFFFFFFFF) >> (32 - n))

def _sm3_cf(V_i, B_i):
    """压缩函数，V_i 为 8 个 32-bit 单元，B_i 为 64 字节块"""
    W = []
    for j in range(16):
        W.append(bytes_to_int(B_i[j*4:(j+1)*4]) & 0xFFFFFFFF)
    for j in range(16, 68):
        x = W[j-16] ^ W[j-9] ^ _rotl(W[j-3], 15)
        x &= 0xFFFFFFFF
        # P1(x) = x ^ (x<<<15) ^ (x<<<23)
        p1 = x ^ _rotl(x, 15) ^ _rotl(x, 23)
        val = (p1 ^ _rotl(W[j-13], 7) ^ W[j-6]) & 0xFFFFFFFF
        W.append(val)
    W_ = [(W[j] ^ W[j+4]) & 0xFFFFFFFF for j in range(64)]

    A,B,C,D,E,F,G,H = V_i
    A &= 0xFFFFFFFF; B &= 0xFFFFFFFF; C &= 0xFFFFFFFF; D &= 0xFFFFFFFF
    E &= 0xFFFFFFFF; F &= 0xFFFFFFFF; G &= 0xFFFFFFFF; H &= 0xFFFFFFFF

    for j in range(64):
        SS1 = _rotl(((_rotl(A,12) + E + _rotl(T_j[j], j)) & 0xFFFFFFFF), 7)
        SS2 = SS1 ^ _rotl(A, 12)
        if j <= 15:
            FF = A ^ B ^ C
            GG = E ^ F ^ G
        else:
            FF = ((A & B) | (A & C) | (B & C)) & 0xFFFFFFFF
            GG = ((E & F) | ((~E) & G)) & 0xFFFFFFFF
        TT1 = (FF + D + SS2 + W_[j]) & 0xFFFFFFFF
        TT2 = (GG + H + SS1 + W[j]) & 0xFFFFFFFF
        D = C
        C = _rotl(B, 9)
        B = A
        A = TT1 & 0xFFFFFFFF
        H = G
        G = _rotl(F, 19)
        F = E
        E = (TT2 ^ _rotl(T_j[j], j)) & 0xFFFFFFFF

    return [
        (V_i[0] ^ A) & 0xFFFFFFFF,
        (V_i[1] ^ B) & 0xFFFFFFFF,
        (V_i[2] ^ C) & 0xFFFFFFFF,
        (V_i[3] ^ D) & 0xFFFFFFFF,
        (V_i[4] ^ E) & 0xFFFFFFFF,
        (V_i[5] ^ F) & 0xFFFFFFFF,
        (V_i[6] ^ G) & 0xFFFFFFFF,
        (V_i[7] ^ H) & 0xFFFFFFFF
    ]

def sm3_hash(msg: bytes) -> bytes:
    """返回 SM3 摘要（32 字节）"""
    msg = bytearray(msg)
    l = len(msg) * 8
    msg.append(0x80)
    while ((len(msg) * 8) % 512) != 448:
        msg.append(0x00)
    msg += struct.pack('>Q', l)
    V = IV[:]
    for i in range(0, len(msg), 64):
        block = bytes(msg[i:i+64])
        V = _sm3_cf(V, block)
    out = b''.join(struct.pack('>I', x) for x in V)
    return out


# KDF : 输出 klen 字节
def kdf(z: bytes, klen: int) -> bytes:
    if klen == 0:
        return b''
    ct = 1
    v = b''
    for _ in range((klen + 31) // 32):
        digest = sm3_hash(z + struct.pack('>I', ct))
        v += digest
        ct += 1
    return v[:klen]


# ZA 计算：将用户 ID 与公钥相关联的摘要
def za_hash(user_id: bytes, pub: tuple):
    entl = len(user_id) * 8
    a_bytes = int_to_bytes(a, 32)
    b_bytes = int_to_bytes(b, 32)
    gx_bytes = int_to_bytes(gx, 32)
    gy_bytes = int_to_bytes(gy, 32)
    px_bytes = int_to_bytes(pub[0], 32)
    py_bytes = int_to_bytes(pub[1], 32)
    data = struct.pack('>H', entl) + user_id + a_bytes + b_bytes + gx_bytes + gy_bytes + px_bytes + py_bytes
    return sm3_hash(data)




# SM2 签名 / 验证
def sm2_key_gen():
    """生成私钥 d (int) 与公钥 P = d*G (tuple)"""
    while True:
        d = int.from_bytes(os.urandom(32), 'big') % n
        if 1 <= d <= n-1:
            break
    P = scalar_mul(d, (gx, gy))
    return d, P


def sm2_sign(msg: bytes, d: int, user_id: bytes = b'1234567812345678'):
    """返回 (r, s) 二元组，均为 int"""
    P = scalar_mul(d, (gx, gy))
    ZA = za_hash(user_id, P)
    M_ = ZA + msg
    e = bytes_to_int(sm3_hash(M_)) % n
    while True:
        k = int.from_bytes(os.urandom(32), 'big') % n
        if k == 0:
            continue
        x1y1 = scalar_mul(k, (gx, gy))
        if x1y1 is None:
            continue
        x1 = x1y1[0]
        r = (e + x1) % n
        if r == 0 or r + k == n:
            continue
        s = (inv_mod(1 + d, n) * (k - r * d)) % n
        if s == 0:
            continue
        return r, s

def sm2_verify(msg: bytes, signature: tuple, P: tuple, user_id: bytes = b'1234567812345678'):
    """signature: (r,s) ints; P: pubkey point (x,y)"""
    r, s = signature
    if not (1 <= r <= n-1 and 1 <= s <= n-1):
        return False
    ZA = za_hash(user_id, P)
    e = bytes_to_int(sm3_hash(ZA + msg)) % n
    t = (r + s) % n
    if t == 0:
        return False
    x1y1 = point_add(scalar_mul(s, (gx, gy)), scalar_mul(t, P))
    if x1y1 is None:
        return False
    x1 = x1y1[0]
    R = (e + x1) % n
    return R == r



# SM2
def sm2_encrypt(msg: bytes, P_B: tuple):
    klen = len(msg)
    while True:
        k = int.from_bytes(os.urandom(32), 'big') % n
        if k == 0:
            continue
        C1 = scalar_mul(k, (gx, gy))
        S = scalar_mul(k, P_B)
        if S is None:
            continue
        x2 = int_to_bytes(S[0], 32)
        y2 = int_to_bytes(S[1], 32)
        t = kdf(x2 + y2, klen)
        if int.from_bytes(t, 'big') == 0:
            continue
        C2 = bytes(x ^ y for x, y in zip(msg, t))
        C3 = sm3_hash(x2 + msg + y2)
        return point_to_bytes(C1) + C3 + C2

def sm2_decrypt(cipher: bytes, d_B: int):
    if len(cipher) < 65 + 32:
        raise ValueError("cipher too short")
    C1_bytes = cipher[:65]
    C3 = cipher[65:97]
    C2 = cipher[97:]
    C1 = bytes_to_point(C1_bytes)
    if not is_on_curve(C1):
        raise ValueError("C1 not on curve")
    S = scalar_mul(d_B, C1)
    if S is None:
        raise ValueError("S is infinity")
    x2 = int_to_bytes(S[0], 32)
    y2 = int_to_bytes(S[1], 32)
    t = kdf(x2 + y2, len(C2))
    if int.from_bytes(t, 'big') == 0:
        raise ValueError("kdf returned zero")
    M = bytes(x ^ y for x, y in zip(C2, t))
    u = sm3_hash(x2 + M + y2)
    if u != C3:
        raise ValueError("C3 verification failed")
    return M


# 测试用例
def demo():
    print("---------------------生成密钥对----------------")
    dA, PA = sm2_key_gen()
    dB, PB = sm2_key_gen()
    print("私钥 dA =", hex(dA))
    print("公钥 PA = (%s, %s)" % (hex(PA[0]), hex(PA[1])))

    msg = b"Hello, SM2 Python!"
    print("\n----------------- 签名/验签 ----------------------")
    sig = sm2_sign(msg, dA)
    print("signature (r,s):", (hex(sig[0]), hex(sig[1])))
    ok = sm2_verify(msg, sig, PA)
    print("验证结果:", ok)

    print("\n--------------- 加密/解密 --------------------")
    cipher = sm2_encrypt(msg, PB)
    print("cipher len:", len(cipher))
    rec = sm2_decrypt(cipher, dB)
    print("解密结果 matches:", rec == msg)
    print("解密文本：", rec)

if __name__ == "__main__":
    demo()
