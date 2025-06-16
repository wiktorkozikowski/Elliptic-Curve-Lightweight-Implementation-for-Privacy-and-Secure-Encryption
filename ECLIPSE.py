import random
from random import randint

O = None

def miller_rabin(n, k=5):
    if n == 2 or n == 3:
        return True
    if n < 2 or n % 2 == 0:
        return False
    s, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def rand_bit_number(k):
    if isinstance(k, int) and k > 0:
        return random.randint(2**(k-1), 2**k - 1)
    else:
        raise ValueError(f'{k}: nie jest poprawną liczbą naturalną')

def rand_prime_mod(k_bits):
    while True:
        number = rand_bit_number(k_bits)
        if miller_rabin(number, k=5):
            return number

def rand_prime_mod_3mod4(k_bits):
    while True:
        p = rand_prime_mod(k_bits)
        if p % 4 == 3:
            return p

def eliptic_curve(p):
    while True:
        a = randint(0, p-1)
        b = randint(0, p-1)
        if (4 * a**3 + 27 * b**2) % p != 0:
            return a, b

def is_on_curve(point, a, b, p):
    if point == O:
        return True
    x, y = point
    return (y**2 - x**3 - a*x - b) % p == 0

def rand_curve_point(a, b, p):
    while True:
        x = randint(0, p-1)
        rhs = (x**3 + a*x + b) % p
        if pow(rhs, (p-1)//2, p) == 1:
            y = pow(rhs, (p + 1) // 4, p)
            return (x, y)

def elliptic_add(P, Q, a, p):
    if P == O:
        return Q
    if Q == O:
        return P
    x_p, y_p = P
    x_q, y_q = Q
    
    if x_p == x_q and (y_p != y_q or y_p == 0):
        return O
    
    if P == Q:
        l = (3 * x_p**2 + a) * pow(2 * y_p, p-2, p) % p
    else:
        l = (y_q - y_p) * pow(x_q - x_p, p-2, p) % p
    
    x_r = (l**2 - x_p - x_q) % p
    y_r = (l * (x_p - x_r) - y_p) % p
    return (x_r, y_r)

def scalar_mult(k, P, a, p):
    result = O
    addend = P
    while k > 0:
        if k & 1:
            result = elliptic_add(result, addend, a, p)
        addend = elliptic_add(addend, addend, a, p)
        k >>= 1
    return result

def generate_keys():
    p = rand_prime_mod_3mod4(256)
    a, b = eliptic_curve(p)
    G = rand_curve_point(a, b, p)
    d = randint(1, p-1) 
    Q = scalar_mult(d, G, a, p)
    return (p, a, b, G, Q), d

def encrypt(M, public_key):
    p, a, b, G, Q = public_key
    k = randint(1, p-1)
    C1 = scalar_mult(k, G, a, p)
    kQ = scalar_mult(k, Q, a, p)
    C2 = elliptic_add(M, kQ, a, p)
    return (C1, C2)

def decrypt(C, private_key, public_key):
    p, a, b, G, Q = public_key
    d = private_key
    C1, C2 = C
    S = scalar_mult(d, C1, a, p)
    if S == O:
        return O
    S_neg = (S[0], (-S[1]) % p)
    M = elliptic_add(C2, S_neg, a, p)
    return M


if __name__ == "__main__":

    public_key, private_key = generate_keys()
    p, a, b, G, Q = public_key
    print(f"Pub Key: p={p}\na={a}\nb={b}\nG={G}\nQ={Q}")
    print(f"Priv Key: d={private_key}\n")

    M = rand_curve_point(a, b, p)
    print(f"message: {M}\n")

    C = encrypt(M, public_key)
    print(f"Encrypted:\n C1={C[0]}\n C2={C[1]}\n")
    

    M_decrypted = decrypt(C, private_key, public_key)
    print(f"Decrypted message: {M_decrypted}")
    print(f"Match: {M == M_decrypted}")
