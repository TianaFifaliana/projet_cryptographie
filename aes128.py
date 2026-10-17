"""AES-128 — implémentation pédagogique en Python.

State : matrice 4x4 d'octets (16 octets = 128 bits), remplie colonne par colonne.
Une ronde : SubBytes -> ShiftRows -> MixColumns -> AddRoundKey.
AES-128 : 10 rondes, AddRoundKey initial avec K0, pas de MixColumns a la derniere ronde.
"""

SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
]


def xtime(a):
    """Multiplication par 2 dans GF(2^8), modulo x^8 + x^4 + x^3 + x + 1 (0x11b)."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11b
    return a & 0xff


def gmul(a, b):
    """Multiplication de deux octets dans GF(2^8)."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result & 0xff


def bytes_to_state(block):
    """16 octets -> State 4x4 (state[row][col]), remplissage colonne par colonne."""
    return [[block[col * 4 + row] for col in range(4)] for row in range(4)]


def state_to_bytes(state):
    """State 4x4 -> 16 octets (lecture colonne par colonne)."""
    return bytes(state[row][col] for col in range(4) for row in range(4))


def key_expansion(key):
    """Etend la cle de 16 octets en 11 cles de ronde (K0..K10), chacune de 16 octets."""
    words = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]                       # RotWord
            temp = [SBOX[b] for b in temp]                   # SubWord
            temp[0] ^= RCON[i // 4 - 1]                      # Rcon
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])
    round_keys = []
    for r in range(11):
        rk = []
        for c in range(4):
            rk.extend(words[r * 4 + c])
        round_keys.append(bytes_to_state(rk))
    return round_keys

# manova ny valeur ny octet
def sub_bytes(state):
    """Confusion : remplace chaque octet par son image dans la S-Box."""
    return [[SBOX[state[row][col]] for col in range(4)] for row in range(4)]

# manova ny position ny octet
def shift_rows(state):
    """Diffusion : decale la ligne r de r cases vers la gauche (circulaire)."""
    return [state[row][row:] + state[row][:row] for row in range(4)]

# mélange les 4 octets de chaque colonne
def mix_columns(state):
    """Diffusion : multiplie chaque colonne par la matrice fixe dans GF(2^8)."""
    result = [[0] * 4 for _ in range(4)]
    for col in range(4):
        s = [state[row][col] for row in range(4)]
        result[0][col] = gmul(s[0], 2) ^ gmul(s[1], 3) ^ s[2] ^ s[3]
        result[1][col] = s[0] ^ gmul(s[1], 2) ^ gmul(s[2], 3) ^ s[3]
        result[2][col] = s[0] ^ s[1] ^ gmul(s[2], 2) ^ gmul(s[3], 3)
        result[3][col] = gmul(s[0], 3) ^ s[1] ^ s[2] ^ gmul(s[3], 2)
    return result

# manao xor aminy k
def add_round_key(state, round_key):
    """Secret : XOR du State avec la cle de ronde."""
    return [[state[row][col] ^ round_key[row][col] for col in range(4)] for row in range(4)]


def encrypt(plaintext, key):
    """Chiffre un bloc de 16 octets. Retourne (ciphertext, trace des states par ronde)."""
    round_keys = key_expansion(key)
    state = bytes_to_state(plaintext)
    trace = [state]

    state = add_round_key(state, round_keys[0])          # AddRoundKey initial avec K0
    trace.append(state)

    for r in range(1, 10):                               # Rondes 1 a 9
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[r])
        trace.append(state)

    state = sub_bytes(state)                             # Ronde 10 (finale)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])         # pas de MixColumns
    trace.append(state)

    return state_to_bytes(state), trace


if __name__ == "__main__":
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")

    ciphertext, trace = encrypt(plaintext, key)
    print("Clair     :", plaintext.hex())
    print("Cle       :", key.hex())
    print("Chiffre   :", ciphertext.hex())
    print("Attendu   :", "69c4e0d86a7b0430d8cdb78070b4c55a")
    print("OK        :", ciphertext.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a")

    print("\nTrace (State de sortie de chaque etape) :")
    print("  K0        :", trace[0])
    for r in range(1, 10):
        print(f"  ronde {r:>2}   :", trace[r])
    print("  ronde 10  :", trace[10])
