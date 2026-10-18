
import os

TAILLE_BLOC = 16


# ============================================================
# 1. Arithmétique dans GF(2^8) et S-box
# ============================================================

def gmul(a, b):
    """Multiplication dans GF(2^8), modulo x^8 + x^4 + x^3 + x + 1 (0x11b)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11b
        b >>= 1
    return p & 0xFF


def ginverse(x):
    """Inverse de x dans GF(2^8) (0 n'a pas d'inverse, on renvoie 0)."""
    if x == 0:
        return 0
    for y in range(1, 256):
        if gmul(x, y) == 1:
            return y


def rotl8(v, n):
    return ((v << n) | (v >> (8 - n))) & 0xFF


def affine(b):
    return b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ 0x63


SBOX = [affine(ginverse(i)) for i in range(256)]
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i


# ============================================================
# 2. Expansion de la clé : 16 octets -> 11 clés de round
# ============================================================

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def expand_key(key):
    if len(key) != 16:
        raise ValueError("AES-128 exige une clé de 16 octets")

    words = [list(key[4 * c:4 * c + 4]) for c in range(4)]
    for i in range(4, 44):
        temp = words[i - 1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[i // 4 - 1]
        words.append([a ^ b for a, b in zip(words[i - 4], temp)])

    return [bytes(b for c in range(4) for b in words[4 * r + c]) for r in range(11)]


# ============================================================
# 3. Transformations d'AES (état = 16 octets, index = ligne + 4 * colonne)
# ============================================================

def add_round_key(state, rk):
    return [s ^ k for s, k in zip(state, rk)]


def sub_bytes(state):
    return [SBOX[b] for b in state]


def inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]


def shift_rows(state):
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = state[r + 4 * ((c + r) % 4)]
    return out


def inv_shift_rows(state):
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = state[r + 4 * ((c - r) % 4)]
    return out


def mix_columns(state):
    out = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = state[4 * c:4 * c + 4]
        out[4 * c + 0] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3
        out[4 * c + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3
        out[4 * c + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3)
        out[4 * c + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2)
    return out


def inv_mix_columns(state):
    out = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = state[4 * c:4 * c + 4]
        out[4 * c + 0] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9)
        out[4 * c + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13)
        out[4 * c + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11)
        out[4 * c + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14)
    return out


# ============================================================
# 4. AES sur un seul bloc : EK et DK
# ============================================================

def aes_encrypt_block(block, round_keys):
    state = add_round_key(list(block), round_keys[0])
    for r in range(1, 10):
        state = add_round_key(mix_columns(shift_rows(sub_bytes(state))), round_keys[r])
    state = add_round_key(shift_rows(sub_bytes(state)), round_keys[10])
    return bytes(state)


def aes_decrypt_block(block, round_keys):
    state = add_round_key(list(block), round_keys[10])
    for r in range(9, 0, -1):
        state = inv_mix_columns(add_round_key(inv_sub_bytes(inv_shift_rows(state)), round_keys[r]))
    state = add_round_key(inv_sub_bytes(inv_shift_rows(state)), round_keys[0])
    return bytes(state)


# ============================================================
# 5. Mode ECB
# ============================================================

def pad(data):
    """ajoute n octets de valeur n pour obtenir un multiple de 16."""
    n = TAILLE_BLOC - len(data) % TAILLE_BLOC
    return data + bytes([n]) * n


def unpad(data):
    n = data[-1]
    if n < 1 or n > TAILLE_BLOC or data[-n:] != bytes([n]) * n:
        raise ValueError("padding invalide")
    return data[:-n]


def chiffrer_ecb(message, cle):
    round_keys = expand_key(cle)
    donnees = pad(message)
    blocs = [donnees[i:i + TAILLE_BLOC] for i in range(0, len(donnees), TAILLE_BLOC)]
    return b"".join(aes_encrypt_block(b, round_keys) for b in blocs)


def dechiffrer_ecb(texte_chiffre, cle):
    if len(texte_chiffre) % TAILLE_BLOC != 0:
        raise ValueError("le texte chiffré doit être un multiple de 16 octets")
    round_keys = expand_key(cle)
    blocs = [texte_chiffre[i:i + TAILLE_BLOC] for i in range(0, len(texte_chiffre), TAILLE_BLOC)]
    return unpad(b"".join(aes_decrypt_block(b, round_keys) for b in blocs))


# ============================================================
# 6. Test de l'AES (vecteur officiel FIPS-197)
# ============================================================

k = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
p = bytes.fromhex("00112233445566778899aabbccddeeff")
c = aes_encrypt_block(p, expand_key(k))
assert c.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
assert aes_decrypt_block(c, expand_key(k)) == p
print("Test AES (FIPS-197) : OK\n")


# ============================================================
# 7. Démo 1 : M1 = M2  =>  C1 = C2
# ==========================                                                                                                                                                                                                                                                                          ==================================

cle = os.urandom(16)
message = b"A" * 32

ciphertext = chiffrer_ecb(message, cle)
c1, c2 = ciphertext[:16], ciphertext[16:32]

print("C1 :", c1.hex())
print("C2 :", c2.hex())
print("C1 == C2 :", c1 == c2)
assert c1 == c2


# ============================================================
# 8. Démo 2 : A || B || A || A  devient  X || Y || X || X
# ============================================================

message2 = b"A" * 16 + b"B" * 16 + b"A" * 16 + b"A" * 16
chiffre2 = chiffrer_ecb(message2, cle)

blocs = [chiffre2[i:i + 16] for i in range(0, 64, 16)]
lettres = {}
motif = "".join(lettres.setdefault(b, chr(ord("X") + len(lettres))) for b in blocs)

print("\nClair  : A B A A")
print("Chiffré :", " ".join(motif))
assert motif == "XYXX"


# ============================================================
# 9. Démo 3 : aller-retour, puis image à zones uniformes
# ============================================================

message3 = b"Bonjour, ceci est un texte plus long que seize octets !"
assert dechiffrer_ecb(chiffrer_ecb(message3, cle), cle) == message3
print("\nAller-retour : OK")

LARGEUR, HAUTEUR = 64, 32
image = bytearray(LARGEUR * HAUTEUR)
for y in range(HAUTEUR):
    for x in range(LARGEUR):
        if x < 21:
            image[y * LARGEUR + x] = 0x00
        elif x < 42:
            image[y * LARGEUR + x] = 0xFF
        else:
            dx, dy = x - 52, y - HAUTEUR // 2
            image[y * LARGEUR + x] = 0xFF if dx * dx + dy * dy < 60 else 0x00
image = bytes(image)

# On enlève le bloc de padding final pour ne comparer que l'image
image_chiffree = chiffrer_ecb(image, cle)[:len(image)]

blocs_clairs = {image[i:i + 16] for i in range(0, len(image), 16)}
blocs_chiffres = {image_chiffree[i:i + 16] for i in range(0, len(image), 16)}
print("Blocs distincts en clair   :", len(blocs_clairs))
print("Blocs distincts en chiffré :", len(blocs_chiffres))
assert len(blocs_clairs) == len(blocs_chiffres)

RAMPE = " .:-=+*#%@"


def rendre_ascii(data):
    for y in range(0, len(data), LARGEUR):
        ligne = data[y:y + LARGEUR]
        print("   " + "".join(RAMPE[b * len(RAMPE) // 256] for b in ligne))


print("\nImage claire :")
rendre_ascii(image)
print("\nImage chiffrée en ECB (les zones restent reconnaissables) :")
rendre_ascii(image_chiffree)