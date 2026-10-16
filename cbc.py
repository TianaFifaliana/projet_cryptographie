"""Mode CBC (Cipher Block Chaining) autour d'AES-128, avec padding PKCS#7.

Contrairement à CFB, CBC utilise bien le déchiffrement AES (decrypt) pour déchiffrer.

Formule de base, pour le bloc i :
    C_i = E_K(P_i XOR C_{i-1})        avec C_0 = IV   (chiffrement)
    P_i = D_K(C_i) XOR C_{i-1}        avec C_0 = IV   (déchiffrement)

Le "registre" est le bloc chiffré précédent C_{i-1}. Il vaut IV au début,
puis le bloc chiffré précédent.
"""

import os

from aes128 import (
    SBOX,
    gmul,
    bytes_to_state,
    state_to_bytes,
    key_expansion,
    add_round_key,
    encrypt,  # encrypt(plaintext, key) -> (ciphertext, trace)
)

TAILLE_BLOC = 16  # CBC : blocs de 128 bits = 16 octets


# ============================================================
# 1. Utilitaire
# ============================================================

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR octet à octet de deux séquences de même longueur."""
    assert len(a) == len(b), "xor_bytes : longueurs différentes"
    return bytes(x ^ y for x, y in zip(a, b))


# ============================================================
# 2. Déchiffrement AES d'un bloc (inverse exact des rondes d'encrypt)
# ============================================================

# INV_SBOX est la permutation inverse de SBOX : si SBOX[i] = j, alors INV_SBOX[j] = i.
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i


def inv_sub_bytes(state):
    """Inverse de SubBytes : chaque octet est remplacé par son image inverse."""
    return [[INV_SBOX[state[row][col]] for col in range(4)] for row in range(4)]


def inv_shift_rows(state):
    """Inverse de ShiftRows : decale la ligne r de r cases vers la droite (circulaire)."""
    return [state[row][-row:] + state[row][:-row] for row in range(4)]


def inv_mix_columns(state):
    """Inverse de MixColumns : multiplication par la matrice 0e 0b 0d 09 dans GF(2^8)."""
    result = [[0] * 4 for _ in range(4)]
    for col in range(4):
        s = [state[row][col] for row in range(4)]
        result[0][col] = gmul(s[0], 0x0e) ^ gmul(s[1], 0x0b) ^ gmul(s[2], 0x0d) ^ gmul(s[3], 0x09)
        result[1][col] = gmul(s[0], 0x09) ^ gmul(s[1], 0x0e) ^ gmul(s[2], 0x0b) ^ gmul(s[3], 0x0d)
        result[2][col] = gmul(s[0], 0x0d) ^ gmul(s[1], 0x09) ^ gmul(s[2], 0x0e) ^ gmul(s[3], 0x0b)
        result[3][col] = gmul(s[0], 0x0b) ^ gmul(s[1], 0x0d) ^ gmul(s[2], 0x09) ^ gmul(s[3], 0x0e)
    return result


def decrypt(ciphertext, key):
    """Déchiffre un bloc de 16 octets. Retourne (plaintext, trace des states par ronde).

    Schéma : AddRoundKey(K10), puis rondes 9 à 1 (InvShiftRows, InvSubBytes,
    AddRoundKey(Kr), InvMixColumns), puis InvShiftRows, InvSubBytes, AddRoundKey(K0).
    """
    round_keys = key_expansion(key)
    state = bytes_to_state(ciphertext)
    trace = [state]

    state = add_round_key(state, round_keys[10])       # AddRoundKey initial avec K10
    trace.append(state)

    for r in range(9, 0, -1):                          # Rondes 9 a 1
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[r])
        state = inv_mix_columns(state)
        trace.append(state)

    state = inv_shift_rows(state)                      # Ronde 0 (finale)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    trace.append(state)

    return state_to_bytes(state), trace


# ============================================================
# 3. Padding PKCS#7
# ============================================================

def pad(data: bytes) -> bytes:
    """Ajoute n octets de valeur n (1 <= n <= 16) pour compléter à 16 octets.

    Si la taille est déjà un multiple de 16, on ajoute un bloc entier de 0x10.
    """
    n = TAILLE_BLOC - len(data) % TAILLE_BLOC
    return data + bytes([n]) * n


def unpad(data: bytes) -> bytes:
    """Retire le padding PKCS#7. Lève ValueError si le padding est invalide."""
    if not data:
        raise ValueError("padding invalide : données vides")
    n = data[-1]
    if n < 1 or n > TAILLE_BLOC or data[-n:] != bytes([n]) * n:
        raise ValueError("padding invalide")
    return data[:-n]


# ============================================================
# 4. Affichage pédagogique (registre / entrée AES / résultat)
# ============================================================

def _afficher(numero, sens, registre, entree_aes, resultat):
    """Affiche une étape : registre, entrée AES et résultat (C_i ou P_i)."""
    if sens == "chiffrement":
        gauche, droite = "P_i XOR R", "C_i"
    else:
        gauche, droite = "D_K(C_i)", "P_i"
    print(f"  [{sens} | bloc {numero}]")
    print(f"    registre  C_(i-1) = {registre.hex()}")
    print(f"    {gauche:<14} = {entree_aes.hex()}")
    print(f"    {droite:<14} = {resultat.hex()}")


# ============================================================
# 5. Mode CBC
# ============================================================

def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes, afficher: bool = False) -> bytes:
    """Chiffre un message de longueur quelconque en mode CBC (padding PKCS#7)."""
    assert len(key) == 16, "la clé doit faire exactement 16 octets"
    assert len(iv) == 16, "l'IV doit faire exactement 16 octets"

    registre = iv                      # C_0 = IV
    chiffre = b""
    donnees = pad(plaintext)           # PKCS#7 : le message devient multiple de 16

    for i in range(0, len(donnees), TAILLE_BLOC):
        p_i = donnees[i:i + TAILLE_BLOC]           # P_i (déjà paddé)

        entree_aes = xor_bytes(p_i, registre)      # P_i XOR C_{i-1}
        c_i, _ = encrypt(entree_aes, key)          # C_i = E_K(entrée AES)
        if afficher:
            _afficher(i // TAILLE_BLOC + 1, "chiffrement", registre, entree_aes, c_i)

        registre = c_i                             # C_i devient le prochain registre
        chiffre += c_i

    return chiffre


def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes, afficher: bool = False) -> bytes:
    """Déchiffre un message en mode CBC — utilise le déchiffrement AES (decrypt)."""
    assert len(key) == 16, "la clé doit faire exactement 16 octets"
    assert len(iv) == 16, "l'IV doit faire exactement 16 octets"
    assert len(ciphertext) % TAILLE_BLOC == 0, "le chiffré doit être un multiple de 16 octets"

    registre = iv                      # C_0 = IV
    donnees = b""

    for i in range(0, len(ciphertext), TAILLE_BLOC):
        c_i = ciphertext[i:i + TAILLE_BLOC]        # C_i reçu

        dechiffre, _ = decrypt(c_i, key)           # D_K(C_i)
        p_i = xor_bytes(dechiffre, registre)       # P_i = D_K(C_i) XOR C_{i-1}
        if afficher:
            _afficher(i // TAILLE_BLOC + 1, "déchiffrement", registre, dechiffre, p_i)

        registre = c_i                             # le registre devient le chiffré REÇU
        donnees += p_i

    return unpad(donnees)                          # retrait du padding PKCS#7


if __name__ == "__main__":

    # --- Vérification du déchiffrement AES (vecteur FIPS-197) ------------
    print("=== Vecteur FIPS-197 : encrypt puis decrypt ===")
    cle_fips = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    clair_fips = bytes.fromhex("00112233445566778899aabbccddeeff")
    chiffre_fips, _ = encrypt(clair_fips, cle_fips)
    assert chiffre_fips.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", "encrypt ne donne pas le vecteur FIPS"
    clair_retrouve, _ = decrypt(chiffre_fips, cle_fips)
    assert clair_retrouve == clair_fips, "decrypt(encrypt(m)) != m"
    print("  chiffré =", chiffre_fips.hex())
    print("  clair   =", clair_retrouve.hex())
    print("  decrypt(encrypt(m)) == m : OK")

    # --- Test 1 : aller-retour CBC pour plusieurs tailles ----------------
    print("\n=== Test 1 : aller-retour cbc_decrypt(cbc_encrypt(m)) == m ===")
    for taille in (0, 1, 15, 16, 17, 32, 40):
        m = os.urandom(taille)
        k = os.urandom(16)
        v = os.urandom(16)
        c = cbc_encrypt(m, k, v)
        assert cbc_decrypt(c, k, v) == m, f"échec pour {taille} octets"
        print(f"  {taille:>3} octets : clair == déchiffrer(chiffrer(clair))  OK")

    # --- Test 2 : vecteur NIST SP 800-38A (CBC-AES128) -------------------
    print("\n=== Test 2 : vecteur NIST SP 800-38A, CBC-AES128 (2 blocs) ===")
    cle = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    message_nist = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
    )
    attendu = bytes.fromhex(
        "7649abac8119b246cee98e9b12e9197d"
        "5086cb9b507219ee95db113a917678b2"
    )

    chiffre = cbc_encrypt(message_nist, cle, iv, afficher=True)
    print(f"  chiffré attendu (32 premiers octets) = {attendu.hex()}")
    print(f"  chiffré obtenu                      = {chiffre[:32].hex()}")
    assert chiffre[:32] == attendu, "le vecteur NIST n'est pas respecté"
    print("  2 premiers blocs conformes au vecteur NIST  OK")

    # aller-retour complet sur le message de 32 octets (le padding est ajouté puis retiré)
    assert cbc_decrypt(chiffre, cle, iv) == message_nist
    print("  aller-retour sur ces 2 blocs (avec padding)  OK")

    # --- Test 3 : même message, deux IV différents ------------------------
    print("\n=== Test 3 : même message avec deux IV différents ===")
    iv1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    iv2 = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
    m_demo = b"Bonjour le monde !" * 3
    c1 = cbc_encrypt(m_demo, cle, iv1)
    c2 = cbc_encrypt(m_demo, cle, iv2)
    print(f"  IV 1 : {iv1.hex()}")
    print(f"  IV 2 : {iv2.hex()}")
    print(f"  chiffré 1 : {c1.hex()}")
    print(f"  chiffré 2 : {c2.hex()}")
    assert c1 != c2, "deux IV différents devraient donner des chiffrés différents"
    assert cbc_decrypt(c1, cle, iv1) == m_demo
    assert cbc_decrypt(c2, cle, iv2) == m_demo
    print("  chiffrés différents, et tous deux déchiffrés correctement  OK")

    # --- Test 4 : deux blocs clairs identiques donnent des chiffrés différents ---
    print("\n=== Test 4 : CBC vs ECB sur deux blocs identiques ===")
    message_identique = b"A" * 32                     # deux blocs 'AAAA...' + bloc de padding
    c_cbc = cbc_encrypt(message_identique, cle, iv1)
    bloc_a, bloc_b = c_cbc[:16], c_cbc[16:32]
    print(f"  bloc clair 1 : {message_identique[:16].hex()}")
    print(f"  bloc clair 2 : {message_identique[16:32].hex()}")
    print(f"  chiffré C1 (CBC) = {bloc_a.hex()}")
    print(f"  chiffré C2 (CBC) = {bloc_b.hex()}")
    assert bloc_a != bloc_b, "en CBC, deux blocs identiques doivent donner des chiffrés différents"
    print("  en CBC, C1 != C2 (chaînage) : OK (en ECB ils seraient identiques)")

    # --- Explication finale ----------------------------------------------
    print("""
=== Pourquoi CBC exige le déchiffrement AES alors que CFB ne l'exige pas ===

CBC chiffre en chaînant les blocs CLAIRS : C_i = E_K(P_i XOR C_{i-1}). Pour
retrouver P_i il faut donc d'abord inverser E_K, puis annuler le XOR :
    P_i = D_K(C_i) XOR C_{i-1}
L'inversion de E_K est indispensable, car E_K n'est pas une simple addition
(SubBytes, ShiftRows, MixColumns, AddRoundKey ne commutent pas).

CFB, lui, n'envoie jamais le clair dans E_K : il chiffre uniquement le registre
et combine le résultat (keystream) au clair par XOR :
    C_i = P_i XOR E_K(C_{i-1})     et     P_i = C_i XOR E_K(C_{i-1})
Le déchiffrement utilise donc la MÊME opération E_K (grâce à la symétrie du
XOR) : il n'y a pas de D_K à implémenter.

--- Pourquoi l'IV doit être imprévisible ---

Dans CBC, C_1 = E_K(P_1 XOR IV). Si l'attaquant connaît l'IV et devine certains
P_1, il peut vérifier ses hypothèses en chiffrant lui-même (P_1 XOR IV) et en
comparant au C_1 observé : CBC devient vulnérable aux attaques à clair choisi.
Un IV imprévisible (aléatoire, jamais réutilisé) empêche de relier deux messages
chiffrés avec la même clé et neutralise les oracles de padding.

--- Un bit modifié dans C_i au déchiffrement ---

D_K est très sensible : un seul bit modifié dans C_i change ENTIÈREMENT le bloc
P_i déchiffré (effet avalanche d'AES). En revanche P_{i+1} = D_K(C_{i+1}) XOR C_i
n'est corrompu qu'au niveau du bit modifié de C_i (un XOR ne touche qu'un bit),
et les blocs suivants restent intacts. CBC ne fournit donc AUCUNE intégrité :
on ne peut détecter une corruption que si le padding devient invalide (et de
façon souvent exploitable par un oracle).
""")

    print("\nTous les tests sont passés.")