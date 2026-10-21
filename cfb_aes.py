"""Mode CFB-128 (Cipher Feedback, segments de 128 bits) autour d'AES-128.

On n'utilise QUE la fonction encrypt() de aes128.py (chiffrement d'un bloc de
16 octets) : ni AES_decrypt, ni padding.

Formule de base, pour le bloc i :
    C_i = P_i XOR E_K(C_{i-1})        avec C_0 = IV   (chiffrement)
    P_i = C_i XOR E_K(C_{i-1})        avec C_0 = IV   (déchiffrement)

Le "registre" est la valeur C_{i-1} alimentant E_K. Il vaut IV au début,
puis le bloc chiffré précédent.
"""

import os

from aes128 import encrypt  # encrypt(plaintext, key) -> (ciphertext, trace)

TAILLE_BLOC = 16  # CFB-128 : segments de 128 bits = 16 octets


# ============================================================
# 1. Utilitaire
# ============================================================

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR octet à octet de deux séquences de même longueur."""
    assert len(a) == len(b), "xor_bytes : longueurs différentes"
    return bytes(x ^ y for x, y in zip(a, b))


# ============================================================
# 2. Affichage pédagogique (registre / keystream / clair / chiffré)
# ============================================================

def _afficher(numero, sens, registre, keystream, entree, sortie):
    """Affiche une étape : registre, keystream, entrée (P ou C) et sortie."""
    if sens == "chiffrement":
        gauche, droite = "P_i", "C_i"
    else:
        gauche, droite = "C_i", "P_i"
    print(f"  [{sens} | bloc {numero}]")
    print(f"    registre  C_(i-1) = {registre.hex()}")
    print(f"    keystream E_K(R)  = {keystream.hex()}")
    print(f"    {gauche:<9}       = {entree.hex()}")
    print(f"    {droite:<9}       = {sortie.hex()}")


# ============================================================
# 3. Chiffrement CFB-128
# ============================================================

def cfb_encrypt(plaintext: bytes, key: bytes, iv: bytes, afficher: bool = False) -> bytes:
    """Chiffre un message (16 octets, ou dernier bloc plus court) en mode CFB-128."""
    assert len(key) == 16, "la clé doit faire exactement 16 octets"
    assert len(iv) == 16, "l'IV doit faire exactement 16 octets"

    registre = iv                      # C_0 = IV
    chiffre = b""

    # Découpage en blocs de 16 octets ; le dernier peut être plus court.
    for i in range(0, len(plaintext), TAILLE_BLOC):
        p_i = plaintext[i:i + TAILLE_BLOC]           # P_i

        # keystream = E_K(registre)  — on ignore la trace renvoyée par encrypt()
        keystream, _ = encrypt(registre, key)
        keystream = keystream[:len(p_i)]             # XOR seulement sur les octets dispo

        c_i = xor_bytes(p_i, keystream)              # C_i = P_i XOR E_K(C_{i-1})
        if afficher:
            _afficher(i // TAILLE_BLOC + 1, "chiffrement", registre, keystream, p_i, c_i)

        registre = c_i                               # le registre devient C_i
        chiffre += c_i

    return chiffre


# ============================================================
# 4. Déchiffrement CFB-128
# ============================================================

def cfb_decrypt(ciphertext: bytes, key: bytes, iv: bytes, afficher: bool = False) -> bytes:
    """Déchiffre un message en mode CFB-128 — uniquement avec AES_encrypt !"""
    assert len(key) == 16, "la clé doit faire exactement 16 octets"
    assert len(iv) == 16, "l'IV doit faire exactement 16 octets"

    registre = iv                      # C_0 = IV
    clair = b""

    for i in range(0, len(ciphertext), TAILLE_BLOC):
        c_i = ciphertext[i:i + TAILLE_BLOC]         # C_i reçu

        # Le registre est toujours un bloc complet ici (un bloc partiel ne peut
        # être suivi d'aucun autre bloc : il est toujours le dernier).
        keystream, _ = encrypt(registre, key)       # E_K(C_{i-1}), et NON un déchiffrement AES
        keystream = keystream[:len(c_i)]

        p_i = xor_bytes(c_i, keystream)             # P_i = C_i XOR E_K(C_{i-1})
        if afficher:
            _afficher(i // TAILLE_BLOC + 1, "déchiffrement", registre, keystream, c_i, p_i)

        registre = c_i                              # le registre devient le chiffré REÇU
        clair += p_i

    return clair



if __name__ == "__main__":

    # --- Test 1 : déchiffrer(chiffrer(m)) == m ---------------------------
    print("=== Test 1 : aller-retour ===")
    for taille in (16, 32, 40):                     # tailles demandées
        m = os.urandom(taille)
        k = os.urandom(16)
        v = os.urandom(16)
        c = cfb_encrypt(m, k, v)
        assert cfb_decrypt(c, k, v) == m, f"échec pour {taille} octets"
        print(f"  {taille:>3} octets : clair == déchiffrer(chiffrer(clair))  OK")

    # quelques tailles non multiples de 16 (dernier bloc partiel)
    for taille in (1, 7, 25, 33):
        m = os.urandom(taille)
        k = os.urandom(16)
        v = os.urandom(16)
        assert cfb_decrypt(cfb_encrypt(m, k, v), k, v) == m
        print(f"  {taille:>3} octets : dernier bloc partiel            OK")

    # --- Test 2 : vecteur NIST SP 800-38A (CFB128-AES128) ---------------
    print("\n=== Test 2 : vecteur NIST SP 800-38A, CFB128-AES128 ===")
    cle = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    clair_bloc1 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    attendu_bloc1 = bytes.fromhex("3b3fd92eb72dad20333449f8e83cfb4a")

    chiffre = cfb_encrypt(clair_bloc1, cle, iv, afficher=True)
    print(f"  chiffré attendu = {attendu_bloc1.hex()}")
    print(f"  chiffré obtenu  = {chiffre.hex()}")
    assert chiffre == attendu_bloc1, "le vecteur NIST n'est pas respecté"
    print("  bloc 1 conforme au vecteur NIST  OK")

    # même vecteur mais avec 4 blocs (64 octets) : aller-retour + bloc 1
    message_nist = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    )
    c_nist = cfb_encrypt(message_nist, cle, iv)
    assert c_nist[:16] == attendu_bloc1
    assert cfb_decrypt(c_nist, cle, iv) == message_nist
    print("  4 blocs : aller-retour + premier bloc  OK")

    # --- Démonstration : affichage bloc par bloc -------------------------
    print("\n=== Démonstration : affichage de chaque bloc ===")
    demo_cle = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    demo_iv = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
    demo_clair = b"AAAA" * 10  # 40 octets : 2 blocs complets + 1 bloc partiel de 8 octets

    demo_chiffre = cfb_encrypt(demo_clair, demo_cle, demo_iv, afficher=True)
    print(f"\n  message chiffré ({len(demo_chiffre)} octets) = {demo_chiffre.hex()}")
    assert cfb_decrypt(demo_chiffre, demo_cle, demo_iv) == demo_clair
    print("  retour à l'identique : OK")

    print("\nTous les tests sont passés.")
