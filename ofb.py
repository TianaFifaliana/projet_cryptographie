"""Mode OFB-128 (Output Feedback, segments de 128 bits) autour d'AES-128.

On n'utilise QUE la fonction encrypt() de aes128.py (chiffrement d'un bloc de
16 octets) : ni déchiffrement AES, ni padding.

Keystream : O_0 = IV, et O_i = E_K(O_{i-1}) pour i >= 1.
Formule de base, pour le bloc i :
    C_i = P_i XOR O_i        (chiffrement)
    P_i = C_i XOR O_i        (déchiffrement : c'est la MÊME opération !)

Le "registre" est la valeur O_{i-1} alimentant E_K. Il vaut IV au début, puis
la SORTIE d'AES (O_i) du bloc précédent — et NON le chiffré C_i. C'est la
différence essentielle avec le mode CFB.
"""

import os

from aes128 import encrypt  # encrypt(plaintext, key) -> (ciphertext, trace)

TAILLE_BLOC = 16  # OFB-128 : segments de 128 bits = 16 octets


# ============================================================
# 1. Utilitaire
# ============================================================

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR octet à octet de deux séquences de même longueur."""
    assert len(a) == len(b), "xor_bytes : longueurs différentes"
    return bytes(x ^ y for x, y in zip(a, b))


# ============================================================
# 2. Génération du keystream (indépendant du message)
# ============================================================

def ofb_keystream(key: bytes, iv: bytes, longueur: int) -> bytes:
    """Génère un keystream de `longueur` octets.

    O_0 = IV, puis O_i = E_K(O_{i-1}) : on concatène les blocs O_i (16 octets)
    et on tronque à `longueur`. Résultat indépendant du message chiffré.
    """
    assert len(key) == 16, "la clé doit faire exactement 16 octets"
    assert len(iv) == 16, "l'IV doit faire exactement 16 octets"

    registre = iv                     # O_0 = IV
    flux = b""

    while len(flux) < longueur:
        o_i, _ = encrypt(registre, key)   # O_i = E_K(O_{i-1})
        flux += o_i
        registre = o_i                    # le registre devient la SORTIE d'AES (O_i)

    return flux[:longueur]


# ============================================================
# 3. Affichage pédagogique (registre / keystream / clair / chiffré)
# ============================================================

def _afficher(numero, sens, registre, keystream, entree, sortie):
    """Affiche une étape : registre O_(i-1), keystream O_i, entrée et sortie."""
    if sens == "chiffrement":
        gauche, droite = "P_i", "C_i"
    else:
        gauche, droite = "C_i", "P_i"
    print(f"  [{sens} | bloc {numero}]")
    print(f"    registre  O_(i-1) = {registre.hex()}")
    print(f"    keystream E_K(O)  = {keystream.hex()}")
    print(f"    {gauche:<9}       = {entree.hex()}")
    print(f"    {droite:<9}       = {sortie.hex()}")


# ============================================================
# 4. Chiffrement OFB-128
# ============================================================

def ofb_encrypt(plaintext: bytes, key: bytes, iv: bytes, afficher: bool = False) -> bytes:
    """Chiffre un message de longueur quelconque en mode OFB-128 (sans padding).

    C_i = P_i XOR O_i, où O_i est la sortie d'AES (O_0 = IV, O_i = E_K(O_{i-1})).
    """
    assert len(key) == 16, "la clé doit faire exactement 16 octets"
    assert len(iv) == 16, "l'IV doit faire exactement 16 octets"

    registre = iv                     # O_0 = IV
    chiffre = b""

    # Découpage en blocs de 16 octets ; le dernier peut être plus court.
    for i in range(0, len(plaintext), TAILLE_BLOC):
        p_i = plaintext[i:i + TAILLE_BLOC]           # P_i

        o_i, _ = encrypt(registre, key)              # O_i = E_K(O_{i-1})
        keystream = o_i[:len(p_i)]                   # tronqué au dernier bloc partiel

        c_i = xor_bytes(p_i, keystream)              # C_i = P_i XOR O_i
        if afficher:
            _afficher(i // TAILLE_BLOC + 1, "chiffrement", registre, keystream, p_i, c_i)

        registre = o_i                               # registre = SORTIE d'AES (O_i), pas C_i
        chiffre += c_i

    return chiffre


# ============================================================
# 5. Déchiffrement OFB-128
# ============================================================

def ofb_decrypt(ciphertext: bytes, key: bytes, iv: bytes, afficher: bool = False) -> bytes:
    """Déchiffre un message en mode OFB-128.

    Le XOR est symétrique : le déchiffrement consiste à régénérer le MÊME
    keystream O_i à partir de (clé, IV) et à refaire le même XOR
    (P_i = C_i XOR O_i). Chiffrer et déchiffrer sont donc exactement la
    même opération, d'où l'appel direct à ofb_encrypt.
    """
    return ofb_encrypt(ciphertext, key, iv, afficher)


if __name__ == "__main__":

    # --- Test 1 : aller-retour -------------------------------------------
    print("=== Test 1 : aller-retour ===")
    for taille in (1, 7, 16, 25, 32, 40):            # tailles demandées
        m = os.urandom(taille)
        k = os.urandom(16)
        v = os.urandom(16)
        c = ofb_encrypt(m, k, v)
        assert ofb_decrypt(c, k, v) == m, f"échec pour {taille} octets"
        print(f"  {taille:>3} octets : clair == déchiffrer(chiffrer(clair))  OK")

    # --- Test 2 : vecteur NIST SP 800-38A (OFB-AES128) -------------------
    print("\n=== Test 2 : vecteur NIST SP 800-38A, OFB-AES128 ===")
    cle = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    message_nist = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    )
    attendu = bytes.fromhex(
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "7789508d16918f03f53c52dac54ed825"
        "9740051e9c5fecf64344f7a82260edcc"
        "304c6528f659c77866a510d9c1d6ae5e"
    )

    chiffre = ofb_encrypt(message_nist, cle, iv, afficher=True)
    print(f"  chiffré attendu = {attendu.hex()}")
    print(f"  chiffré obtenu  = {chiffre.hex()}")
    assert chiffre == attendu, "le vecteur NIST n'est pas respecté"
    assert ofb_decrypt(chiffre, cle, iv) == message_nist
    print("  chiffré conforme au vecteur NIST + aller-retour  OK")

    # --- Test 3 : le keystream est indépendant du message -----------------
    print("\n=== Test 3 : le keystream ne dépend pas du message ===")
    k = os.urandom(16)
    v = os.urandom(16)
    m1 = os.urandom(40)
    m2 = os.urandom(40)

    c1 = ofb_encrypt(m1, k, v)
    c2 = ofb_encrypt(m2, k, v)
    ks_1 = ofb_keystream(k, v, 40)
    ks_2 = ofb_keystream(k, v, 40)

    print(f"  keystream pour m1 (40 octets) = {ks_1.hex()}")
    print(f"  keystream pour m2 (40 octets) = {ks_2.hex()}")
    assert ks_1 == ks_2, "le keystream ne doit dépendre que de (clé, IV)"
    assert c1 == xor_bytes(m1, ks_1), "C1 != P1 XOR keystream"
    assert c2 == xor_bytes(m2, ks_1), "C2 != P2 XOR keystream"
    print("  même clé + même IV => même keystream O_i (indépendant du message)  OK")

    # --- Test 4 : malléabilité (un bit inversé dans C_2) ------------------
    print("\n=== Test 4 : malléabilité, 1 bit inversé dans C_2 ===")
    m = b"0123456789abcdef" * 3              # 48 octets : 3 blocs complets
    c = bytearray(ofb_encrypt(m, k, v))
    c[16 + 6] ^= 0x20                        # inverse un bit du 2e bloc chiffré (octet 22)
    m_mod = ofb_decrypt(bytes(c), k, v)

    diff_b1 = xor_bytes(m[:16], m_mod[:16])   # bloc 1 : doit rester intact
    diff_b2 = xor_bytes(m[16:32], m_mod[16:32])  # bloc 2 : doit ne changer que d'1 bit
    diff_b3 = xor_bytes(m[32:48], m_mod[32:48])  # bloc 3 : doit rester intact

    print(f"  bit modifié dans C_2 : octet 22 (16+6), masque 0x20")
    print(f"  diff bloc 1 = {diff_b1.hex()}   (aucun octet modifié)")
    print(f"  diff bloc 2 = {diff_b2.hex()}   (1 seul octet, 1 seul bit)")
    print(f"  diff bloc 3 = {diff_b3.hex()}   (aucun octet modifié)")
    assert diff_b1 == b"\x00" * 16
    assert diff_b3 == b"\x00" * 16
    assert sum(b != 0 for b in diff_b2) == 1  # un seul octet touché
    assert diff_b2[6] == 0x20                 # et un seul bit
    print("  SEUL le bit correspondant de P_2 a changé : OK")

    # --- Test 5 : danger de la réutilisation de l'IV ----------------------
    print("\n=== Test 5 : réutilisation de (clé, IV) => C XOR C' == P XOR P' ===")
    m1 = b"Premier message secret numero 1"
    m2 = b"Second  message secret numero 2"
    assert len(m1) == len(m2), "il faut deux messages de même longueur"

    c1 = ofb_encrypt(m1, k, v)               # même clé k, même IV v !
    c2 = ofb_encrypt(m2, k, v)

    xor_cc = xor_bytes(c1, c2)
    xor_pp = xor_bytes(m1, m2)
    print(f"  P1 XOR P2 = {xor_pp.hex()}")
    print(f"  C1 XOR C2 = {xor_cc.hex()}")
    assert xor_cc == xor_pp, "C1 XOR C2 doit être égal à P1 XOR P2"
    print("  C1 XOR C2 == P1 XOR P2 : OK (le keystream s'annule, le secret fuit)")

    # --- Explication finale ----------------------------------------------
    print("""
=== Pourquoi OFB n'a besoin ni de padding ni du déchiffrement AES ===

Le padding sert à compléter le DERNIER bloc entier (ECB, CBC...) pour qu'il
tienne dans l'opération de bloc. En OFB, on ne chiffre jamais le clair : on
génère un keystream indépendant du message et on fait C_i = P_i XOR O_i. Le
dernier bloc peut donc être plus court : on tronque simplement O_i et on ne
XOR que les octets disponibles. Il n'y a aucune contrainte sur la longueur du
message, donc aucun padding nécessaire. Comme E_K n'est appliqué qu'au
registre (et jamais au clair ou au chiffré), il n'y a jamais à inverser AES :
le déchiffrement n'utilise que E_K.

--- Pourquoi chiffrement et déchiffrement sont la même opération ---

Par symétrie du XOR : on a C_i = P_i XOR O_i, donc P_i = C_i XOR O_i. Les deux
utilisent exactement le même keystream O_i (déterminé par (clé, IV) uniquement).
Chiffrer un message P avec ofb_encrypt et le "déchiffrer" avec ofb_encrypt
donnent le même résultat ; de même, ofb_decrypt n'est qu'un alias d'ofb_encrypt.

--- Pourquoi réutiliser (clé, IV) est catastrophique ---

Si deux messages sont chiffrés avec la même clé et le même IV, ils partagent
le même keystream O_i. Alors C = P XOR O et C' = P' XOR O, d'où
    C XOR C' = (P XOR O) XOR (P' XOR O) = P XOR P'
Le keystream s'élimine : un attaquant possédant les deux chiffrés obtient le
XOR des deux clairs. Si l'un des clairs (ou une partie) est connu ou deviné
(entête de fichier, langue connue), l'autre est immédiatement reconstituable.
C'est la faille classique du "two-time pad".

--- Que devient le chiffré si un bit est inversé (propagation d'erreur) ---

P_i = C_i XOR O_i ne dépend d'AUCUN autre bloc : un bit inversé dans C_i ne
modifie QUE le bit correspondant de P_i. Aucune propagation d'erreur : les
blocs voisins restent parfaitement intacts. C'est un avantage pour les canaux
bruyants mais une faiblesse majeure pour l'intégrité : OFB (comme CFB/CTR)
est malléable — un attaquant peut retourner des bits du clair à volonté en
modifiant le même nombre de bits du chiffré, sans jamais être détecté.
""")

    print("\nTous les tests sont passés.")