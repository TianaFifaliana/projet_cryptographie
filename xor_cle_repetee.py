# ============================================================
# Exercice 3 : chiffrement XOR avec une clé répétée
#   Ci = Pi XOR Ki mod m      (m = longueur de la clé)
# ============================================================


def xor_cle_repetee(data, cle):
    """Chiffre (ou déchiffre) data avec cle répétée : C = P ^ K, (P ^ K) ^ K = P."""
    if not cle:
        raise ValueError("La clé ne doit pas être vide")
    m = len(cle)
    return bytes(octet ^ cle[i % m] for i, octet in enumerate(data))


# ============================================================
# Programme de démonstration
# ============================================================

message = b"Cryptographie et securite informatique"
cle = b"L3INFO"

print("Message original  :", message)
print("Longueur message  :", len(message), "octets")
print("Clé               :", cle)
print("Longueur clé (m)  :", len(cle), "octets")
print("Clé répétée       :", (cle * (len(message) // len(cle) + 1))[: len(message)])
print()

# 1. Chiffrement
chiffre = xor_cle_repetee(message, cle)

# 2. Affichage des octets chiffrés
print("Octets chiffrés   :", list(chiffre))
print("Octets chiffrés   :", chiffre)
print()

# 3. Déchiffrement (même fonction)
dechiffre = xor_cle_repetee(chiffre, cle)

# 4. Vérification
assert dechiffre == message, "Erreur : le message déchiffré diffère de l'original !"
print("Octets déchiffrés :", dechiffre)
print("Message retrouvé  :", dechiffre.decode())
print("Vérification      : OK\n")


# ============================================================
# Contrainte : refus d'une clé vide
# ============================================================

print("=== Clé vide refusée ===")

for mauvaise_cle in (b"", bytearray()):
    try:
        xor_cle_repetee(message, bytes(mauvaise_cle))
    except ValueError as e:
        print("clé", repr(bytes(mauvaise_cle)), "-> refusée :", e)

# Deuxième tour de la clé : le même index i % m revient après m octets
assert xor_cle_repetee(b"ABCDEFG", b"XY") == bytes(
    a ^ k for a, k in zip(b"ABCDEFG", b"XYXYXYX")
)
print("\nRépétition correcte sur 7 octets avec une clé de 2 : OK")
# ny i%m avec i= position message, m=longueur cle