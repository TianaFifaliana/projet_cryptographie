# ============================================================
# Chiffrement de César généralisé sur 256 valeurs (Z256)
# ============================================================

# ---------- Fonctions de base ----------

def chiffrer(data, cle):
    """Chiffre un objet bytes : C = (P + K) mod 256."""
    return bytes((octet + cle) % 256 for octet in data)


def dechiffrer(data, cle):
    """Déchiffre un objet bytes : P = (C - K) mod 256."""
    return bytes((octet - cle) % 256 for octet in data)


# ---------- Partie 6 : attaque par force brute ----------

def attaque_force_brute(data_chiffree):
    """Teste les clés de 0 à 255 et affiche les 20 premiers octets déchiffrés."""
    for cle in range(256):
        essai = dechiffrer(data_chiffree[:20], cle)  # seulement 20 octets : plus rapide
        print("Cle", cle, ":", list(essai))


# ============================================================
# PARTIE 1 : message texte
# ============================================================

print("=== PARTIE 1 : message texte ===")

message = b"Bonjour L3!"
cle = 73

print("Message original :", message)
print("Octets originaux :", list(message))
print("Cle :", cle)

chiffre = chiffrer(message, cle)
print("Octets chiffres :", list(chiffre))

dechiffre = dechiffrer(chiffre, cle)
print("Octets dechiffres :", list(dechiffre))
print("Message retrouve :", dechiffre)

assert dechiffre == message, "Erreur : le message déchiffré diffère de l'original !"
print("Verification : OK\n")


# ============================================================
# PARTIE 3 : fichier binaire
# ============================================================

print("=== PARTIE 3 : fichier binaire ===")

nom_fichier = "diagramme textile.jpeg"   # à remplacer par ton fichier (pdf, zip, ...)
cle = 73

# 1. Lecture en mode binaire
with open(nom_fichier, "rb") as f:
    original = f.read()

print("Taille du fichier original :", len(original), "octets")

# 2. Chiffrement puis enregistrement
chiffre_fichier = chiffrer(original, cle)
with open("fichier_chiffre.bin", "wb") as f:
    f.write(chiffre_fichier)

# 3. Relecture et déchiffrement
with open("fichier_chiffre.bin", "rb") as f:
    donnees_chiffrees = f.read()

dechiffre_fichier = dechiffrer(donnees_chiffrees, cle)

# 4. Vérification
if original == dechiffre_fichier:
    print("Fichier correctement restaure.\n")
else:
    print("Erreur : le fichier restaure est different de l'original.\n")


# ============================================================
# PARTIE 6 : attaque par force brute
# ============================================================

print("=== PARTIE 6 : attaque par force brute sur le fichier chiffré ===")
attaque_force_brute(donnees_chiffrees)