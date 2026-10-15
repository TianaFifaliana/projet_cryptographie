def chiffrer_xor(data, cle):
    """Chiffre une suite d'octets en appliquant XOR avec la clé (0 à 255)."""
    if not 0 <= cle <= 255:
        raise ValueError("La clé doit être comprise entre 0 et 255")
    return bytes(octet ^ cle for octet in data)


def dechiffrer_xor(data, cle):
    """Le déchiffrement est identique au chiffrement : (P ^ K) ^ K = P."""
    return chiffrer_xor(data, cle)


# Test
message = b"Bonjour L3!"
cle = 73

chiffre = chiffrer_xor(message, cle)
dechiffre = dechiffrer_xor(chiffre, cle)

print("Octets originaux  :", message)
print("Octets chiffrés   :", chiffre)
print("Octets déchiffrés :", dechiffre)
print("Message retrouvé  :", dechiffre.decode())

