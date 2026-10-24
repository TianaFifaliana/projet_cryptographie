# ============================================================
# Exercice 5 : cryptanalyse d'un XOR avec cle d'un octet
#   Ci = Pi XOR K      avec  0 <= K <= 255
#   Dechiffrement identique : Pi = Ci XOR K
# ============================================================

DATA = [11, 38, 37, 35, 38, 32, 39, 123, 47, 38, 123, 56, 39, 34, 43, 47]

# Bornes ASCII demandees par l'enonce
ASCII_MIN = 32
ASCII_MAX = 126

# Lettres (alphabet latin, majuscules + minuscules)
LETTRES = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

# Mots frequents en francais et en anglais (comptes comme mots entiers)
MOTS_FREQUENTS = (
    "the", "and", "for", "you", "not", "with", "this", "that", "are", "was",
    "have", "from", "all", "can", "will", "one", "his", "her",
    "est", "les", "des", "une", "pour", "dans", "que", "qui", "sur", "pas",
    "avec", "plus", "nous", "vous", "cette", "sont", "elle", "aux", "par",
    "info", "donnees", "cle", "message", "texte", "texte", "chiffre",
    "informatique", "reseaux", "securite", "xors",
)

# Ponctuation acceptable dans un texte lisible
PONCTUATION_OK = set(" ,.;:!?-()'\"")

# Frequences des lettres en francais (indice de Shapiro) : un texte vrai
# se rapproche de ces proportions, du bruit ne se rapproche pas.
FREQ_LETTRES = {
    "e": 0.146, "a": 0.097, "i": 0.095, "s": 0.079, "n": 0.071, "r": 0.069,
    "t": 0.072, "o": 0.055, "l": 0.055, "u": 0.058, "d": 0.037, "c": 0.033,
    "m": 0.030, "p": 0.031, "g": 0.009, "b": 0.009, "v": 0.015, "h": 0.007,
    "f": 0.011, "y": 0.004, "x": 0.004, "j": 0.006, "k": 0.006, "q": 0.002,
    "w": 0.0001, "z": 0.0003,
}

VOYELLES = set("aeiouyAEIOUY")


def dechiffrer(data, k):
    """Retourne le clair pour la cle d'un octet k : Pi = Ci XOR K."""
    return [c ^ k for c in data]


def ratio_affichable(data):
    """Proportion de caracteres ASCII affichables (32 <= Pi <= 126)."""
    if not data:
        return 0.0
    nb = sum(1 for p in data if ASCII_MIN <= p <= ASCII_MAX)
    return nb / len(data)


def attaque_xor(data):
    """Teste les 256 cles possibles et renvoie la liste (k, clair) de chaque essai."""
    resultats = []
    for k in range(256):
        resultats.append((k, dechiffrer(data, k)))
    return resultats


def coupe_mots(texte):
    """Decoupe un texte en suite de mots (lettres seulement)."""
    mot = ""
    mots = []
    for ch in texte:
        if ch in LETTRES:
            mot += ch
        else:
            if mot:
                mots.append(mot)
                mot = ""
    if mot:
        mots.append(mot)
    return mots


def ecart_frequences(mots):
    """Distance entre la repartition des lettres du texte et le francais courant."""
    if not mots:
        return 1.0
    lettres = "".join(mots).lower()
    ecart = 0.0
    for l, f in FREQ_LETTRES.items():
        observe = lettres.count(l) / len(lettres)
        ecart += abs(observe - f)
    return ecart


def score_texte(data):
    """Attribue un score a chaque cle : plus le score est haut, plus le texte est credible.

    Criteres de l'enonce :
      - nombre de caracteres ASCII imprimables (32 <= Pi <= 126) ;
      - nombre d'espaces ;
      - nombre de lettres ;
      - presence de mots frequents.
    Deux criteres complementaires (ponctuation et frequence des voyelles)
    servent a eliminer les faux positifs.
    """
    scores = []
    for k in range(256):
        clair = dechiffrer(data, k)
        n = len(clair)
        if n == 0:
            scores.append((0.0, k, clair))
            continue

        n_affichables = sum(1 for p in clair if ASCII_MIN <= p <= ASCII_MAX)
        n_espaces = clair.count(32)
        n_lettres = sum(1 for p in clair if chr(p) in LETTRES)
        n_voyelles = sum(1 for p in clair if chr(p) in VOYELLES)

        texte = "".join(chr(p) for p in clair)
        mots = coupe_mots(texte.lower())
        n_mots_frequents = sum(1 for m in mots if m in MOTS_FREQUENTS)

        # Ponctuation : on accepte la ponctuation courante, on penalise le reste
        n_bonnes_ponct = sum(1 for p in clair if chr(p) in PONCTUATION_OK)

        score = (
            3.0 * n_affichables / n              # ASCII imprimable
            + 4.0 * n_espaces / n                # espaces
            + 2.0 * n_lettres / n                # lettres
            + 12.0 * n_mots_frequents            # mots frequents (mots entiers)
            + 1.0 * n_bonnes_ponct / n           # ponctuation plausible
            + 3.0 * n_voyelles / n_lettres if n_lettres else 0.0
            - 2.0 * ecart_frequences(mots)       # lettres peu credibles
        )
        scores.append((score, k, clair))

    scores.sort(reverse=True)
    return scores


# ============================================================
# 1. Attaque brute force : les 256 cles
# ============================================================

print("=== Exercice 5 : cryptanalyse d'un XOR avec cle d'un octet ===\n")
print("Donnees chiffrees :", DATA)
print("Nombre d'octets   :", len(DATA))
print()

print("--- 1. Les 256 cles possibles : Pi = Ci XOR K ---")
resultats = attaque_xor(DATA)
for k, clair in resultats:
    affiche = "".join(chr(p) if ASCII_MIN <= p <= ASCII_MAX else "." for p in clair)
    print(f"Cle {k:3d} : {affiche}")
print()

# ============================================================
# 2. Version amelioree : uniquement les cles majoritairement affichables
# ============================================================

print("--- 2. Cles majoritairement en ASCII affichable ---")
seuil = 0.95
meilleures = [(k, clair) for k, clair in resultats if ratio_affichable(clair) >= seuil]
for k, clair in meilleures:
    affiche = "".join(chr(p) for p in clair)
    print(f"Cle {k:3d} ({k:3d} = 0x{k:02X}, {chr(k)!r}) : {affiche}   "
          f"[{ratio_affichable(clair) * 100:.0f} % affichable]")
print(f"\n{len(meilleures)} cle(s) sur 256 passent le seuil de {seuil * 100:.0f} %.")
print()

# ============================================================
# 3. Notation : espaces + lettres + ASCII imprimables + mots frequents
# ============================================================

print("--- 3. Les 5 cles les plus probables (score_texte) ---")
classement = score_texte(DATA)
for rang, (score, k, clair) in enumerate(classement[:5], start=1):
    affiche = "".join(chr(p) if ASCII_MIN <= p <= ASCII_MAX else "." for p in clair)
    print(f"{rang}. Cle {k:3d} (0x{k:02X}, {chr(k)!r})  score = {score:7.2f}  |  {affiche}")

# Verification du XOR : (P ^ K) ^ K = P
meilleure_cle = classement[0][1]
clair = dechiffrer(DATA, meilleure_cle)
assert [p ^ meilleure_cle for p in clair] == DATA
print("\nVerification ((P ^ K) ^ K = P) : OK")
print("Cle retenue       :", meilleure_cle, "=", hex(meilleure_cle), "=", repr(chr(meilleure_cle)))
print("Message dechiffre :", "".join(chr(p) for p in clair))

# ============================================================
# 4. Validation du score sur un message dont on connait la cle
# ============================================================

print("\n--- 4. Validation : chiffrement d'un message connu puis cryptanalyse ---")

for message_connu, cle_connue in (
    ("le xor est simple", 0x2A),
    ("CRYPTOGRAPHIE ET RESEAUX", 0x77),
    ("les donnees sont chiffrees avec une cle", 0x13),
):
    clair_connu = [ord(c) for c in message_connu]
    chiffre_connu = [p ^ cle_connue for p in clair_connu]
    trouvee = score_texte(chiffre_connu)[0][1]
    print(f"{message_connu!r:45} cle={cle_connue:3d} -> retrouvee {trouvee:3d} "
          f"{'OK' if trouvee == cle_connue else 'ECHEC'}")
    assert trouvee == cle_connue, "Le score doit retrouver la bonne cle"
