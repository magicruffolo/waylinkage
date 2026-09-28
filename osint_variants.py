"""
Questo file genera le varianti "a naso" dello username, quelle da provare
sulle altre piattaforme.
Perché serve: raramente una persona usa esattamente LO STESSO username
dappertutto (magari era già preso, oppure c'erano limiti di lunghezza/
caratteri, o semplicemente ha voluto cambiarlo apposta) - ma di solito
segue degli schemi abbastanza prevedibili: separatori diversi, piccole
sostituzioni leetspeak, suffissi tipici tipo "official"/"real"/l'anno,
oppure combinazioni nome.cognome. Sono gli stessi pattern che usano tool
OSINT tipo Sherlock/Maigret (con il flag --permute) e le guide sull'argomento.

Ogni variante che tiriamo fuori porta con sé anche la "tecnica" usata per
generarla, così nel report si può spiegare PERCHÉ è stata
provata, e in futuro magari dare più peso a una tecnica piuttosto che a
un'altra.
"""

import re
from difflib import SequenceMatcher

LEET_MAP = {
    'a': ['4'],
    'e': ['3'],
    'i': ['1'],
    'o': ['0'],
    's': ['5'],
}

SEPARATORS = ['', '.', '_', '-']
SUFFIXES = ['official', 'real', '1', '01', '00', '99', '2024', '2025']


def _split_words(username):
    """Cerca di capire quali "parole" ci sono dentro lo username: prima
    prova con i separatori scritti chiari (_ . -), poi con il camelCase
    (tipo 'MarioRossi' -> ['Mario', 'Rossi'])."""
    # primo tentativo: separatori scritti chiari, tipo "mario_rossi" -> ["mario", "rossi"]
    parts = re.split(r'[._\-]', username)
    parts = [p for p in parts if p]   # via le stringhe vuote (se c'erano due separatori di fila)
    if len(parts) > 1:
        return parts

    # secondo tentativo: split sul camelCase, tipo "MarioRossi" -> ["Mario", "Rossi"]
    camel_split = re.findall(r'[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])', username)
    if len(camel_split) > 1:
        return camel_split

    # niente da spezzare: è una parola sola
    return [username]


def _leet_variants(word):
    """Varianti leetspeak, ma con UNA sostituzione alla volta - se no le
    combinazioni esplodono e vengono fuori varianti assurde che nessuno
    userebbe mai."""
    variants = set()
    lower = word.lower()
    # scorriamo lettera per lettera: se la lettera ha un sostituto leet
    # (tipo 'a' -> '4'), creiamo UNA variante con solo quella lettera
    # cambiata (il resto della parola resta uguale)
    for i, c in enumerate(lower):
        if c in LEET_MAP:
            for repl in LEET_MAP[c]:
                variants.add(lower[:i] + repl + lower[i + 1:])
    return variants


def _quick_distance(a, b):
    return -SequenceMatcher(None, a.lower(), b.lower()).ratio()


def generate_variants(username, nome=None, cognome=None, max_variants=15):
    """
    Tira fuori una lista di username "candidati", collegabili in qualche
    modo allo username di partenza.

    Torna una lista di dict: [{"variante": str, "tecnica": str}, ...],
    ordinata mettendo per prime le varianti più simili allo username
    originale (così si testano prima quelle più probabili).
    """
    username = (username or "").strip()
    if not username:
        return []

    candidates = {}  # variante(lower) -> tecnica (vince la prima che troviamo)

    def add(v, tecnica):
        # piccola funzione "helper" richiamata da tutte le sezioni sotto:
        # aggiunge una variante alla lista, ma solo se non è' vuota, non è'
        # uguale allo username originale, e non l'abbiamo già presa prima
        v = (v or "").strip()
        if not v or v.lower() == username.lower():
            return
        key = v.lower()
        if key not in candidates:
            candidates[key] = tecnica

    words = _split_words(username)
    # 1. proviamo separatori diversi tra le parole che abbiamo trovato
    if len(words) > 1:
        for sep in SEPARATORS:
            sep_label = sep if sep else "nessuno"
            add(sep.join(words), f"separatore '{sep_label}'")
            add(sep.join(w.capitalize() for w in words),
                f"separatore '{sep_label}' + capitalizzazione")

    # 2. suffissi classici (uno stato tipo "official", oppure l'anno)
    for suf in SUFFIXES:
        add(f"{username}{suf}", f"suffisso '{suf}'")
        add(f"{username}_{suf}", f"suffisso '_{suf}'")

    # 3. leetspeak (una sostituzione alla volta, vedi sopra il perché)
    # sorted: _leet_variants restituisce un insieme, e l'ordine di un insieme
    # di stringhe cambia da un'esecuzione all'altra (PYTHONHASHSEED). Senza
    # ordinarlo, rilanciando la stessa indagine si provavano varianti diverse.
    for v in sorted(_leet_variants(username)):
        add(v, "sostituzione leetspeak")

    # 4. combo nome/cognome, ma solo se l'utente li ha dati entrambi
    if nome and cognome:
        n, c = nome.strip().lower(), cognome.strip().lower()
        if n and c:
            for v, tecnica in [
                (f"{n}.{c}", "nome.cognome"),
                (f"{n}_{c}", "nome_cognome"),
                (f"{n}{c}", "nomecognome"),
                (f"{c}.{n}", "cognome.nome"),
                (f"{c}{n}", "cognomenome"),
                (f"{n[0]}.{c}", "iniziale.cognome"),
                (f"{n[0]}{c}", "inizialecognome"),
                (f"{n}.{c[0]}", "nome.inizialecognome"),
            ]:
                add(v, tecnica)

    # ordiniamo tutti i candidati per somiglianza allo username originale
    # (i più simili prima), e teniamo solo i primi max_variants
    # a parità di somiglianza decide l'ordine alfabetico: così la scelta delle
    # varianti è la stessa a ogni esecuzione (riproducibilità)
    ordered = sorted(candidates.items(),
                     key=lambda kv: (_quick_distance(username, kv[0]), kv[0]))
    return [{"variante": v, "tecnica": t} for v, t in ordered[:max_variants]]
