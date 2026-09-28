"""
Confronto delle foto profilo tramite perceptual hashing (dHash).

Perché questo segnale
----------------------
La stessa persona riusa l'immagine del profilo molto più spesso di quanto
riusi la bio: l'avatar viene portato da una piattaforma all'altra quasi per
inerzia, mentre la descrizione viene riscritta ogni volta. È quindi
plausibilmente un indizio più forte di content_similarity.

Non si confrontano i byte: la stessa immagine servita da due piattaforme
diverse è ricompressa, ridimensionata, a volte ritagliata, quindi due file
identici all'occhio hanno byte completamente diversi. Il perceptual hashing
risolve proprio questo: riduce l'immagine a una firma corta che resta simile
quando l'immagine resta simile.

Qui è implementato dHash (difference hash), non la libreria imagehash, per
non aggiungere una dipendenza: sono venti righe e serve solo Pillow.
Funziona così: l'immagine viene portata a 9x8 pixel in scala di grigi, e per
ogni riga si confronta ogni pixel col successivo (8 confronti per riga, 8
righe = 64 bit). Il bit vale 1 se il pixel è più chiaro del vicino. Il
risultato dipende dai rapporti di luminosità tra zone vicine, che
sopravvivono a ricompressione e ridimensionamento, e non dai valori assoluti.

Le tre guardie, che NON sono opzionali
--------------------------------------
1. IMMAGINI DEGENERI. Un quadrato di colore uniforme produce un hash che
   somiglia a quello di ogni altro quadrato uniforme. Si scartano le immagini
   con varianza di luminosità troppo bassa.

2. IMMAGINI TROPPO PICCOLE. Sotto una certa dimensione non c'è struttura da
   hashare e il risultato è rumore.

3. AVATAR DI DEFAULT - la più importante. La sagoma grigia di Instagram, lo
   snoo di Reddit, le lettere colorate di Telegram sono IDENTICHE fra persone
   DIVERSE. Un hash del genere, preso per buono, produce falsi positivi
   confidenti, che sono i peggiori di tutti. La guardia è la stessa idea che
   Perito et al. applicano agli username: un identificatore condiviso da molti
   non identifica nessuno. Qui si conta su quanti username DIVERSI compare lo
   stesso hash (a meno di qualche bit di distanza): se sono troppi, l'hash non
   è distintivo e il segnale vale zero. Il conteggio si costruisce da solo
   mano a mano che si analizzano profili, quindi migliora con l'uso.

LIMITE: la guardia 3 impara dai dati raccolti, quindi
sulle prime indagini - quando la tabella degli hash è quasi vuota - non ha
ancora niente su cui basarsi e un avatar di default potrebbe passare.
"""

import io

try:
    from PIL import Image
    PILLOW_DISPONIBILE = True
except ImportError:      # senza Pillow il modulo non serve, ma non deve rompere nulla
    PILLOW_DISPONIBILE = False

LATO = 8                      # 8x8 confronti = 64 bit
MIN_PIXEL = 32                # sotto i 32px per lato non c'è struttura
MIN_VARIANZA = 40.0           # sotto questa varianza l'immagine è quasi piatta
BIT = LATO * LATO             # 64

# Entro quanti bit due hash si considerano "la stessa immagine" ai fini del
# conteggio di distintività (guardia 3). Tenuto basso apposta: serve a
# raggruppare le varianti dello stesso avatar di default, non a decidere se
# due persone coincidono - quella soglia va calibrata sui dati.
BIT_STESSA_FAMIGLIA = 4

# Su quanti username diversi un hash può comparire prima di essere
# considerato non distintivo. 3 è prudente: la stessa persona su 9
# piattaforme ha UN solo username, quindi un hash legittimo compare su 1
# username (o 2 se è anche una sua variante).
MAX_USERNAME_PER_HASH = 3


def dhash(dati_immagine):
    """Calcola il dHash a 64 bit. Torna (hash, motivo_scarto).

    Se l'immagine è inutilizzabile torna (None, motivo): il motivo serve per
    poterlo scrivere nel CSV e sapere PERCHÉ un profilo non ha contribuito
    con la foto, invece di vedere solo una cella vuota.
    """
    if not PILLOW_DISPONIBILE:
        return None, "Pillow non installato"
    if not dati_immagine:
        return None, "immagine vuota"
    try:
        img = Image.open(io.BytesIO(dati_immagine))
        img.load()
    except Exception as e:                      # formati rotti, troncati, non immagini
        return None, f"non apribile ({type(e).__name__})"

    larghezza, altezza = img.size
    if min(larghezza, altezza) < MIN_PIXEL:
        return None, f"troppo piccola ({larghezza}x{altezza})"

    grigi = img.convert("L")

    # guardia 1: immagine quasi piatta
    campione = grigi.resize((16, 16), Image.Resampling.BILINEAR)
    valori = list(campione.getdata())
    media = sum(valori) / len(valori)
    varianza = sum((v - media) ** 2 for v in valori) / len(valori)
    if varianza < MIN_VARIANZA:
        return None, f"immagine quasi uniforme (varianza {varianza:.0f})"

    # dHash: 9 colonne per avere 8 confronti orizzontali per riga
    piccola = grigi.resize((LATO + 1, LATO), Image.Resampling.LANCZOS)
    pixel = list(piccola.getdata())
    bit = 0
    for riga in range(LATO):
        base = riga * (LATO + 1)
        for col in range(LATO):
            bit <<= 1
            if pixel[base + col] > pixel[base + col + 1]:
                bit |= 1
    return bit, ""


def distanza(hash_a, hash_b):
    """Distanza di Hamming: quanti bit differiscono. 0 = identiche,
    64 = opposte. In pratica sotto ~10 sono la stessa immagine, sopra ~20
    sono immagini diverse - ma la soglia va CALIBRATA sui dati, non decisa
    qui: per questo il valore grezzo finisce nel CSV."""
    if hash_a is None or hash_b is None:
        return None
    return bin(int(hash_a) ^ int(hash_b)).count("1")


def somiglianza(hash_a, hash_b):
    """Da 0 a 1, per poter entrare nel punteggio come gli altri segnali.

    Non è una semplice proporzione lineare sui 64 bit: due immagini
    completamente diverse danno in media 32 bit di differenza, non 64, quindi
    1 - d/64 partirebbe da 0.5 anche per immagini che non hanno niente a che
    fare. Si usa 32 come fondo scala: a 32 bit o più il segnale è zero.
    """
    d = distanza(hash_a, hash_b)
    if d is None:
        return 0.0
    return max(0.0, 1.0 - d / (BIT / 2))


def hash_distintivo(hash_foto, censimento):
    """Guardia 3: questo hash è di una persona o è un avatar di default?

    `censimento` è una lista di coppie (hash, username) già viste. Si
    contano gli username DIVERSI il cui avatar sta entro
    BIT_STESSA_FAMIGLIA bit da questo: se sono troppi, l'immagine è
    condivisa fra persone diverse e come indizio non vale niente.

    Torna (True/False, quanti_username).
    """
    if hash_foto is None:
        return False, 0
    simili = {u for h, u in censimento
              if u and distanza(hash_foto, h) is not None
              and distanza(hash_foto, h) <= BIT_STESSA_FAMIGLIA}
    return len(simili) <= MAX_USERNAME_PER_HASH, len(simili)


def scarica(url, session, timeout=30):
    """Scarica i byte dell'immagine. Nessuna logica di rete qui dentro oltre
    al minimo: la fila, la cache e il conteggio degli errori stanno in
    osint.py, come per le pagine."""
    try:
        r = session.get(url, timeout=timeout)
        if r.status_code != 200:
            return None, f"HTTP {r.status_code}"
        if len(r.content) > 8 * 1024 * 1024:
            return None, "immagine troppo grande"
        return r.content, ""
    except Exception as e:
        # si distingue: un errore di rete è temporaneo, un errore inatteso no
        import requests
        if isinstance(e, requests.exceptions.RequestException):
            return None, f"errore di rete ({type(e).__name__})"
        return None, f"errore inatteso ({type(e).__name__})"
