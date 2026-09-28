"""
Qui dentro c'è il motore che calcola quanto è probabile che un candidato
(uno username variante trovato attivo su una piattaforma) sia in realtà
la STESSA persona dello username di partenza.

È un modulo di solo calcolo, niente rete qui dentro - scaricare le pagine
è compito di osint.py / osint_profile.py. Così è facile testarlo per
conto suo, senza dover simulare internet.

Gli indicatori che usiamo sono quelli tipici per correlare identità tra
piattaforme diverse (in letteratura: hard/soft selector, riuso
di bio/testo, sovrapposizione temporale delle attività, presenza su più
piattaforme):

- username_similarity : quanto il candidato somiglia testualmente allo
  username originale (in pratica: quanto "riusa" l'handle).
- content_similarity   : quanto il testo preso dalle pagine archiviate
  (titolo/bio) del candidato somiglia a quello del target (cioè: quanto
  "riusa" la stessa bio/descrizione).
- temporal_overlap     : quanto si sovrappongono nel tempo i periodi in
  cui i due account sono stati attivi (guardando lo snapshot più vecchio
  e quello più recente su Wayback Machine).
- multi_platform       : su quante piattaforme diverse (rispetto al
  totale che stiamo controllando) salta fuori il candidato.

I pesi non sono nascosti dentro il calcolo, sono parametri veri e propri
(DEFAULT_WEIGHTS, SAME_USERNAME_WEIGHTS), stimati sui dati con una regressione logistica (vedi sotto).
"""

import math
import re
from difflib import SequenceMatcher
from datetime import datetime, timedelta

# PESI DEL PUNTEGGIO: stimati sui dati, non scelti a mano.
# Vengono da una regressione logistica sui 943 candidati giudicati a mano come
# stessa persona (S) o no (N) nelle indagini della tesi, stimata separatamente
# per le varianti e per i candidati con lo stesso username, e arrotondati a due
# decimali in modo che la somma resti 1. Lo script di calibrazione e i giudizi
# non fanno parte di questo repository: i dati riguardano persone reali.
# Sono stime su pochi dati, soprattutto per le varianti (16 collegamenti veri).
# Con più giudizi basta ristimarli e aggiornare questi numeri, senza rifare
# alcuna richiesta di rete, perché il CSV registra ogni indizio separatamente.
#
# account_links (link esplicito fra i due account) è anche il criterio con
# cui molte etichette S sono state decise: il suo peso è quindi ottimistico.
#
# Varianti (username diverso dall'originale): conta soprattutto il periodo di
# presenza nell'archivio e il link esplicito, poi testo e foto.
DEFAULT_WEIGHTS = {
    "username_similarity": 0.10,
    "content_similarity": 0.16,
    "temporal_overlap": 0.24,
    "multi_platform": 0.09,
    "shared_links": 0.0,
    "photo_similarity": 0.13,
    "temporal_containment": 0.0,
    "account_links": 0.28,
}

# Stesso username su un'altra piattaforma: la somiglianza dello username vale
# sempre 1 e la presenza su più piattaforme non si calcola, quindi non entrano
# nella stima. Contano il link esplicito, il testo e il periodo di presenza
# nell'archivio. Link in comune: peso zero (sempre assenti nei dati).
SAME_USERNAME_WEIGHTS = {
    "username_similarity": 0.0,
    "content_similarity": 0.31,
    "temporal_overlap": 0.31,
    "multi_platform": 0.0,
    "shared_links": 0.0,
    "photo_similarity": 0.02,
    "temporal_containment": 0.0,
    "account_links": 0.36,
}


def fascia(score_100):
    """Fascia di confidenza a parole: sotto 40 bassa, da 40 media, da 70 alta."""
    if score_100 >= 70:
        return "Alta"
    if score_100 >= 40:
        return "Media"
    return "Bassa"


def punteggio_da_riga(riga):
    """Ricalcola il punteggio (0-100) di una riga del CSV dai suoi indizi, con
    i pesi attuali. Serve a rivalutare risultati già salvati senza rete."""
    pesi = SAME_USERNAME_WEIGHTS if riga.get("Tipo") == "Stesso username" else DEFAULT_WEIGHTS
    tot = 0.0
    for k, p in pesi.items():
        v = riga.get("ind_" + k, "")
        try:
            tot += p * float(v)
        except (TypeError, ValueError):
            pass
    return round(tot * 100, 1)

# Parole troppo comuni (italiano + inglese) che ignoriamo quando
# confrontiamo i testi: senza questo filtro, anche due bio TOTALMENTE
# diverse risultano comunque un po' simili solo per punteggiatura, spazi,
# articoli condivisi e roba del genere - e questo sporca il segnale.
# Quello che ci interessa davvero è capire se vengono riusate parole o
# frasi SPECIFICHE, non la struttura generica della lingua.
_STOPWORDS = {
    "il", "lo", "la", "i", "gli", "le", "un", "uno", "una", "di", "del", "della",
    "dei", "delle", "e", "ed", "o", "che", "chi", "cui", "non", "per", "con", "su",
    "tra", "fra", "da", "in", "a", "al", "allo", "alla", "ai", "agli", "alle",
    "è", "sono", "sei", "siamo", "siete",
    "the", "a", "an", "of", "and", "or", "to", "in", "on", "for", "is", "are",
    "was", "were", "from", "with", "at", "by", "this", "that", "it", "as", "be", "i",
}


def _tokenize(text):
    # occhio: usiamo 'à-öø-ÿ' e non 'à-ÿ' apposta, per escludere il simbolo
    # '÷' (divisione) che altrimenti ci scappava dentro come se fosse una
    # lettera qualunque (sta proprio in mezzo a 'ö' e 'ø' nella tabella
    # Unicode, per puro caso).
    words = re.findall(r"[a-zà-öø-ÿ0-9]+", text.lower())
    return [w for w in words if w not in _STOPWORDS and len(w) > 1]


def username_similarity(original, candidate):
    # SequenceMatcher confronta due stringhe carattere per carattere e dà
    # un numero da 0 (per niente simili) a 1 (identiche)
    return SequenceMatcher(None, original.lower(), candidate.lower()).ratio()


def content_similarity(snippet_a, snippet_b):
    """Confronta due testi (titolo/bio) a livello di PAROLE, non di
    caratteri grezzi. Così si cattura quello che interessa davvero - il
    riuso di parole o frasi precise tra un profilo e l'altro - senza il
    "rumore di fondo" che si crea confrontando caratteri tra due testi
    qualsiasi nella stessa lingua."""
    if not snippet_a or not snippet_b:
        return 0.0
    tokens_a = _tokenize(snippet_a)
    tokens_b = _tokenize(snippet_b)
    if not tokens_a or not tokens_b:
        return 0.0
    return SequenceMatcher(None, tokens_a, tokens_b).ratio()


def _snapshot_bounds(snapshots):
    # prende tutte le date degli snapshot e restituisce solo la più vecchia
    # e la più recente - cioè l'inizio e la fine del periodo "attivo"
    dates = [datetime.strptime(s["Data_Salvataggio"], "%Y-%m-%d %H:%M:%S") for s in snapshots]
    return (min(dates), max(dates)) if dates else (None, None)


def temporal_overlap(snapshots_a, snapshots_b, padding_days=30):
    """Punteggio da 0 a 1 in base a quanto si sovrappongono nel tempo i
    periodi di attività (dallo snapshot più vecchio al più recente) dei
    due gruppi di snapshot.

    Ogni data viene "allargata" un po' (padding_days) prima di fare il
    calcolo: senza questo trucco, un candidato con UN SOLO snapshot (cioè
    un punto nel tempo, non un intervallo) avrebbe SEMPRE sovrapposizione
    zero con qualsiasi riferimento, anche se quel giorno cadeva proprio in
    mezzo al periodo noto - ed è il caso più comune, perché la maggior
    parte dei candidati ha pochi snapshot."""
    start_a, end_a = _snapshot_bounds(snapshots_a)
    start_b, end_b = _snapshot_bounds(snapshots_b)
    if not start_a or not start_b:
        return 0.0

    pad = timedelta(days=padding_days)
    start_a, end_a = start_a - pad, end_a + pad
    start_b, end_b = start_b - pad, end_b + pad

    latest_start = max(start_a, start_b)
    earliest_end = min(end_a, end_b)
    overlap_days = (earliest_end - latest_start).days
    if overlap_days <= 0:
        return 0.0

    span_days = max((max(end_a, end_b) - min(start_a, start_b)).days, 1)
    return min(overlap_days / span_days, 1.0)


def temporal_containment(snapshots_a, snapshots_b, padding_days=30):
    """Come temporal_overlap, ma la sovrapposizione è divisa per il periodo
    PIÙ CORTO invece che per l'unione dei due.

    Perché esiste: temporal_overlap penalizza chi è stato archiviato poco.
    Misurato sulle prime etichette della seconda serie: il Medium di
    mitchellbaker, che linka il suo Twitter (quindi è lei), ha UNA sola copia
    del 2019, che cade in pieno nei 18 anni di Twitter; con la formula
    sull'unione vale 0.009, con questa vale 1. Il rovescio: con un'ancora
    lunga (jack è su Twitter dal 2006) qualsiasi candidato "ci sta dentro",
    quindi questo segnale distingue poco. Quale dei due funziona meglio non
    si decide a tavolino: si calcolano entrambi e lo dice la calibrazione."""
    start_a, end_a = _snapshot_bounds(snapshots_a)
    start_b, end_b = _snapshot_bounds(snapshots_b)
    if not start_a or not start_b:
        return 0.0
    pad = timedelta(days=padding_days)
    start_a, end_a = start_a - pad, end_a + pad
    start_b, end_b = start_b - pad, end_b + pad
    overlap_days = (min(end_a, end_b) - max(start_a, start_b)).days
    if overlap_days <= 0:
        return 0.0
    piu_corto = max(min((end_a - start_a).days, (end_b - start_b).days), 1)
    return min(overlap_days / piu_corto, 1.0)


def rarita_username(candidati_prefisso):
    """Quanto è RARO lo username di partenza, da 0 a 1.

    Misurato su quanti username diversi la ricerca per prefisso ha trovato:
    'torvalds' ne ha 15, 'jack' oltre 54.000. Serve a correggere
    multi_platform: per uno username raro, un candidato presente su molte
    piattaforme suggerisce una persona che riusa il proprio nome; per uno
    username comune misura soprattutto quanto è diffuso quel nome
    ('Jackson' è su 6 piattaforme perché ce l'hanno 6 persone diverse).
    È l'argomento di Perito et al. sull'informazione contenuta in uno
    username, misurato sui dati dell'indagine.

    Formula: 1 fino a 10 candidati, poi 1/log10(N): ogni fattore dieci di
    candidati in più riduce il valore (100 -> 0.5, 1000 -> 0.33,
    54.936 -> 0.21). Il numero è un minimo (gli elenchi molto lunghi
    vengono letti solo in parte), quindi la correzione è prudente."""
    if not candidati_prefisso or candidati_prefisso <= 10:
        return 1.0
    return 1.0 / math.log10(candidati_prefisso)


def multi_platform_score(platform_count, total_platforms):
    # semplice proporzione: su quante piattaforme è spuntato il candidato,
    # diviso il totale che stiamo controllando (es. 3 su 10 -> 0.3)
    if total_platforms == 0:
        return 0.0
    return min(platform_count / total_platforms, 1.0)


def _normalizza_link(link):
    """Riduce un URL alla sua forma "essenziale" per poterlo confrontare:
    via il protocollo, via il 'www.', via la barra finale, tutto minuscolo.
    Così 'https://www.miosito.it/' e 'http://miosito.it' risultano lo
    stesso link (perché lo sono)."""
    link = (link or "").strip().lower()
    link = re.sub(r'^https?://', '', link)
    link = re.sub(r'^www\.', '', link)
    return link.rstrip('/')


def shared_links_score(links_a, links_b):
    """Quanti link esterni hanno in comune i due profili, da 0 a 1.

    Perché questo indicatore: se due account linkano lo STESSO sito
    esterno (il sito personale, un altro social, un blog), è una prova
    forte e - cosa che gli altri indicatori non hanno - completamente
    INDIPENDENTE da come si chiama l'account. username_similarity invece
    è quasi sempre alto per costruzione (i candidati nascono mutando lo
    username di partenza o cercando per prefisso, quindi somigliano
    all'originale per forza): misurato sui candidati veri, regalava ~23
    punti su 100 a chiunque, usandone solo ~5 per distinguere un candidato
    dall'altro. Questo indicatore invece vale 0 quando non c'è nessuna
    prova, e sale solo quando una prova c'è davvero.

    Scala scelta: un link in comune vale 0.5 (buon indizio), due o più
    valgono 1.0 (prova solida). Non usiamo una proporzione sul totale dei
    link perché i profili hanno numeri di link molto diversi tra loro, e
    quello che conta è QUANTI ne condividono, non che percentuale."""
    if not links_a or not links_b:
        return 0.0
    set_a = {_normalizza_link(x) for x in links_a if x and x.strip()}
    set_b = {_normalizza_link(x) for x in links_b if x and x.strip()}
    comuni = set_a & set_b
    return min(len(comuni) / 2, 1.0)


def compute_confidence(original_username, candidate_username,
                        candidate_snapshots, baseline_snapshots,
                        candidate_platform_count, total_platforms,
                        content_snippet_a="", content_snippet_b="",
                        links_a=None, links_b=None,
                        photo_similarity_value=0.0,
                        weights=None, rarita=1.0):
    """Mette insieme tutti i segnali in un punteggio unico da 0 a 100, e
    restituisce anche il dettaglio di ognuno (utile per spiegare bene il
    risultato nel report, invece di dare solo un numero secco)."""
    w = weights or DEFAULT_WEIGHTS

    # calcoliamo i 5 segnali uno per uno, ognuno da 0 a 1
    signals = {
        "username_similarity": username_similarity(original_username, candidate_username),
        "content_similarity": content_similarity(content_snippet_a, content_snippet_b),
        "temporal_overlap": temporal_overlap(candidate_snapshots, baseline_snapshots),
        # corretto per la rarità dello username: vedi rarita_username
        "multi_platform": multi_platform_score(candidate_platform_count, total_platforms) * rarita,
        "shared_links": shared_links_score(links_a, links_b),
        # collegamento esplicito fra i due account: si calcola dopo, quando
        # tutte le pagine dell'indagine sono disponibili (osint.py, export)
        "account_links": 0.0,
        # calcolato fuori da qui (serve Pillow e la rete per l'immagine):
        # questo modulo resta di puro calcolo, vedi osint_foto.py
        "photo_similarity": float(photo_similarity_value or 0.0),
        "temporal_containment": temporal_containment(candidate_snapshots, baseline_snapshots),
    }

    # e li sommiamo, ognuno moltiplicato per il suo peso - poi portiamo il
    # risultato (che va da 0 a 1) su una scala da 0 a 100, più facile da leggere
    score = sum(signals[k] * w.get(k, 0) for k in signals)
    score_100 = round(score * 100, 1)

    # tre fasce, giusto per dare un'etichetta a parole invece del solo numero
    label = fascia(score_100)

    return {
        "score": score_100,
        "confidenza": label,
        "dettaglio_indicatori": {k: round(v, 3) for k, v in signals.items()},
    }
