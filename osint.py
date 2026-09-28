"""
OSINT Username Correlator - v4

Cos'è, in due parole: dato uno username prova a capire se quella persona
usa handle diversi su altri social, e tira su tutte le info che trova.

Roba nuova rispetto alla versione base:

  1. cerca varianti VERE dello username, cioè già esistite davvero (con
     la ricerca per prefisso di Wayback), invece di sparare ipotesi a caso;
  2. in più genera anche varianti "a naso" (separatori diversi, leetspeak,
     suffissi tipo "official", combo nome.cognome) per beccare i casi che
     la ricerca per prefisso non riesce a coprire (cioè quando cambia
     l'INIZIO dello username, non la fine);
  3. ogni candidato trovato viene ricontrollato su tutte le piattaforme
     che monitoriamo;
  4. c'è un sistema di punteggio (vedi osint_scoring.py) che dice quanto
     è probabile che un certo candidato sia proprio la stessa persona;
  5. si sceglie una piattaforma "di riferimento" tra quelle con lo stesso
     username, e si usa quella come metro di paragone per le altre - non
     si dà per scontato che stesso username = stessa persona ovunque;
  6. si tira giù nome/bio/foto/link dai profili (osint_profile.py) e si
     mette tutto insieme in una scheda persona finale (osint_report.py).

Dati: SOLO Wayback Machine, punto. Niente richieste dirette ai siti veri,
né per controllare se un profilo esiste né per leggerne il contenuto -
si scarica sempre e solo la pagina già salvata da archive.org.

Le richieste partono UNA alla volta, senza parallelismo. È una scelta,
non una dimenticanza: una versione parallela era 3 volte più veloce, ma
alzava talmente il ritmo verso archive.org che dopo un po' le connessioni
venivano rifiutate - e un'indagine con metà delle richieste fallite
produce punteggi calcolati su dati mancanti, cioè numeri che sembrano
validi e non lo sono. Per uno strumento di indagine è il difetto peggiore
possibile, quindi: meglio dieci minuti e risultati di cui ci si può fidare.
Il codice, in cambio, resta leggibile riga per riga.

Se archive.org dovesse rispondere male (errori 503 o connessioni
rifiutate), il programma se ne accorge, si ferma e lo dice, invece di
andare avanti e produrre una scheda basata sul nulla. Per rallentare
ancora: --delay 3.
"""

import argparse
import json
import os
import random
import re
import time
from datetime import datetime
from difflib import SequenceMatcher
from urllib.parse import quote

import pandas as pd
import requests

# questi quattro moduli sono i "pezzi" del programma, ognuno fa una cosa sola:
from osint_variants import generate_variants          # inventa username simili
from osint_scoring import (compute_confidence, SAME_USERNAME_WEIGHTS,
                            DEFAULT_WEIGHTS, rarita_username,
                            punteggio_da_riga, fascia)   # calcola i punteggi
from osint_profile import fetch_archive_html, extract_profile_fields, domain_from_archive_url
from osint_report import build_person_summary, print_person_summary, export_person_summary
# osint_profile legge le pagine archiviate, osint_report costruisce la scheda finale
from osint_cache import CacheCDX
import osint_foto
# osint_rete è il livello che parla con archive.org: fila delle richieste,
# cache, freno dopo un 503, conteggio degli errori. Importato come modulo e non
# con "from ... import cache" apposta: main() deve poter sostituire gli oggetti
# condivisi con quelli costruiti dalle opzioni, e un "from" ne copierebbe solo
# il riferimento (vedi la nota in cima a osint_rete.py).
import osint_rete as rete
import percorsi
# osint_cache tiene su disco ciò che deve sopravvivere alla fine del processo:
# le risposte già ottenute, il freno dopo un 503 e i tempi delle richieste

DEFAULT_PLATFORMS = [
    "github.com",
    "twitter.com",
    "x.com",
    "instagram.com",
    "reddit.com/user",
    "medium.com/@",
    "t.me",
    "tiktok.com/@",
    "keybase.io",
]


_ALIAS_PIATTAFORME = {
    "twitter": "twitter/x",
    "x": "twitter/x",
}


def _platform_label(url_base):
    # trasforma tipo "github.com" in "github" o "medium.com/@" in "medium",
    # solo per avere un'etichetta più corta e pulita da mettere nei dati.
    # Prendiamo prima SOLO il dominio (tutto quello che sta prima del primo
    # '/'): se non lo facciamo, un prefisso con un pezzo di path dentro tipo
    # "reddit.com/user" verrebbe attaccato male e diventerebbe "reddituser"
    # invece di "reddit" - sembra un nome a caso, non il sito Reddit.
    domain = url_base.split('/')[0]
    etichetta = domain.replace('.com', '').replace('@', '')
    # e infine accorpiamo i domini che sono la stessa piattaforma (vedi sopra)
    return _ALIAS_PIATTAFORME.get(etichetta, etichetta)


# I cinque segnali che compongono il punteggio, nell'ordine in cui li vogliamo
# nel CSV. Vengono salvati UNO PER UNO, non solo la loro somma pesata.
#
# Perché è importante: un punteggio finale è una somma pesata, e da una
# somma non si risale agli addendi. Salvando solo 'Score' l'unico modo per
# provare pesi diversi sarebbe rifare tutte le richieste di rete da capo -
# cioè rifare il batch per ogni ipotesi di pesatura. Salvando i segnali, la
# calibrazione diventa un calcolo offline su file che hai già, ripetibile
# quante volte vuoi in pochi secondi e senza toccare archive.org.
_SEGNALI = ("username_similarity", "content_similarity", "temporal_overlap",
            "multi_platform", "shared_links", "photo_similarity",
            "temporal_containment", "account_links")


class _PagineDallaCache:
    """Adatta la cache dello strumento all'interfaccia usata da
    trova_collegamenti (un metodo html(url))."""
    def html(self, url):
        return rete.cache.leggi_pagina(url) if url else None


def aggiungi_collegamenti(righe, username):
    """Indizio account_links: cerca, con le pagine già scaricate, i link
    espliciti fra l'ancora e ogni candidato (vedi trova_collegamenti.py) e
    ricalcola punteggio e fascia delle righe dei candidati."""
    from trova_collegamenti import analizza_righe, valore_indizio, _PIATT
    trovati = analizza_righe(righe, username, _PagineDallaCache())
    valori = {(c["Piattaforma"], c["Candidato"]): valore_indizio(c["Livello"]) for c in trovati}
    for r in righe:
        if r.get("Tipo") == "Target":
            continue
        k = (_PIATT.get(r.get("Piattaforma"), r.get("Piattaforma")),
             (r.get("Username_Testato") or "").lower())
        pesi = SAME_USERNAME_WEIGHTS if r.get("Tipo") == "Stesso username" else DEFAULT_WEIGHTS
        r["ind_account_links"] = valori.get(k, 0.0)
        r["peso_account_links"] = pesi.get("account_links", 0.0)
        r["Score"] = punteggio_da_riga(r)
        r["Confidenza"] = fascia(r["Score"])
    return len(valori)


def _colonne_indicatori(esito=None, pesi=None):
    """Trasforma il dettaglio degli indicatori in colonne piatte per il CSV.

    Salva anche i PESI usati per quella riga: baseline e candidati usano
    pesature diverse (SAME_USERNAME_WEIGHTS vs DEFAULT_WEIGHTS), e senza
    registrarlo non si saprebbe, rileggendo il CSV, con quale formula quel
    punteggio è stato prodotto."""
    dettaglio = (esito or {}).get("dettaglio_indicatori", {})
    colonne = {f"ind_{k}": dettaglio.get(k, "") for k in _SEGNALI}
    colonne.update({f"peso_{k}": (pesi or {}).get(k, "") for k in _SEGNALI})
    return colonne



def _copia_di_riserva(piattaforma, handle, gia_provati):
    """Snapshot "finto" per il ripiego del punto 4 di _profile_data_for: la
    copia di twitter.com/<handle> più vicina al 1/1/2020, oppure None se la
    piattaforma non è Twitter/X o se fra le copie già in lista ce n'è già
    una di quel periodo."""
    p = (piattaforma or "").lower()
    if not handle or not ("twitter" in p or p.startswith("x.") or p == "x"):
        return None
    if any(str(x.get("Data_Salvataggio", ""))[:4] < "2020" for x in gia_provati):
        return None
    return {"URL_Archivio": f"https://web.archive.org/web/20200101000000/https://twitter.com/{handle}",
            "Data_Salvataggio": "2020-01-01 (copia più vicina)",
            "Piattaforma": piattaforma}

def _durata(snapshots):
    """Giorni fra la prima e l'ultima cattura di un elenco di snapshot."""
    date = sorted(x['Data_Salvataggio'] for x in snapshots)
    if len(date) < 2:
        return 0
    f = '%Y-%m-%d %H:%M:%S'
    return (datetime.strptime(date[-1], f) - datetime.strptime(date[0], f)).days


def _nome_file_sicuro(username):
    # toglie dallo username i caratteri che non si possono usare in un nome
    # di file (su Windows soprattutto: \ / : * ? " < > |) e li sostituisce
    # con '_', così il salvataggio del CSV/JSON non fallisce mai per colpa
    # dello username scelto (es. uno username con uno '/' dentro)
    return re.sub(r'[\\/:*?"<>|]', '_', username)


def _target_url(url_base, username):
    # costruisce l'URL vero e proprio del profilo, tipo "github.com" +
    # "torvalds" -> "github.com/torvalds" (o "medium.com/@torvalds" se il
    # prefisso finisce già con '/' o '@'). Lo username viene "quotato"
    # (quote) prima di essere incollato nell'URL: se contenesse caratteri
    # strani tipo spazi o '&', senza questo passaggio rischierebbero di
    # rompere la richiesta alla CDX API (es. '&' verrebbe letto come inizio
    # di un altro parametro nella query, non come parte dello username).
    safe_username = quote(username, safe='')
    if url_base.endswith(('/', '@')):
        return f"{url_base}{safe_username}"
    return f"{url_base}/{safe_username}"


def fetch_snapshots(url_base, username, session, delay=1.5, timeout=25,
                    uno_per_giorno=True):
    """Chiede alla Wayback Machine (via CDX API, match esatto) se esiste una
    pagina salvata per questa coppia piattaforma+username. Torna indietro
    la lista di snapshot trovati, tipo:
        [{"Piattaforma": ..., "Data_Salvataggio": ..., "URL_Archivio": ...}, ...]
    """
    url_target = _target_url(url_base, username)
    # la CDX API è semplicemente un endpoint che, dato un URL, ti dice quali
    # copie salvate esistono su Wayback Machine - qui gli chiediamo il
    # risultato in JSON e solo le colonne che ci servono
    cdx_url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url={url_target}&output=json&fl=timestamp,original,statuscode,mimetype"
        # collapse=timestamp:8 = una riga per GIORNO invece di una per ogni
        # singola visita del crawler. Senza, per una pagina molto archiviata
        # (github.com/antirez, twitter.com/jack) si chiedono ad archive.org
        # decine di migliaia di righe: è la query che sotto carico viene
        # respinta con 503, ed è il motivo per cui fallivano sempre le stesse
        # piattaforme - quelle dove la persona è più presente.
        # Cosa NON cambia: temporal_overlap usa solo la data più vecchia e
        # la più recente (_snapshot_bounds), che restano identiche.
        # Cosa cambia: l'ancora si sceglie contando i GIORNI di presenza
        # invece delle visite del crawler - che è poi quello che il commento
        # di _select_anchor dice di voler misurare ("presenza solida nel
        # tempo"): 200 visite in una settimana non sono più storia di una
        # visita al mese per dieci anni.
        + ("&collapse=timestamp:8" if uno_per_giorno else "")
        # Filtri LATO SERVER: invece di scaricare tutte le righe e buttarne
        # metà qui in Python, si chiede direttamente ad archive.org di non
        # mandarle. Meno byte in transito e meno lavoro per un servizio che
        # sotto carico risponde 503. Sono spenti di default perché la
        # sintassi di 'filter' va verificata sul campo: vedi --filtri-server.
        + rete.filtri_server()
    )

    snapshots = []
    dati, esito = rete.richiesta_cdx(cdx_url, session, delay, timeout,
                                 url_base, dove_errore=url_base)

    if esito == "rete-a-terra":
        return snapshots
    if esito == "troppo-lento":
        # dato mancante, non uno zero: la piattaforma va segnata come non
        # contattata, se no il suo "0 snapshot" sembra un'informazione vera
        rete.errori_rete.piattaforme_fallite.add(url_base)
        return snapshots
    if esito == "errore-rete":
        # segna_errore() ha già registrato la piattaforma fra quelle fallite
        print(f"[!] {url_base}: errore di rete, salto questa piattaforma.")
        return snapshots
    if esito.startswith("http-"):
        # occhio: questo NON è un "username non trovato" - è la Wayback
        # Machine che ha risposto con un codice diverso da 200. Va registrato
        # come piattaforma fallita, se no il suo "0 snapshot" sembrerebbe un
        # dato vero e potrebbe spostare la scelta dell'ancora.
        rete.errori_rete.piattaforme_fallite.add(url_base)
        print(f"[!] {url_base}: la Wayback Machine ha risposto con codice "
              f"{esito[5:]}, salto questa piattaforma.")
        return snapshots
    if esito == "json-rotto":
        rete.errori_rete.piattaforme_fallite.add(url_base)
        print(f"[!] {url_base}: risposta della Wayback Machine ricevuta ma "
              f"JSON corrotto/troncato, salto questa piattaforma.")
        return snapshots

    # la prima riga di dati è l'intestazione delle colonne, non un risultato
    for row in (dati or [])[1:]:
        try:
            timestamp, original, statuscode, mimetype = row
            # teniamo solo le pagine caricate bene (200) e che sono HTML vero.
            # Resta anche con i filtri lato server attivi: se quelli sono
            # spenti (--no-filtri-server) questo è l'unico controllo che c'è.
            if statuscode != '200' or 'text/html' not in mimetype:
                continue
            dt_obj = datetime.strptime(timestamp, '%Y%m%d%H%M%S')
        except (ValueError, TypeError):
            # riga malformata: la si salta invece di far esplodere lo script
            continue
        snapshots.append({
            'Piattaforma': _platform_label(url_base),
            'Data_Salvataggio': dt_obj.strftime('%Y-%m-%d %H:%M:%S'),
            'URL_Archivio': f"https://web.archive.org/web/{timestamp}/{original}",
            'Fonte_Date': 'cdx',
        })

    return snapshots


def _extract_handle(original_url, url_base):
    """Tira fuori lo username da un URL archiviato, conoscendo il prefisso
    della piattaforma (es. original='https://github.com/torvalds1', url_base=
    'github.com' -> restituisce 'torvalds1')."""
    # via il protocollo (http/https) e l'eventuale "www." davanti, sia
    # dall'URL trovato che dal prefisso della piattaforma, così li possiamo
    # confrontare alla pari
    cleaned = re.sub(r'^https?://(www\.)?', '', original_url)
    # CDX conserva la porta com'era al momento della cattura: le catture
    # vecchie sono spesso "http://github.com:80/torvalds". Senza toglierla,
    # l'handle estratto era ':80', lo username vero spariva, e la ricerca per
    # prefisso concludeva che il candidato NON esisteva su quella piattaforma.
    # Ed è proprio la riga della cattura più vecchia quella che resta con
    # collapse=urlkey: colpiva soprattutto gli account più longevi.
    cleaned = re.sub(r'^([^/:?#]+):\d+', r'\1', cleaned)
    base_clean = re.sub(r'^https?://(www\.)?', '', url_base)
    if not cleaned.lower().startswith(base_clean.lower()):
        return None  # non è nemmeno un URL di questa piattaforma, niente da estrarre
    # quello che resta dopo il prefisso è lo username (con magari uno '/' o
    # '@' iniziale da togliere)
    remainder = cleaned[len(base_clean):].lstrip('/@')
    # e ci fermiamo al primo '/', '?' o '#' che troviamo, perché dopo lo
    # username di solito inizia un'altra pagina del sito (tipo /repositories)
    handle = re.split(r'[/?#]', remainder)[0]
    return handle or None


# Quante pagine da 1000 profili leggere al massimo per piattaforma: 10.000
# profili che iniziano come lo username bastano anche per "jack" e "apple";
# oltre, l'elenco resta segnato come incompleto.
_PAGINE_PREFISSO = 10

# Ricerca a pezzi (vedi discover_prefix_candidates): i caratteri che possono
# seguire lo username in un handle, in ORDINE ALFABETICO della CDX (conta:
# l'elenco vale fino all'ultima riga letta). Per ogni pezzo al massimo
# _PAGINE_PEZZO pagine, e in tutto al massimo _QUERY_MAX_PEZZI richieste.
_CARATTERI_DOPO_USERNAME = "-.0123456789_abcdefghijklmnopqrstuvwxyz"
_PAGINE_PEZZO = 5
_QUERY_MAX_PEZZI = 80


def _separa_chiave_ripresa(dati, limit):
    """Divide una risposta CDX JSON chiesta con showResumeKey=true.
    Il formato è: intestazione, righe, poi una riga vuota [] e infine
    [chiave] se ci sono altre pagine. Torna (righe, chiave o None, piena),
    dove piena = pagina con limit righe ma senza chiave (troncata e basta)."""
    righe, chiave = [], None
    corpo = list(dati or [])
    if corpo and corpo[0] and corpo[0][0] == "timestamp":
        corpo = corpo[1:]
    for i, riga in enumerate(corpo):
        if riga == []:
            dopo = corpo[i + 1] if i + 1 < len(corpo) else None
            if dopo and len(dopo) == 1:
                chiave = dopo[0]
            break
        if len(riga) == 1 and i == len(corpo) - 1:
            chiave = riga[0]     # chiave in fondo anche senza la riga vuota
            break
        righe.append(riga)
    piena = chiave is None and len(righe) >= limit
    return righe, chiave, piena


def _regex_sotto_profilo(url_base):
    """Regex sull'urlkey (l'indirizzo normalizzato di archive.org, tipo
    'com,github)/torvalds/linux') che riconosce le pagine SOTTO un profilo.
    Il '.*' iniziale e il '.+' finale la fanno valere sia se il server
    confronta tutta la stringa sia se cerca solo una corrispondenza."""
    percorso = url_base.split("/", 1)[1] if "/" in url_base else ""
    if percorso and not percorso.endswith(("/", "@")):
        percorso += "/"
    # esclude sia le pagine sotto il profilo (x/qualcosa) sia le varianti con
    # parametri (x?tab=..., x?hl=tr): sono lo stesso profilo ripetuto, e su
    # github.com/jack occupavano metà delle 10.000 righe lette. La query CDX
    # esatta sul profilo, del resto, non le vede: nessuna informazione persa.
    return r".*\)/" + re.escape(percorso.lower()) + r"[^/?]+[/?].+"


def _pagina_profilo(original_url, url_base):
    """Vero se l'URL è la pagina del profilo stessa (github.com/x o
    github.com/x/), falso se è una pagina sotto (github.com/x/linux) o una
    variante con parametri (github.com/x?tab=repositories)."""
    handle = _extract_handle(original_url, url_base)
    if not handle:
        return False
    cleaned = re.sub(r'^https?://(www\.)?', '', original_url)
    cleaned = re.sub(r'^([^/:?#]+):\d+', r'\1', cleaned)
    base_clean = re.sub(r'^https?://(www\.)?', '', url_base)
    resto = cleaned[len(base_clean):].lstrip('/@')[len(handle):]
    return resto in ("", "/")

# Caratteri ammessi in QUALSIASI username plausibile sulle piattaforme che
# monitoriamo (unione delle regole reali: GitHub ammette lettere/cifre/
# trattino fino a 39 caratteri, Twitter/X lettere/cifre/underscore fino a
# 15, Reddit anche il trattino fino a 20, Instagram e TikTok anche il punto
# fino a 30, Telegram lettere/cifre/underscore da 5 in su). Non è una
# validazione perfetta piattaforma per piattaforma, ma basta a riconoscere
# quando NON è affatto uno username.
_USERNAME_PLAUSIBILE = re.compile(r'[A-Za-z0-9_.\-]{1,39}')

# "username" che in realtà sono nomi di file archiviati (github.com/jack.json
# è un file, non una persona): il punto è un carattere legittimo su
# Instagram/TikTok, quindi non basta scartare tutti i punti - scartiamo solo
# quando finisce con una di queste estensioni note.
_ESTENSIONI_FILE = (
    ".html", ".htm", ".json", ".xml", ".php", ".asp", ".aspx", ".js", ".css",
    ".txt", ".atom", ".rss", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".pdf",
)


def _handle_plausibile(handle):
    """Vero solo se 'handle' potrebbe davvero essere uno username su una
    delle piattaforme monitorate.

    Serve perché _extract_handle si ferma solo su '/', '?' o '#': se un
    URL archiviato è malformato o dinamico (capita con pagine di
    condivisione/redirect, es. su Instagram) e continua con altri
    caratteri (virgole, due punti, virgolette codificate '%22', spazi
    '%20'...), _extract_handle prende TUTTO il resto della stringa come se
    fosse lo username - scoperto provando lo username 'jack' (comunissimo,
    quindi con tantissimi URL archiviati anche strani). Questo controllo
    scarta quella spazzatura prima che diventi un "candidato" da
    verificare (ogni candidato falso costa 9 richieste di rete a vuoto).

    I controlli, in ordine, e da dove vengono le regole:
      1. solo caratteri ammessi e max 39 (fullmatch, non match: con 'match'
         una stringa tipo 'jack\\n' sarebbe passata, perché '$' in Python
         accetta anche un a-capo finale);
      2. non può iniziare/finire con '.' o '-' (GitHub vieta il trattino
         a inizio/fine, Instagram e TikTok vietano il punto a inizio/fine);
         l'underscore invece a bordo è legittimo (es. '_jack' su Twitter);
      3. niente '..' o '--' di fila (vietati rispettivamente da Instagram
         e da GitHub);
      4. niente estensioni di file (vedi _ESTENSIONI_FILE): sono pagine
         archiviate, non profili di persone.
    """
    if not handle or not _USERNAME_PLAUSIBILE.fullmatch(handle):
        return False
    if handle[0] in ".-" or handle[-1] in ".-":
        return False
    if ".." in handle or "--" in handle:
        return False
    if handle.lower().endswith(_ESTENSIONI_FILE):
        return False
    return True


# Quante righe chiedere alla ricerca per prefisso. Era 150, e per gli username
# affollati (jack: 221 candidati, sama: 179, nike: 269) la lista usciva
# TRONCATA. Da una lista troncata non si può dedurre che un candidato NON
# esista su una piattaforma, quindi il risparmio di _check_platforms si
# spegneva proprio dove serviva di più, e ogni candidato costava 9 richieste
# invece di 1-2. Una risposta più lunga costa una richiesta; una lista
# troncata ne costa decine.
LIMITE_PREFISSO = 1000

# VERIFICA A CAMPIONE del controllo 404: su una parte dei "404" si fa lo
# stesso la query CDX, per misurare durante le prove vere quante volte il 404
# sbaglia. La scelta è deterministica (crc32 di piattaforma+candidato), così
# è ripetibile e non dipende dal caso. Ogni verifica finisce in
# FILE_VERIFICA_404; se la CDX trova catture si usano quelle (nessuna perdita).
QUOTA_VERIFICA_404 = 0.10
FILE_VERIFICA_404 = "verifica_404_campione.csv"


def _da_verificare_404(plat, candidato, quota=None):
    import zlib
    quota = QUOTA_VERIFICA_404 if quota is None else quota
    if quota <= 0:
        return False
    return (zlib.crc32(f"{plat}|{candidato}".lower().encode()) % 1000) < quota * 1000


def _registra_verifica_404(indagato, plat, candidato, catture):
    import csv, os
    nuovo = not os.path.exists(FILE_VERIFICA_404)
    with open(FILE_VERIFICA_404, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if nuovo:
            w.writerow(["data", "indagato", "piattaforma", "candidato",
                        "catture_cdx", "esito"])
        w.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), indagato, plat,
                    candidato, catture, "SBAGLIATO" if catture else "ok"])


def discover_prefix_candidates(url_base, username, session, delay=1.5, timeout=25,
                               limit=LIMITE_PREFISSO, con_limite=False):
    """Chiede alla CDX API quali pagine sono state DAVVERO archiviate sotto
    {piattaforma}/{username}* (matchType=prefix): a differenza delle varianti
    tirate a indovinare, qui i candidati sono garantiti - sono esistiti per
    davvero, non sono ipotesi. E costa solo 1 richiesta per piattaforma.

    Limite: prende solo le varianti che iniziano UGUALE allo username
    originale (tipo suffissi: torvalds1, torvaldsofficial). Se lo username
    cambia all'inizio non lo becca - per quei casi ci pensa la generazione
    a naso (osint_variants.generate_variants).
    """
    if len(username) < 3:
        # username troppo corto: la ricerca per prefisso rischia di tirar su
        # centinaia di pagine a caso che iniziano allo stesso modo, quindi
        # in quel caso rinunciamo
        return ([], set(), False, {}, None) if con_limite else ([], set(), False, {})

    prefix_target = _target_url(url_base, username)
    # stessa CDX API di prima, ma con matchType=prefix: invece di cercare
    # l'URL esatto, cerca tutti gli URL che INIZIANO così
    cdx_url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url={prefix_target}&matchType=prefix&collapse=urlkey"
        f"&output=json&fl=timestamp,original,statuscode,mimetype&limit={limit}"
        + rete.filtri_server()
    )
    # SOLO I PROFILI. Sotto github.com/torvalds* ci sono migliaia di pagine
    # del repository torvalds/linux, sotto twitter.com/torvalds* i singoli
    # tweet: la CDX le restituisce in ordine alfabetico e riempivano da sole
    # il limite di 1000 righe, così l'elenco si troncava e i candidati che
    # venivano dopo (torvaldsx, torvaldsz, ...) non si vedevano. Con
    # questo filtro è archive.org a scartare le pagine SOTTO un profilo.
    # Verificato sul servizio vero: dove l'elenco
    # non era troncato dà gli stessi profili; su twitter.com/torvalds ne ha
    # trovati 4 che prima non si vedevano; github.com/antirez è passato da
    # 1000 righe troncate a 92 complete. Su github.com/torvalds però il
    # server non ce la fa (504 dopo 60 s, deve scorrere tutto il repository
    # linux): allora si ripiega sulla query di prima, con l'elenco troncato
    # e segnato come inaffidabile - cioè esattamente come prima, non peggio.
    filtrata = cdx_url + "&filter=" + quote(
        "!urlkey:" + _regex_sotto_profilo(url_base), safe="")

    handles = set()  # un set, così i doppioni si scartano da soli
    # visti = TUTTI gli handle archiviati sotto questo prefisso, compreso lo
    # username originale. handles invece tiene solo le VARIANTI (serve a
    # generare i candidati). Con visti sappiamo, senza altre richieste, se un
    # dato handle è archiviato o no su questa piattaforma - originale incluso,
    # ed è ciò che permette di risparmiare anche richieste della baseline.
    visti = set()
    # prime = per ogni handle, la sua PRIMA cattura (timestamp, url originale).
    # Con collapse=urlkey la CDX restituisce una riga per indirizzo, la più
    # vecchia: è esattamente la data d'inizio che serve a temporal_overlap, e
    # arriva gratis con la ricerca per prefisso. La data di fine la dà la
    # pagina (vedi osint_rete.ultima_cattura).
    prime = {}
    # affidabile = la CDX ha risposto 200 e non ha troncato l'elenco. Solo in
    # quel caso "questo handle non c'è" è un'informazione su cui si può
    # contare per saltare richieste dopo (vedi _check_platforms).
    affidabile = False
    righe_lette = 0

    # PAGINE. Anche con il filtro, per username molto comuni i profili sono
    # più di 1000 (jack: github 437 candidati ma elenco troncato, t.me 992...).
    # Un elenco troncato costava carissimo: per OGNI candidato bisognava poi
    # interrogare con CDX tutte le piattaforme troncate (su jack, 8 query a
    # candidato: circa 14 ore). Con showResumeKey la CDX restituisce, insieme
    # alle prime 1000 righe, una chiave per chiedere le successive: si legge
    # l'elenco completo in poche pagine e da lì in poi si sa già dove esiste
    # ogni candidato, senza altre query.
    def leggi_pagine(prima_url, etichetta, max_pagine):
        """Legge un elenco a pagine (showResumeKey). Torna (righe, completo,
        pagine), oppure (None, esito, 0) se non arriva nemmeno la prima."""
        d, es = rete.richiesta_cdx(prima_url, session, delay, timeout,
                                   f"{url_base} ({etichetta})",
                                   dove_errore=url_base, facoltativa=True)
        if d is None:
            return None, es, 0
        righe, chiave, piena = _separa_chiave_ripresa(d, limit)
        pagine = 1
        while chiave and pagine < max_pagine:
            altre, _ = rete.richiesta_cdx(
                prima_url + "&resumeKey=" + quote(chiave, safe=""), session, delay, timeout,
                f"{url_base} ({etichetta}, pagina {pagine + 1})",
                dove_errore=url_base, facoltativa=True)
            if altre is None:
                break          # pagina non arrivata: l'elenco resta incompleto
            nuove, chiave, piena = _separa_chiave_ripresa(altre, limit)
            righe.extend(nuove)
            pagine += 1
        # incompleto se restano pagine da leggere, oppure se una pagina piena
        # è arrivata SENZA chiave (il server avrebbe ignorato showResumeKey)
        return righe, not (chiave or piena), pagine

    # PAGINE. Anche con il filtro, per username molto comuni i profili sono
    # più di 1000. Con showResumeKey la CDX restituisce, insieme alle prime
    # 1000 righe, una chiave per chiedere le successive: si legge l'elenco
    # completo in poche pagine e da lì in poi si sa già dove esiste ogni
    # candidato, senza altre query.
    pagina1 = filtrata + "&showResumeKey=true"
    righe, completo, pagine = leggi_pagine(pagina1, "prefix, solo profili", _PAGINE_PREFISSO)
    paginata = righe is not None
    esito = "ok" if paginata else completo

    if not paginata and esito in ("http-504", "troppo-lento"):
        # ELENCO A PEZZI. Un 504 qui vuol dire che sotto {username}/ c'è un
        # sottoalbero enorme che il server deve scorrere tutto (twitter.com/jack:
        # tutti i tweet di Jack Dorsey). Visto su jack: senza elenco, OGNI
        # candidato richiedeva una query CDX su twitter.com, circa un minuto a
        # candidato. Ma i candidati sono jack0*, jacka*, jack_* ...: si chiede
        # un pezzo per ogni carattere che può seguire lo username, e nessun
        # pezzo contiene il sottoalbero pesante (che sta sotto "jack/").
        # I pezzi si leggono in ordine alfabetico: se uno non arriva o resta
        # incompleto ci si ferma lì, e l'elenco vale fino all'ultima riga letta.
        print(f"    [i] {url_base}: la ricerca dei soli profili non ha risposto "
              f"({esito}): la divido in pezzi per carattere")
        righe, completo, fatte = [], True, 0
        for c in _CARATTERI_DOPO_USERNAME:
            if fatte >= _QUERY_MAX_PEZZI:
                completo = False
                break
            sub_url = (cdx_url.replace(f"url={prefix_target}&",
                                       f"url={_target_url(url_base, username + c)}&", 1)
                       + "&filter=" + quote("!urlkey:" + _regex_sotto_profilo(url_base), safe="")
                       + "&showResumeKey=true")
            r, comp, p = leggi_pagine(sub_url, f"prefix {username}{c}*", _PAGINE_PEZZO)
            fatte += max(p, 1)
            if r is None:
                completo = False
                break
            righe.extend(r)
            if not comp:
                completo = False
                break
        print(f"    [i] {url_base}: elenco a pezzi {'completo' if completo else 'incompleto'} "
              f"({fatte} richieste, {len(righe)} righe)")
        dati = [["timestamp", "original", "statuscode", "mimetype"]] + righe
        affidabile = completo
    else:
        if not paginata and esito not in ("rete-a-terra",):
            print(f"    [i] {url_base}: la ricerca dei soli profili non ha risposto "
                  f"({esito}), uso quella completa (può essere troncata)")
            dati, esito = rete.richiesta_cdx(cdx_url, session, delay, timeout,
                                             f"{url_base} (prefix)", dove_errore=url_base)

        if esito in ("rete-a-terra", "errore-rete", "troppo-lento"):
            if esito == "errore-rete":
                print(f"[!] {url_base}: errore ricerca per prefisso, salto.")
            return ([], set(), False, {}, None) if con_limite else ([], set(), False, {})
        if esito.startswith("http-"):
            # un codice diverso da 200 non è "nessun candidato trovato"
            print(f"[!] {url_base}: la Wayback Machine ha risposto con codice "
                  f"{esito[5:]}, salto la ricerca per prefisso.")
            return ([], set(), False, {}, None) if con_limite else ([], set(), False, {})
        if esito == "json-rotto":
            print(f"[!] {url_base}: risposta della Wayback Machine ricevuta ma "
                  f"JSON corrotto/troncato, salto la ricerca per prefisso.")
            return ([], set(), False, {}, None) if con_limite else ([], set(), False, {})

        # Un 200 è attendibile ANCHE con corpo vuoto: vuol dire "sotto questo
        # prefisso non c'è nulla", che è l'informazione più utile di tutte
        # perché permette di escludere la piattaforma per tutti i candidati che
        # iniziano come lo username.
        affidabile = True
        if paginata:
            if pagine > 1:
                print(f"    [i] {url_base}: elenco dei profili letto in {pagine} pagine "
                      f"({len(righe)} righe)")
            if not completo:
                affidabile = False
                print(f"    [i] {url_base}: elenco dei profili incompleto "
                      f"({len(righe)} righe lette): i candidati andranno verificati con CDX")
            dati = [["timestamp", "original", "statuscode", "mimetype"]] + righe
        else:
            dati = dati or []
            righe_lette = max(0, len(dati) - 1)
            # se la CDX ha restituito esattamente il massimo chiesto, l'elenco è
            # probabilmente TRONCATO: allora l'assenza di un handle non prova niente
            if righe_lette >= limit:
                affidabile = False
    for row in dati[1:]:
        try:
            timestamp, original, statuscode, mimetype = row
        except (ValueError, TypeError):
            continue
        if statuscode != '200' or 'text/html' not in mimetype:
            continue
        handle = _extract_handle(original, url_base)
        if handle:
            visti.add(handle.lower())
            # La prima cattura si prende SOLO dalla pagina del profilo, non da
            # una pagina sotto (github.com/x/un-repo, medium.com/@x/un-articolo).
            # Serve per due motivi: la data deve essere quella del profilo,
            # come la darebbe la query CDX esatta; e da questo indirizzo si
            # chiede poi l'ultima cattura (ultima_cattura), cioè la pagina da
            # cui si leggono nome e bio - che altrimenti sarebbero stati il
            # titolo e la descrizione di un repository o di un articolo.
            # Se del profilo non c'è nessuna riga, niente data: si ripiega
            # sulla query CDX esatta, come prima.
            if _pagina_profilo(original, url_base):
                gia = prime.get(handle.lower())
                if gia is None or timestamp < gia[0]:
                    prime[handle.lower()] = (timestamp, original)
        # lo username originale non è una "variante", e scartiamo anche
        # tutto ciò che non è plausibile come username (caso 'jack')
        if handle and handle.lower() != username.lower() and _handle_plausibile(handle):
            handles.add(handle)

    # ordiniamo mettendo per primi quelli più simili allo username originale
    # (così chi legge l'output vede prima i candidati più probabili)
    ordinati = sorted(handles,
                      key=lambda h: -SequenceMatcher(None, username.lower(), h.lower()).ratio())
    if con_limite:
        # FIN DOVE L'ELENCO È SICURO. Anche un elenco incompleto è completo
        # fino all'ultima riga letta, perché la CDX lo restituisce in ordine
        # alfabetico: se l'ultima riga è github.com/jackx, ogni handle
        # che viene prima (jack1, jackal, jacks...) o è nell'elenco o non è
        # archiviato. Solo per gli handle DOPO serve la query CDX.
        fino_a = None
        if not affidabile:
            ultimi = [r for r in dati[1:] if len(r) == 4]
            if ultimi:
                fino_a = (_extract_handle(ultimi[-1][1], url_base) or "").lower() or None
            if fino_a is None:
                fino_a = ""        # niente di sicuro
        return ordinati, visti, affidabile, prime, fino_a
    return ordinati, visti, affidabile, prime


class OsintUsernameInvestigator:
    # Quante varianti "a naso" (leetspeak, separatori) verificare per ogni
    # indagine. Hanno un budget LORO, fisso, invece di prendere i posti avanzati
    # dopo la ricerca per prefisso. Nel batch da 100 avveniva il contrario, e la
    # loro resa risultava falsata in due modi: venivano provate soprattutto
    # sugli username con pochi risultati (in media 8 posti su chi era presente
    # su <=3 piattaforme, 2,4 su chi era presente su >=5, e 98 su 213 sulle
    # stringhe inventate), e ogni variante che esisteva davvero e iniziava come
    # lo username veniva trovata prima dal prefisso e contata lì. Con un budget
    # fisso ogni username ne prova lo stesso numero, e la resa si può misurare.
    max_euristiche = 3
    senza_euristiche = False
    campione_oltre_limite = 0
    # Date dei candidati senza CDX: prima cattura dalla ricerca per prefisso,
    # ultima dal reindirizzamento della pagina (vedi _snapshot_senza_cdx).
    date_da_pagina = True
    controllo_404 = False      # vedi --controllo-404
    candidati_prefisso_trovati = 0
    candidati_prefisso_verificati = 0
    """
    Questa è la classe che manda avanti tutta l'indagine, passo per passo:

      1. tira su gli snapshot dello username originale su tutte le
         piattaforme (la "baseline");
      2. sceglie una piattaforma "di riferimento" (quella con più storia
         alle spalle) e controlla anche gli altri match con lo stesso
         username confrontandoli con quella, invece di fidarsi a scatola
         chiusa;
      3. trova candidati VERI cercando per prefisso su Wayback, e ne
         aggiunge altri IPOTIZZATI a naso;
      4. ricontrolla ogni candidato sulle stesse piattaforme;
      5. dà un punteggio a ogni candidato trovato e ci appiccica sopra
         nome/bio/foto/link, se ci sono;
      6. mette tutto insieme nella scheda persona finale ed esporta
         CSV + JSON.
    """

    def __init__(self, username, nome=None, cognome=None, platforms=None,
                 max_candidates=15, delay=1.5, timeout=25):
        self.username = username
        self.nome = nome
        self.cognome = cognome
        self.platforms = platforms or DEFAULT_PLATFORMS
        self.max_candidates = max_candidates
        self.delay = delay
        self.timeout = timeout
        # Cosa ha visto la ricerca per prefisso su ogni piattaforma:
        #   piattaforma -> set di handle trovati   (elenco attendibile)
        #   piattaforma -> None                    (non lo sappiamo)
        # Serve a non richiedere due volte la stessa informazione: vedi
        # _check_platforms.
        self._prefisso_per_piattaforma = {}
        self._prime_catture = {}
        self._prefisso_fino_a = {}
        self.uno_per_giorno = True   # vedi fetch_snapshots
        self.session = rete.build_session()

        # questi si riempiono man mano che l'indagine va avanti, li teniamo
        # come attributi così i vari metodi (le "fasi") se li passano da soli
        self.baseline_snapshots = []   # tutti gli snapshot con username esatto, su ogni piattaforma
        self.anchor_platform = None    # la piattaforma scelta come "quella vera", il riferimento
        self.anchor_snapshots = []     # gli snapshot solo di quella piattaforma
        self.anchor_profile = None     # nome/bio/foto/link presi dal riferimento
        self.rows = []                 # tutte le righe di risultato, quelle che poi finiscono nel CSV
        self.person_summary = None     # la scheda persona finale (un dict)

    def _check_platforms(self, target_username):
        """Cerca questo username su tutte le piattaforme, UNA ALLA VOLTA,
        e torna tutti gli snapshot trovati in una lista sola.

        Le richieste partono in fila, non insieme: è una scelta. Una
        versione che le mandava a gruppi era 3 volte più veloce, ma
        alzava troppo il ritmo verso archive.org, che dopo un po'
        rifiutava le connessioni - e un'indagine con metà delle
        richieste fallite produce punteggi calcolati su dati mancanti,
        numeri che sembrano validi e non lo sono. Meglio lenta che
        inaffidabile."""
        snapshots = []
        saltate = 0
        senza_cdx = 0
        non_archiviati = 0
        chiave = target_username.lower()
        per_prefisso = chiave.startswith(self.username.lower())
        for plat in self.platforms:
            # RISPARMIO SENZA PERDITE. La ricerca per prefisso ha già chiesto
            # ad archive.org l'elenco completo di ciò che è archiviato sotto
            # {piattaforma}/{username}*: se l'elenco era attendibile e il
            # candidato inizia come lo username ma non c'è, non è archiviato
            # qui, e richiederlo darebbe di sicuro zero snapshot.
            noti = self._prefisso_per_piattaforma.get(plat)
            fino_a = self._prefisso_fino_a.get(plat)
            # l'elenco copre questo candidato se è completo, oppure se il
            # candidato viene alfabeticamente prima dell'ultima riga letta
            coperto = noti is not None and (fino_a is None or chiave <= fino_a)
            if per_prefisso and coperto and chiave not in noti:
                saltate += 1
                continue
            # SENZA CDX, quando si può: la prima cattura la sappiamo già, e
            # l'ultima arriva con la pagina, che si scarica comunque.
            prime = self._prime_catture.get(plat)
            if self.date_da_pagina and prime is not None and chiave in prime:
                trovati = self._snapshot_senza_cdx(plat, target_username, *prime[chiave])
                if trovati is not None:
                    snapshots.extend(trovati)
                    senza_cdx += 1
                    continue
            # CONTROLLO VELOCE (--controllo-404): prima della query CDX si chiede
            # all'archivio se ha qualcosa per questo indirizzo. Se risponde 404
            # la query CDX darebbe zero snapshot: si salta. Usato solo dopo
            # averlo verificato sul servizio vero.
            if self.controllo_404 and rete.archiviato(
                    _target_url(plat, target_username), self.session, self.delay,
                    self.timeout, dove=f"{plat} (controllo 404)") is False:
                if not _da_verificare_404(plat, target_username):
                    non_archiviati += 1
                    continue
                # verifica a campione: la query CDX si fa lo stesso
                perdite_prima = rete.errori_rete.dati_persi
                trovati = fetch_snapshots(plat, target_username, self.session,
                                          delay=self.delay, timeout=self.timeout,
                                          uno_per_giorno=self.uno_per_giorno)
                if rete.errori_rete.dati_persi == perdite_prima:
                    _registra_verifica_404(self.username, plat, target_username,
                                           len(trovati))
                    if trovati:
                        print(f"    [!] controllo 404 SBAGLIATO su {_target_url(plat, target_username)}: "
                              f"la CDX ha {len(trovati)} catture (usate quelle)")
                snapshots.extend(trovati)
                continue
            snapshots.extend(
                fetch_snapshots(plat, target_username, self.session,
                                 delay=self.delay, timeout=self.timeout,
                                 uno_per_giorno=self.uno_per_giorno)
            )
        if senza_cdx:
            print(f"    [i] date prese dalla pagina senza query CDX su {senza_cdx} "
                  f"piattaforma/e")
        if saltate:
            print(f"    [i] {saltate} piattaforme non interrogate: la ricerca "
                  f"per prefisso le ha già escluse per questo candidato")
        if non_archiviati:
            print(f"    [i] {non_archiviati} piattaforme escluse dal controllo veloce (404)")
        return snapshots

    def _snapshot_senza_cdx(self, plat, target, prima_ts, prima_orig):
        """Gli snapshot di un candidato su una piattaforma, SENZA query CDX.

        Servono solo la prima e l'ultima data, perché temporal_overlap usa
        soltanto gli estremi del periodo (_snapshot_bounds prende min e max):
        il segnale è identico a quello calcolato sull'elenco completo.
          - la prima cattura la ha già data la ricerca per prefisso;
          - l'ultima la dà il reindirizzamento di Wayback (ultima_cattura), e
            la pagina scaricata per saperla è la stessa che serve per nome e
            bio: resta in cache e non si riscarica.
        Torna None quando bisogna ripiegare sulla query CDX: se l'indirizzo
        finale non ha una data leggibile, oppure se porta a un ALTRO account
        (un account rinominato: la pagina e le date sarebbero dell'account
        nuovo, non del candidato).
        """
        etichetta = _platform_label(plat)

        def snapshot(ts, url):
            dt = datetime.strptime(ts[:14], '%Y%m%d%H%M%S')
            return {'Piattaforma': etichetta,
                    'Data_Salvataggio': dt.strftime('%Y-%m-%d %H:%M:%S'),
                    'URL_Archivio': url, 'Fonte_Date': 'prefisso+pagina'}

        prima = snapshot(prima_ts, f"https://web.archive.org/web/{prima_ts}/{prima_orig}")
        perdite_prima = rete.errori_rete.dati_persi
        esito = rete.ultima_cattura(prima_orig, self.session, self.delay, self.timeout,
                                    dove=f"{plat} (ultima cattura)")
        if esito is None:
            if rete.errori_rete.dati_persi > perdite_prima:
                # perdita di rete, già registrata: si tiene la prima data, e
                # l'indagine risulterà incompleta e verrà ripresa
                return [prima]
            return None                      # data illeggibile: si usa CDX
        url_finale, ts_finale, _ = esito
        m = rete._RE_ARCHIVIO.match(url_finale)
        handle_finale = _extract_handle(m.group(2), plat) if m else None
        if not handle_finale or handle_finale.lower() != target.lower():
            print(f"    [i] {plat}: l'ultima cattura di '{target}' porta a "
                  f"'{handle_finale}' (account rinominato?): uso la query CDX")
            return None
        if ts_finale[:8] == prima_ts[:8]:
            return [prima]
        return [prima, snapshot(ts_finale, url_finale)]

    def _profile_data_for(self, snapshots, max_pages=1, tentativi_extra=2, handle=None):
        """Scarica poche pagine archiviate e ne tira fuori nome/bio/foto/link.

        Quali pagine sceglie, e perché:

        1. UNA SOLA PIATTAFORMA. La lista che arriva può mescolare
           piattaforme diverse (in fase 3, _check_platforms concatena i
           risultati di tutte e 9), e mescolarle sarebbe un guaio: la bio
           finirebbe presa da una piattaforma a caso (magari TikTok) e poi
           confrontata con quella dell'ancora (magari GitHub), facendo
           crollare content_similarity per un motivo che non c'entra
           niente con l'identità della persona. Quindi teniamo solo gli
           snapshot della piattaforma con più evidenza storica nella
           lista - stesso criterio dell'ancora (_select_anchor).
        2. I PIÙ RECENTI DI QUELLA PIATTAFORMA. La CDX API di solito li
           dà dal più vecchio al più recente, ma non è garantito, e lo
           snapshot più vecchio spesso è il più povero (profilo appena
           creato); ordiniamo noi per data decrescente.
        3. SE LA PAGINA PIÙ RECENTE NON DÀ NIENTE, si riprova con una
           più vecchia (fino a `tentativi_extra` volte in più). Serve
           perché gli snapshot recenti dei social a volte sono gusci
           vuoti pieni di JavaScript o pagine di cookie: senza questo
           ripiego, un profilo con dati buoni nel 2014 e un guscio vuoto
           nel 2024 risulterebbe senza nome/bio. Chi trova subito il dato
           buono (il caso normale) fa comunque UNA sola richiesta.
        """
        # 'da_*' = da QUALE snapshot viene quel campo. Serve perché i campi
        # si riempiono a "primo che trova vince" su pagine prese
        # deliberatamente agli estremi della storia dell'account: il nome può
        # venire dal 2024 e la bio dal 2013. Senza queste date la scheda
        # persona descrive qualcuno che non è mai esistito in nessun momento
        # singolo, e non c'è modo di accorgersene leggendo l'output. Con le
        # date il problema resta, ma diventa visibile e dichiarabile - e conta
        # perché content_similarity confronta bio che possono essere lontane
        # anni: un punteggio basso può voler dire "persone diverse" oppure
        # "stessa persona, dieci anni dopo", e la formula non distingue.
        empty = {"nome_rilevato": "", "bio_rilevata": "", "foto_url": "",
                 "link_esterni": [], "content_snippet": "",
                 "nome_da": "", "bio_da": "", "foto_da": "", "scartate": 0,
                 "foto_hash": None, "foto_motivo": ""}
        if not snapshots:
            return empty

        # 1. una sola piattaforma: quella con più snapshot in questa lista
        per_piattaforma = {}
        for s in snapshots:
            per_piattaforma.setdefault(s.get("Piattaforma", ""), []).append(s)
        # a parità di numero di snapshot, quella con la storia più lunga:
        # con le date prese senza CDX ogni piattaforma ha al massimo 2 snapshot
        # (prima e ultima cattura), e senza questo criterio la scelta sarebbe
        # caduta sulla prima dell'elenco
        scelti = max(per_piattaforma.values(),
                     key=lambda l: (len(l), _durata(l)))
        profilo_da = scelti[0].get("Piattaforma", "")

        # 2. i più recenti per primi
        snapshots_ordinati = sorted(scelti, key=lambda s: s['Data_Salvataggio'], reverse=True)

        # 3. scegliamo QUALI pagine provare. Non le prime N di fila: se un
        # account ha tanti snapshot recenti tutti uguali (es. decine di
        # pagine x.com che sono solo muri di login o gusci JavaScript), tre
        # tentativi consecutivi finirebbero tutti lì dentro e tornerebbero
        # a mani vuote, senza mai arrivare alle pagine più vecchie che
        # invece i dati ce li hanno. Quindi il primo tentativo resta il più
        # recente (il caso normale: se è buono finisce lì e costa UNA
        # richiesta), ma quelli di riserva sono distribuiti lungo tutta la
        # storia dell'account invece di stare appiccicati al primo.
        tentativi = max_pages + tentativi_extra
        if len(snapshots_ordinati) > tentativi and tentativi > 1:
            # indici distribuiti da un estremo all'altro: il primo è sempre
            # lo snapshot più RECENTE e l'ultimo sempre il più VECCHIO,
            # gli altri spalmati in mezzo. Prendere invece campioni a
            # intervalli regolari senza ancorare la fine non basta: con 20
            # pagine vuote davanti e 2 buone in fondo, i campioni cadrebbero
            # tutti dentro le prime 20 e le buone non verrebbero mai lette.
            ultimo = len(snapshots_ordinati) - 1
            indici = sorted({round(i * ultimo / (tentativi - 1)) for i in range(tentativi)})
            da_provare = [snapshots_ordinati[i] for i in indici]
        else:
            da_provare = snapshots_ordinati

        aggregato = dict(empty)   # copia di 'empty' che riempiamo man mano
        aggregato["link_esterni"] = []
        snippets = []
        pagine_utili = 0
        # ci fermiamo appena abbiamo max_pages pagine che hanno dato qualcosa
        # 4. RIPIEGO SULLE COPIE VECCHIE DI TWITTER. Per i candidati verificati
        # senza CDX si conosce solo la copia più recente, e per Twitter/X le
        # copie recenti sono quasi sempre gusci JavaScript senza nome né bio:
        # il profilo c'era, ma la copia letta non lo mostra (lo si vede
        # aprendo una copia vecchia). Se nessuna pagina ha dato niente, si
        # chiede UNA pagina in più: la copia più vicina al 1 gennaio 2020,
        # quando twitter.com era ancora una pagina normale. Costa una
        # richiesta solo in questo caso, e non serve la CDX.
        riserva = _copia_di_riserva(profilo_da, handle or self.username, snapshots_ordinati)
        i = 0
        while i < len(da_provare) or (riserva and pagine_utili == 0):
            if i >= len(da_provare):
                da_provare = list(da_provare) + [riserva]
                riserva = None
            s = da_provare[i]
            i += 1
            if pagine_utili >= max_pages:
                break
            own_domain = domain_from_archive_url(s['URL_Archivio'])
            # il download passa dalla cache e aspetta il suo turno nella fila
            # globale solo se deve partire per davvero
            html = rete.pagina_archiviata(s['URL_Archivio'], self.session,
                                          self.delay, self.timeout)
            campi = extract_profile_fields(html, own_domain=own_domain, handle=handle)

            # prendiamo nome/bio/foto solo se non li abbiamo già trovati
            # prima (così non sovrascriviamo un dato buono con uno vuoto)
            # pagina segnaposto ("lapide"): vale come pagina vuota e si passa
            # al tentativo successivo, più indietro nella storia dell'account
            if campi.get("motivo_scarto"):
                aggregato["scartate"] += 1
                print(f"    [i] {s['Data_Salvataggio'][:10]}: pagina segnaposto "
                      f"scartata ({campi['motivo_scarto']}), provo uno snapshot "
                      f"più vecchio")
                continue
            if not aggregato["nome_rilevato"] and campi["nome_rilevato"]:
                aggregato["nome_rilevato"] = campi["nome_rilevato"]
                aggregato["nome_da"] = s["Data_Salvataggio"][:10]
            if not aggregato["bio_rilevata"] and campi["bio_rilevata"]:
                aggregato["bio_rilevata"] = campi["bio_rilevata"]
                aggregato["bio_da"] = s["Data_Salvataggio"][:10]
            if not aggregato["foto_url"] and campi["foto_url"]:
                aggregato["foto_url"] = campi["foto_url"]
                aggregato["foto_da"] = s["Data_Salvataggio"][:10]
            # i link esterni invece li accumuliamo tutti (poi tolgo i doppioni sotto)
            aggregato["link_esterni"].extend(campi["link_esterni"])
            if campi["content_snippet"]:
                snippets.append(campi["content_snippet"])
                pagine_utili += 1   # questa pagina ha dato qualcosa, conta

        # hash della foto scelta: una richiesta in più solo se una foto c'è
        if aggregato["foto_url"]:
            # l'username registrato con l'hash deve essere quello del PROFILO,
            # non quello dell'indagine: la guardia sugli avatar di default conta
            # su quanti username DIVERSI compare lo stesso hash, e con lo
            # username dell'indagine gli avatar grigi di Reddit visti su due
            # candidati diversi risultavano "un solo username"
            aggregato["foto_hash"], aggregato["foto_motivo"] = rete.hash_foto(
                aggregato["foto_url"], handle or self.username, self.session,
                self.delay, self.timeout)
        else:
            aggregato["foto_motivo"] = "nessuna foto nel profilo"

        aggregato["content_snippet"] = " | ".join(snippets)
        aggregato["profilo_da"] = profilo_da
        # dict.fromkeys() è un trucchetto per togliere i doppioni mantenendo
        # l'ordine, poi teniamo solo i primi 5 link
        aggregato["link_esterni"] = list(dict.fromkeys(aggregato["link_esterni"]))[:5]
        return aggregato

    def _somiglianza_foto(self, profilo):
        """Quanto la foto di questo profilo somiglia a quella dell'ancora, con
        la guardia sugli avatar di default applicata.

        La guardia sta QUI e non in osint_foto perché ha bisogno del censimento
        in cache, cioè di cosa si è visto nelle indagini precedenti: un hash
        che compare su molti username diversi è la sagoma grigia che la
        piattaforma dà a tutti, e come indizio non vale niente. È la stessa
        logica per cui uno username comune non identifica nessuno.
        """
        mio = profilo.get("foto_hash")
        suo = (self.anchor_profile or {}).get("foto_hash")
        if mio is None or suo is None:
            return 0.0
        censimento = rete.cache.censimento_foto()
        for h, etichetta in ((mio, "candidato"), (suo, "ancora")):
            distintivo, quanti = osint_foto.hash_distintivo(h, censimento)
            if not distintivo:
                print(f"    [i] foto del {etichetta} ignorata: lo stesso avatar "
                      f"compare su {quanti} username diversi (probabile immagine "
                      f"di default della piattaforma)")
                return 0.0
        return osint_foto.somiglianza(mio, suo)

    def _select_anchor(self):
        """Sceglie, tra le piattaforme dove abbiamo trovato lo username
        esatto, quella da usare come "riferimento" per tutti i confronti
        dopo.

        Perché serve: se trovi lo stesso username su due piattaforme
        diverse NON vuol dire automaticamente che sia la stessa persona
        (uno username comune può essere stato preso da qualcun altro
        altrove - tipo 'torvalds' su Medium potrebbe benissimo NON essere
        Linus Torvalds). Quindi scegliamo come "ancora" la piattaforma con
        più storia alle spalle (più snapshot = presenza più solida nel
        tempo), e le ALTRE piattaforme con lo stesso username le
        controlliamo contro questa ancora, con lo stesso punteggio che
        usiamo per le varianti - non le diamo per buone a prescindere."""
        # raggruppiamo gli snapshot per piattaforma: {"github": [...], "medium": [...]}
        per_piattaforma = {}
        for s in self.baseline_snapshots:
            per_piattaforma.setdefault(s["Piattaforma"], []).append(s)

        if not per_piattaforma:
            return None, []   # username non trovato da nessuna parte

        # prendiamo la piattaforma con la lista di snapshot più lunga
        anchor_platform = max(per_piattaforma.items(), key=lambda kv: len(kv[1]))[0]
        return anchor_platform, per_piattaforma[anchor_platform]

    @staticmethod
    def _riga_baseline(plat, trovati):
        """Scrive la riga di riepilogo di una piattaforma, distinguendo il
        caso "non c'è niente" dal caso "non sono riuscito a chiedere".

        Prima erano tutti e due '0 snapshot', e leggendo l'output non si
        capiva la differenza - ma per l'indagine è enorme: uno zero vero
        dice che lo username lì non esiste, uno zero da errore non dice
        proprio niente."""
        if plat in rete.errori_rete.piattaforme_fallite:
            return f"[baseline] {plat}: NON CONTATTABILE (dato mancante, non uno zero)"
        return f"[baseline] {plat}: {len(trovati)} snapshot"

    def _raccogli_baseline(self):
        """Fase 1: si va a cercare lo username originale su tutte le
        piattaforme."""
        print(f"\n=== Baseline: {self.username} ===")
        print(f"[...] interrogo {len(self.platforms)} piattaforme, una alla volta")

        # Le richieste partono in fila, non insieme: i risultati escono quindi
        # già nell'ordine delle piattaforme e si vedono comparire man mano,
        # così non sembra mai piantato.
        risultati = []
        for plat in self.platforms:
            trovati = fetch_snapshots(plat, self.username, self.session,
                                       delay=self.delay, timeout=self.timeout,
                                       uno_per_giorno=self.uno_per_giorno)
            print(self._riga_baseline(plat, trovati))
            risultati.append((plat, trovati))
        # SECONDA PASSATA sulle piattaforme non contattate. Una piattaforma
        # persa qui non è un dettaglio: il suo "zero" mancante può spostare
        # la scelta dell'ancora e falsare l'intera indagine. Vale quindi la
        # pena spendere qualche richiesta in più per riprovare SOLO quelle,
        # dopo una pausa che lasci sfiammare il rate limit.
        mancanti = [p for p in self.platforms if p in rete.errori_rete.piattaforme_fallite]
        if mancanti:
            attesa = 30
            print(f"\n[i] {len(mancanti)} piattaforme non contattate al primo "
                  f"tentativo: aspetto {attesa}s e riprovo solo quelle "
                  f"({', '.join(mancanti)})")
            time.sleep(attesa)
            recuperate = []
            for plat in mancanti:
                # la togliamo dall'elenco PRIMA di riprovare: se il secondo
                # tentativo fallisce di nuovo, fetch_snapshots ce la rimette
                # da solo, e sapremo che è ancora irraggiungibile
                rete.errori_rete.piattaforme_fallite.discard(plat)
                trovati = fetch_snapshots(plat, self.username, self.session,
                                           delay=self.delay, timeout=self.timeout,
                                           uno_per_giorno=self.uno_per_giorno)
                if plat not in rete.errori_rete.piattaforme_fallite:
                    recuperate.append(plat)
                    print(self._riga_baseline(plat, trovati))
                    risultati = [(p, t) for p, t in risultati if p != plat]
                    risultati.append((plat, trovati))
            if recuperate:
                print(f"[i] recuperate al secondo tentativo: {', '.join(recuperate)}")

        for plat, trovati in risultati:
            self.baseline_snapshots.extend(trovati)

        # una volta raccolti tutti gli snapshot, scegliamo l'ancora e ci
        # scarichiamo subito il suo profilo (ci servirà come metro di paragone)
        self.anchor_platform, self.anchor_snapshots = self._select_anchor()
        self.anchor_profile = self._profile_data_for(self.anchor_snapshots,
                                                     handle=self.username)
        if self.anchor_platform:
            print(f"[i] Piattaforma di riferimento (più evidenza storica): {self.anchor_platform}")

        # Se qualche piattaforma non è stata contattata, l'ancora è stata
        # scelta su dati incompleti: magari la piattaforma giusta era proprio
        # una di quelle fallite, e allora TUTTI i confronti successivi si
        # basano sul riferimento sbagliato. È il tipo di errore che non si
        # vede guardando il CSV, quindi va detto forte qui.
        fallite = [p for p in self.platforms if p in rete.errori_rete.piattaforme_fallite]
        if fallite:
            print(f"\n[!!] ATTENZIONE: {len(fallite)} piattaforme su {len(self.platforms)} "
                  f"non sono state contattate: {', '.join(fallite)}")
            print("     Il loro 'zero' non è un dato: se lo username era presente lì,")
            print("     la piattaforma di riferimento appena scelta potrebbe essere quella")
            print("     sbagliata, e con essa tutti i punteggi che seguono.")
            print("     Conviene rilanciare più tardi, con --delay più alto.\n")

    def _valuta_baseline(self):
        """Fase 2: la piattaforma scelta come ancora diventa il 'Target'
        (punteggio 100 fisso, è il nostro riferimento). Le altre
        piattaforme dove è spuntato lo STESSO username invece le
        confrontiamo con l'ancora usando lo stesso punteggio delle
        varianti - non le prendiamo per buone così, a occhio."""
        altre_piattaforme = {}
        for row in self.baseline_snapshots:
            if row["Piattaforma"] == self.anchor_platform:
                # questa è la piattaforma di riferimento: la mettiamo dritta
                # nei risultati con punteggio 100, nessun dubbio
                self.rows.append({
                    **row,   # ** = "spacchetta" il dict row e ci aggiunge sopra i campi nuovi
                    "Username_Testato": self.username,
                    "Tipo": "Target",
                    "Tecnica_Variante": "-",
                    **_colonne_indicatori(),   # il Target non ha indicatori: colonne vuote
                    "Score": 100.0,
                    "Confidenza": "Target (piattaforma di riferimento)",
                    "Nome_Rilevato": self.anchor_profile["nome_rilevato"],
                    "Bio_Rilevata": self.anchor_profile["bio_rilevata"],
                    "Foto_URL": self.anchor_profile["foto_url"],
                    "Link_Esterni": " | ".join(self.anchor_profile["link_esterni"]),
                    # da QUALE piattaforma vengono nome, bio e foto: il profilo si
                    # legge da una sola piattaforma ma finisce su tutte le righe
                    # del candidato, e senza questa colonna una riga "t.me"
                    # sembrava contenere una bio di Telegram che era di GitHub
                    "Profilo_Da": self.anchor_profile.get("profilo_da", ""),
                })
            else:
                # le altre piattaforme le mettiamo da parte, le valutiamo dopo
                altre_piattaforme.setdefault(row["Piattaforma"], []).append(row)

        # ora controlliamo, una piattaforma alla volta, quanto è probabile
        # che sia davvero la stessa persona dell'ancora
        for piattaforma, righe in altre_piattaforme.items():
            profilo = self._profile_data_for(righe, handle=self.username)
            esito = compute_confidence(
                original_username=self.username,
                candidate_username=self.username,   # è lo stesso username, la stringa è identica
                candidate_snapshots=righe,
                baseline_snapshots=self.anchor_snapshots,
                candidate_platform_count=1,
                total_platforms=len(self.platforms),
                content_snippet_a=profilo["content_snippet"],
                content_snippet_b=self.anchor_profile["content_snippet"],
                # i link esterni erano già raccolti ma non venivano mai usati
                # per il punteggio: adesso servono a shared_links_score
                links_a=profilo["link_esterni"],
                links_b=self.anchor_profile["link_esterni"],
                photo_similarity_value=self._somiglianza_foto(profilo),
                weights=SAME_USERNAME_WEIGHTS,   # pesi diversi apposta, vedi osint_scoring.py
            )
            nota = ("verosimile" if esito["score"] >= 40
                    else "DA VERIFICARE, potrebbe non essere la stessa persona")
            print(f"[i] Stesso username su '{piattaforma}': score={esito['score']} "
                  f"({esito['confidenza']}) rispetto al riferimento — {nota}")

            for row in righe:
                self.rows.append({
                    **row,
                    "Username_Testato": self.username,
                    "Tipo": "Stesso username",
                    "Tecnica_Variante": "match esatto username (altra piattaforma)",
                    **_colonne_indicatori(esito, SAME_USERNAME_WEIGHTS),
                    "Score": esito["score"],
                    "Confidenza": esito["confidenza"],
                    "Nome_Rilevato": profilo["nome_rilevato"],
                    "Bio_Rilevata": profilo["bio_rilevata"],
                    "Foto_URL": profilo["foto_url"],
                    "Link_Esterni": " | ".join(profilo["link_esterni"]),
                    # da QUALE piattaforma vengono nome, bio e foto: il profilo si
                    # legge da una sola piattaforma ma finisce su tutte le righe
                    # del candidato, e senza questa colonna una riga "t.me"
                    # sembrava contenere una bio di Telegram che era di GitHub
                    "Profilo_Da": profilo.get("profilo_da", ""),
                    "Nome_Da": profilo.get("nome_da", ""),
                    "Bio_Da": profilo.get("bio_da", ""),
                    "Foto_Da": profilo.get("foto_da", ""),
                    "Pagine_Segnaposto_Scartate": profilo.get("scartate", 0),
                    # in esadecimale e con il prefisso 0x: scritto come
                    # numero, un hash sopra 2^63 riletto da pandas può
                    # diventare un float e perdere le ultime cifre, cioè
                    # diventare un altro hash. Come testo resta esatto.
                    "Foto_Hash": (f"0x{profilo['foto_hash']:016x}"
                                  if profilo.get("foto_hash") is not None else ""),
                    "Foto_Scarto": profilo.get("foto_motivo", ""),
                    # ATTENZIONE al "or": una distanza di 0 significa immagini
                    # IDENTICHE, cioè il segnale più forte possibile, e con
                    # 'or ""' finiva nel CSV come cella vuota. Serve il
                    # confronto esplicito con None.
                    "Foto_Distanza": rete.vuoto_se_none(osint_foto.distanza(
                        profilo.get("foto_hash"),
                        (self.anchor_profile or {}).get("foto_hash"))),
                })

    def _valuta_candidati(self):
        """Fase 3: si cercano e si controllano i candidati veri e propri
        (cioè username diversi da quello originale)."""
        candidati = self._collect_candidates()
        print(f"\n=== {len(candidati)} candidati totali da verificare ===")

        for n, v in enumerate(candidati, 1):
            # se la rete è andata giù, prima di arrenderci proviamo un
            # raffreddamento (vedi _ContatoreErrori.prova_a_riprendere): su
            # una run di ore vale la pena aspettare qualche minuto ed
            # eventualmente riprendere, invece di buttare via tutti i
            # candidati rimasti al primo blocco temporaneo di archive.org
            if rete.errori_rete.rete_a_terra:
                if rete.errori_rete.prova_a_riprendere():
                    print(f"[i] Riprendo l'indagine dal candidato {n} di {len(candidati)}.")
                else:
                    print(f"\n[!!] Indagine interrotta al candidato {n} di {len(candidati)}: "
                          f"rete ancora irraggiungibile dopo "
                          f"{rete.errori_rete.MAX_RAFFREDDAMENTI} tentativi di raffreddamento.")
                    break
            candidate_username = v["variante"]
            # si stampa PRIMA di partire, con il contatore: la verifica di un
            # candidato richiede una decina di richieste, e senza questa riga
            # non si capirebbe né a che punto siamo né quanto manca
            print(f"[{n}/{len(candidati)}] verifico '{candidate_username}'...")
            candidate_snapshots = self._check_platforms(candidate_username)
            if not candidate_snapshots:
                continue   # candidato mai esistito su nessuna piattaforma, si scarta

            # su quante piattaforme diverse è spuntato questo candidato
            # (usiamo un set {} così ogni piattaforma conta una volta sola)
            platform_count = len({s['Piattaforma'] for s in candidate_snapshots})
            candidate_profile = self._profile_data_for(candidate_snapshots,
                                                       handle=candidate_username)

            result = compute_confidence(
                original_username=self.username,
                candidate_username=candidate_username,
                candidate_snapshots=candidate_snapshots,
                baseline_snapshots=self.anchor_snapshots,
                candidate_platform_count=platform_count,
                total_platforms=len(self.platforms),
                content_snippet_a=candidate_profile["content_snippet"],
                content_snippet_b=self.anchor_profile["content_snippet"],
                # stessa cosa qui: link già raccolti, ora usati anche nel punteggio
                links_a=candidate_profile["link_esterni"],
                links_b=self.anchor_profile["link_esterni"],
                photo_similarity_value=self._somiglianza_foto(candidate_profile),
                rarita=rarita_username(self.candidati_prefisso_trovati),
            )

            print(f"[+] Candidato '{candidate_username}' ({v['tecnica']}): "
                  f"score={result['score']} ({result['confidenza']})")

            for row in candidate_snapshots:
                self.rows.append({
                    **row,
                    "Username_Testato": candidate_username,
                    "Tipo": "Variante",
                    "Tecnica_Variante": v["tecnica"],
                    **_colonne_indicatori(result, DEFAULT_WEIGHTS),
                    "Score": result["score"],
                    "Confidenza": result["confidenza"],
                    "Nome_Rilevato": candidate_profile["nome_rilevato"],
                    "Bio_Rilevata": candidate_profile["bio_rilevata"],
                    "Foto_URL": candidate_profile["foto_url"],
                    "Link_Esterni": " | ".join(candidate_profile["link_esterni"]),
                    # da QUALE piattaforma vengono nome, bio e foto: il profilo si
                    # legge da una sola piattaforma ma finisce su tutte le righe
                    # del candidato, e senza questa colonna una riga "t.me"
                    # sembrava contenere una bio di Telegram che era di GitHub
                    "Profilo_Da": candidate_profile.get("profilo_da", ""),
                    "Nome_Da": candidate_profile.get("nome_da", ""),
                    "Bio_Da": candidate_profile.get("bio_da", ""),
                    "Foto_Da": candidate_profile.get("foto_da", ""),
                    "Pagine_Segnaposto_Scartate": candidate_profile.get("scartate", 0),
                    # in esadecimale e con il prefisso 0x: scritto come
                    # numero, un hash sopra 2^63 riletto da pandas può
                    # diventare un float e perdere le ultime cifre, cioè
                    # diventare un altro hash. Come testo resta esatto.
                    "Foto_Hash": (f"0x{candidate_profile['foto_hash']:016x}"
                                  if candidate_profile.get("foto_hash") is not None else ""),
                    "Foto_Scarto": candidate_profile.get("foto_motivo", ""),
                    # ATTENZIONE al "or": una distanza di 0 significa immagini
                    # IDENTICHE, cioè il segnale più forte possibile, e con
                    # 'or ""' finiva nel CSV come cella vuota. Serve il
                    # confronto esplicito con None.
                    "Foto_Distanza": rete.vuoto_se_none(osint_foto.distanza(
                        candidate_profile.get("foto_hash"),
                        (self.anchor_profile or {}).get("foto_hash"))),
                })

    def _collect_candidates(self):
        """Mette insieme i candidati trovati per davvero (ricerca per
        prefisso) e quelli tirati a indovinare (permutazione a naso),
        togliendo i doppioni. Ai primi diamo la precedenza perché sono
        più affidabili, e poi si taglia tutto a max_candidates."""
        prefix_candidates = {}
        print("\n=== Ricerca diretta di varianti realmente esistite (CDX prefix) ===")

        risultati = []
        for plat in self.platforms:
            handles, visti, affidabile, prime, fino_a = discover_prefix_candidates(
                plat, self.username, self.session,
                delay=self.delay, timeout=self.timeout, con_limite=True)
            print(f"[prefix] {plat}: {len(handles)} candidati")
            # se la risposta è attendibile teniamo l'elenco: da qui in poi
            # sappiamo con certezza QUALI handle che iniziano come lo username
            # sono archiviati su questa piattaforma, e quali no
            # anche un elenco incompleto è valido fino all'ultima riga letta
            # (fino_a): si tiene, insieme al punto in cui smette di esserlo
            self._prefisso_per_piattaforma[plat] = (visti if (affidabile or fino_a)
                                                    else None)
            self._prefisso_fino_a[plat] = None if affidabile else fino_a
            self._prime_catture[plat] = prime
            risultati.append((plat, handles))

        # ORDINE DI VERIFICA: prima i candidati più probabili. Prima si
        # prendevano piattaforma per piattaforma (tutti quelli di GitHub, poi
        # tutti quelli di Twitter...), quindi con un limite venivano tagliate
        # per intero le ultime piattaforme della lista, a prescindere da chi
        # c'era. Ora l'ordine è unico, e usa solo informazioni che la ricerca
        # per prefisso ha GIÀ dato, senza richieste in più:
        #   1. su quante piattaforme compare lo stesso handle: chi ha usato
        #      "torvaldsx" sia su GitHub sia su Twitter è più probabile
        #      che sia una persona che ricicla il nome (è il segnale
        #      multi_platform, stimato in anticipo);
        #   2. a parità, la somiglianza con lo username (username_similarity);
        #   3. a parità ancora, l'ordine alfabetico, così è ripetibile.
        # Il limite --max-candidates prende i primi di QUESTO ordine, e il
        # campione casuale misura cosa c'è dopo.
        su_quante = {}
        for _, handles in risultati:
            # sorted: handles è un insieme e il suo ordine cambia da
            # un'esecuzione all'altra; qui decide con quale grafia (maiuscole)
            # si interroga il candidato, quindi deve essere ripetibile
            for handle in sorted(handles):
                key = handle.lower()
                su_quante[key] = su_quante.get(key, 0) + 1
                if key not in prefix_candidates:   # primo che arriva vince, così non duplichiamo
                    prefix_candidates[key] = {"variante": handle, "tecnica": "prefix Wayback (verificato)"}
        u = self.username.lower()
        prefix_candidates = dict(sorted(
            prefix_candidates.items(),
            key=lambda kv: (-su_quante[kv[0]],
                            -SequenceMatcher(None, u, kv[0]).ratio(),
                            kv[0])))
        self._su_quante_piattaforme = su_quante
        print(f"[+] {len(prefix_candidates)} candidati verificati trovati per prefisso")
        multi = sum(1 for n in su_quante.values() if n >= 2)
        if multi:
            print(f"[i] {multi} di questi compaiono su 2 o più piattaforme: "
                  f"vengono verificati per primi")

        # Se ne generano parecchie: il budget si applica sotto, per categoria.
        heuristic = generate_variants(self.username, self.nome, self.cognome,
                                       max_variants=60)

        tutti_prefisso = list(prefix_candidates.values())
        # max_candidates = 0 vuol dire TUTTI. È la scelta giusta per un'analisi completa:
        # il limite era una toppa sul costo delle richieste, non una scelta di
        # metodo. Con le liste per prefisso complete ogni candidato costa una
        # sola query CDX (sulla piattaforma dove esiste: le altre le esclude
        # già la ricerca per prefisso), invece delle 9 di prima.
        if self.max_candidates == 0:
            prefissi, oltre = tutti_prefisso, []
        else:
            prefissi = tutti_prefisso[:self.max_candidates]
            oltre = tutti_prefisso[self.max_candidates:]
        # CAMPIONE OLTRE IL LIMITE. I candidati per prefisso sono ordinati per
        # somiglianza allo username e se ne verificano i primi max_candidates.
        # Ma quel limite non è dimostrato: nel batch da 100 ha tagliato 3640
        # candidati su 39 username, e 2 dei 6 candidati buoni erano in posizione
        # 9, appena sotto la soglia. Cosa c'era oltre non si può sapere, perché
        # non è mai stato controllato. Un piccolo campione CASUALE di quelli
        # esclusi serve a misurarlo: se fra loro compaiono candidati buoni, il
        # limite scarta informazione e va alzato; se no, è giustificato.
        # Il seme dipende dallo username: rilanciando si ottiene lo stesso
        # campione, quindi la cache vale anche per lui e il risultato è ripetibile.
        campione = []
        if oltre and self.campione_oltre_limite > 0:
            rng = random.Random(f"campione:{self.username.lower()}")
            scelti = rng.sample(oltre, min(self.campione_oltre_limite, len(oltre)))
            campione = [{"variante": c["variante"],
                         "tecnica": "prefix Wayback (campione oltre il limite)"}
                        for c in scelti]
        self.candidati_prefisso_trovati = len(tutti_prefisso)
        self.candidati_prefisso_verificati = len(prefissi) + len(campione)
        if oltre:
            print(f"[i] {len(tutti_prefisso)} candidati per prefisso: verificati i primi "
                  f"{len(prefissi)} più probabili"
                  + (f" + {len(campione)} estratti a caso fra gli altri {len(oltre)}"
                     if campione else f", ignorati gli altri {len(oltre)}"))
        prefissi = prefissi + campione

        # Le varianti inventate si dividono in due categorie, perché non hanno
        # lo stesso valore:
        #  - INDIPENDENTI: non iniziano come lo username (leetspeak, separatori,
        #    nome/cognome). La ricerca per prefisso non può trovarle: se non le
        #    si prova, restano invisibili.
        #  - DI SICUREZZA: iniziano come lo username (suffissi). Se esistono, la
        #    ricerca per prefisso le ha GIÀ trovate - a meno che quella
        #    ricerca sia fallita o sia stata troncata. Servono solo in quel caso,
        #    e solo lì vengono provate.
        visti = set(prefix_candidates.keys())
        indipendenti, di_sicurezza, scartate = [], [], 0
        for v in heuristic:
            chiave = v["variante"].lower()
            if not _handle_plausibile(v["variante"]):
                # spazi, accenti, caratteri che nessuna piattaforma ammette:
                # sarebbero richieste a vuoto garantite
                scartate += 1
                continue
            if chiave in visti:
                continue
            visti.add(chiave)
            (di_sicurezza if chiave.startswith(self.username.lower())
             else indipendenti).append(v)
        if scartate:
            print(f"[i] {scartate} varianti ipotizzate scartate perché non sono "
                  f"username validi su nessuna piattaforma (spazi/accenti/caratteri strani)")

        budget = 0 if self.senza_euristiche else max(0, self.max_euristiche)
        # le combinazioni nome/cognome ci sono solo se l'utente li ha dati, sono
        # al massimo 8, e il batch da 100 non le usava: nessun dato per tagliarle
        da_nomi = [v for v in indipendenti if "nome" in v["tecnica"]]
        altre = [v for v in indipendenti if "nome" not in v["tecnica"]][:budget]
        prefisso_inaffidabile = [p for p, noti in self._prefisso_per_piattaforma.items()
                                 if noti is None or self._prefisso_fino_a.get(p) is not None]
        sicurezza = di_sicurezza[:budget] if prefisso_inaffidabile else []

        print(f"[i] candidati: {len(prefissi)} per prefisso, {len(altre)} varianti "
              f"indipendenti (budget {budget}), {len(da_nomi)} da nome/cognome, "
              f"{len(sicurezza)} di sicurezza"
              + (f" (ricerca per prefisso inaffidabile su: "
                 f"{', '.join(prefisso_inaffidabile)})" if sicurezza else ""))
        return prefissi + altre + da_nomi + sicurezza

    def run(self):
        rete.errori_rete.azzera()      # ogni indagine parte con il contatore pulito
        # ORDINE: la baseline per prima, sempre. È la fase che non può
        # permettersi di fallire, perché da lei dipende la scelta della
        # piattaforma di riferimento e quindi TUTTI i punteggi successivi
        # (è esattamente ciò che è andato storto su 'torvalds' nel test da
        # 100 username). Va quindi eseguita quando la connessione è ancora
        # fresca, prima di aver consumato richieste con altro.
        # La ricerca per prefisso viene dopo: se fallisce non si perde nulla,
        # si rinuncia soltanto a risparmiare richieste sui candidati.
        self._raccogli_baseline()
        self._valuta_baseline()
        self._valuta_candidati()

        # COMPLETEZZA DEI DATI. Prima c'era solo un avviso stampato a schermo:
        # nel CSV non restava nessuna traccia, e un CSV prodotto sotto
        # congestione della rete era indistinguibile da uno pulito. Per un
        # uso normale è già grave; per la calibrazione dei pesi è fatale,
        # perché si finirebbe a calibrare su punteggi calcolati su dati
        # mancanti senza saperlo.
        # Adesso OGNI riga del CSV porta con sé se l'indagine che l'ha
        # prodotta era completa, e cosa è andato perso. In calibrazione si
        # usano solo le righe con Dati_Completi = True.
        self._timbra_completezza()

        if self.rows:
            try:
                n = aggiungi_collegamenti(self.rows, self.username)
                if n:
                    print(f"[i] collegamenti espliciti con l'ancora: {n}")
            except Exception as e:   # l'indizio manca, ma l'indagine resta valida
                print(f"[!] collegamenti espliciti non calcolati: {e}")

        if not self.rows:
            print(f"\n[!] Nessuno snapshot trovato per '{self.username}' su nessuna "
                  f"piattaforma monitorata: nessuna scheda persona da costruire.")
            return self.rows

        # solo se abbiamo trovato qualcosa costruiamo e stampiamo il riepilogo
        self.person_summary = build_person_summary(self.username, self.rows)
        self.person_summary.update(self._completezza())
        print_person_summary(self.person_summary)
        return self.rows

    def _completezza(self):
        """Il verdetto sulla completezza di questa indagine, in una forma che
        si può scrivere sia nel CSV sia nel JSON."""
        e = rete.errori_rete
        # le perdite si raggruppano per luogo e motivo, così la cella resta
        # leggibile anche con venti richieste perse
        conteggio = {}
        for dove, motivo in e.perdite:
            conteggio[f"{dove}: {motivo}"] = conteggio.get(f"{dove}: {motivo}", 0) + 1
        dettaglio = "; ".join(f"{k} (x{v})" if v > 1 else k
                              for k, v in sorted(conteggio.items()))
        return {
            "Dati_Completi": e.dati_persi == 0,
            "Dati_Persi": e.dati_persi,
            "Piattaforme_Non_Contattate": ", ".join(sorted(e.piattaforme_fallite)),
            "Dettaglio_Perdite": dettaglio,
            # la configurazione con cui è stata fatta l'indagine: multi_platform
            # è una frazione sul numero di piattaforme, quindi punteggi ottenuti
            # con insiemi di piattaforme diversi NON sono confrontabili fra loro
            "N_Piattaforme": len(self.platforms),
            "Max_Euristiche": 0 if self.senza_euristiche else self.max_euristiche,
            # quanto è "affollato" il prefisso: 221 handle che iniziano con
            # "jack" vogliono dire che "jack" è uno username comune, e che una
            # coincidenza di nome, da sola, prova poco (l'argomento di Perito
            # et al. sull'entropia degli username, misurato sui dati)
            "Candidati_Prefisso_Trovati": self.candidati_prefisso_trovati,
            "Candidati_Prefisso_Verificati": self.candidati_prefisso_verificati,
            # il fattore che corregge multi_platform (osint_scoring.rarita_username):
            # multi_platform grezzo = multi_platform / Rarita_Username
            "Rarita_Username": round(rarita_username(self.candidati_prefisso_trovati), 3),
        }

    def _timbra_completezza(self):
        c = self._completezza()
        for riga in self.rows:
            riga.update(c)
        if c["Dati_Completi"]:
            print("\n[V] Dati completi: nessuna richiesta persa.")
            return
        print(f"\n[!!] DATI INCOMPLETI: {c['Dati_Persi']} informazioni non sono "
              f"arrivate a causa della rete.")
        if c["Piattaforme_Non_Contattate"]:
            print(f"     Piattaforme non contattate: {c['Piattaforme_Non_Contattate']}")
        print(f"     Dettaglio: {c['Dettaglio_Perdite']}")
        print("     I punteggi di questa indagine NON vanno usati per calibrare i pesi")
        print("     (colonna Dati_Completi = False nel CSV). Rilanciando, la cache")
        print("     fa ripartire SOLO le richieste perse: è un rilancio quasi gratis.")

    def export(self, filename=None):
        if not self.rows:
            print("\n[!] Nessun dato raccolto. Esportazione annullata.")
            return None

        # Se run() non è arrivato in fondo (Ctrl+C, errore imprevisto), le
        # righe raccolte fin lì non hanno il timbro di completezza. Esportarle
        # così vorrebbe dire un CSV che non dice di essere parziale: lo
        # timbriamo qui, e un'indagine interrotta è per definizione incompleta.
        interrotta = "Dati_Completi" not in self.rows[0]
        if interrotta:
            rete.errori_rete.segna_perdita("indagine", "interrotta prima della fine")
            self._timbra_completezza()

        df = pd.DataFrame(self.rows)
        # ordiniamo per punteggio decrescente, così i risultati più probabili
        # stanno in cima al CSV
        df = df.sort_values(by=["Score", "Data_Salvataggio"], ascending=[False, False])

        # lo username lo usiamo anche come pezzo del nome del file: se
        # contenesse un carattere non ammesso in un nome di file (tipo '/')
        # to_csv esploderebbe DOPO aver già fatto tutte le richieste di
        # rete, perdendo tutto il lavoro fatto - meglio ripulirlo prima
        username_sicuro = _nome_file_sicuro(self.username)
        # Un'indagine interrotta NON sovrascrive il CSV di un'indagine finita:
        # è successo con torvalds, dove un rilancio fermato dopo due minuti ha
        # rimpiazzato il CSV completo con le sole 428 righe dell'ancora.
        filename = filename or (f"OSINT_{username_sicuro}_correlato"
                                + ("_INTERROTTA" if interrotta else "") + ".csv")
        df.to_csv(filename, index=False)
        print(f"[V] Report dettagliato esportato in: {filename}")

        if self.person_summary:
            profilo_filename = f"OSINT_{username_sicuro}_profilo.json"
            export_person_summary(self.person_summary, profilo_filename)
            print(f"[V] Scheda persona esportata in: {profilo_filename}")

        return filename


def _riepilogo_finale():
    """Stampa dove se n'è andato il tempo e quanto ha risparmiato la cache."""
    print("\n" + "=" * 66)
    print("BILANCIO DELLE RICHIESTE")
    print("=" * 66)
    print(rete.cronometro.riepilogo())
    print(rete.cache.riepilogo())
    if rete.errori_rete.lenti:
        print(f"risposte mai arrivate entro il timeout: {rete.errori_rete.lenti} "
              f"(non contate come errori di rete; se sono tante alza --timeout)")
    print("=" * 66)


def _indaga(username, nome, cognome, args):
    """Una singola indagine. Torna True se è andata ragionevolmente bene."""
    investigator = OsintUsernameInvestigator(
        username, nome=nome, cognome=cognome,
        platforms=args.piattaforme,
        max_candidates=args.max_candidates,
        delay=args.delay,
        timeout=args.timeout,
    )
    investigator.uno_per_giorno = not args.tutti_gli_snapshot
    investigator.senza_euristiche = args.senza_euristiche
    investigator.max_euristiche = args.max_euristiche
    investigator.campione_oltre_limite = args.campione_oltre_limite
    investigator.date_da_pagina = not args.cdx_per_candidato
    investigator.controllo_404 = args.controllo_404
    # Un'indagine può girare a lungo senza nessuno davanti allo schermo. Se
    # qualcosa va storto a metà strada - un caso limite della rete, un Ctrl+C
    # - senza questo blocco tutto il lavoro fatto andrebbe perso: run() si
    # fermerebbe con un errore ed export() non verrebbe mai chiamata.
    interrotto = False
    try:
        investigator.run()
    except KeyboardInterrupt:
        print("\n[!] Indagine interrotta manualmente (Ctrl+C). Esporto quello raccolto finora...")
        interrotto = True
    except Exception as e:
        print(f"\n[!!] Errore imprevisto durante l'indagine ({type(e).__name__}: {e}). "
              f"Esporto comunque quello raccolto finora, per non perdere il lavoro fatto.")
    investigator.export()
    if interrotto:
        raise KeyboardInterrupt
    # quante informazioni sono andate perse: 0 = indagine completa
    return rete.errori_rete.dati_persi


def _costruisci_parser():
    """Tutte le opzioni da riga di comando.

    Separata da main() per un motivo preciso: così i test possono costruirla e
    verificarla da sola. Da Python 3.14 argparse controlla i testi di aiuto nel
    momento in cui l'opzione viene definita, e un carattere '%' non raddoppiato
    in un testo di aiuto fa fallire il programma all'AVVIO, prima di fare
    qualsiasi cosa. Nelle versioni precedenti lo stesso errore esplodeva solo
    lanciando --help, e quindi passava inosservato: è successo.
    """
    parser = argparse.ArgumentParser(
        description="OSINT Username Correlator (Wayback Machine) - scopre varianti "
                     "reali e ipotizzate dello username, le verifica cross-platform, "
                     "assegna un punteggio di affidabilità e aggrega le informazioni "
                     "di profilo trovate in una scheda persona."
    )
    parser.add_argument("--username", "-u", help="Username target da analizzare")
    parser.add_argument("--lista", "-l",
                         help="File con un username per riga (righe vuote e righe che "
                              "iniziano con # vengono saltate). Le indagini girano una "
                              "dopo l'altra DENTRO QUESTO STESSO PROCESSO: è il modo "
                              "giusto di fare un batch, perché così il limitatore e il "
                              "contatore degli errori restano vivi da un username al "
                              "successivo. Lanciando invece uno script esterno che apre "
                              "un processo nuovo per ogni username, ogni rallentamento "
                              "imposto da archive.org viene dimenticato subito dopo.")
    parser.add_argument("--nome", help="Nome della persona (opzionale, per varianti nome.cognome)")
    parser.add_argument("--cognome", help="Cognome della persona (opzionale)")
    parser.add_argument("--max-candidates", type=int, default=15,
                         help="Quanti candidati trovati per prefisso verificare, in "
                              "ordine di somiglianza allo username (default: 15). "
                              "0 = TUTTI: è la scelta per un'analisi completa, il limite "
                              "serve solo a risparmiare tempo quando si prova un caso "
                              "al volo. Le varianti inventate hanno un budget a parte "
                              "(--max-euristiche).")
    parser.add_argument("--delay", type=float, default=3.0,
                         help="Secondi di pausa tra una richiesta e l'altra alla Wayback "
                              "Machine (default: 3.0, cioè circa 0.33 richieste al "
                              "secondo). Alzalo se vedi errori di rete o connessioni "
                              "rifiutate: l'indagine diventa più lenta ma molto più "
                              "affidabile")
    parser.add_argument("--tutti-gli-snapshot", action="store_true",
                         help="Chiede ad archive.org OGNI singola visita del crawler "
                              "invece di una al giorno. Produce file enormi ed è la "
                              "causa dei 503 sulle pagine molto archiviate: usalo solo "
                              "se ti serve davvero il dettaglio per visita.")
    parser.add_argument("--timeout", type=float, default=90,
                         help="Timeout (secondi) per ogni richiesta HTTP (default: 90). "
                              "Sembra enorme e non lo è: misurato sul servizio vero, "
                              "il tempo di risposta della CDX NON dipende da quanto è "
                              "pesante la query ma da quanto è carico il servizio in quel "
                              "momento. Una query da 2 righe ha impiegato 33s e una da 4667 "
                              "righe 15s; una da 144 righe è andata oltre i 60s. Un timeout "
                              "basso non protegge da niente: trasforma solo le risposte "
                              "lente in falsi 'errori di rete', e 8 di fila costano 5 minuti "
                              "di raffreddamento inutile.")
    parser.add_argument("--cartella", default=None,
                         help="Cartella in cui scrivere i risultati delle indagini. Se lo "
                              "strumento è lanciato dalla cartella del progetto, di default "
                              "è dati/indagini (e la cache è dati/osint_cache.sqlite); "
                              "altrimenti è la cartella corrente.")
    parser.add_argument("--cache", default=None,
                         help="File della cache su disco (default: dati/osint_cache.sqlite "
                              "dalla cartella del progetto, altrimenti osint_cache.sqlite). "
                              "Tiene le risposte già ottenute, così rilanciare dopo un "
                              "blocco non ricosta tutte le richieste da capo.")
    parser.add_argument("--no-cache", action="store_true",
                         help="Non usare la cache: ogni richiesta parte davvero. Serve "
                              "solo per misurare i tempi reali o per forzare dati freschi.")
    parser.add_argument("--cache-ttl", type=float, default=7,
                         help="Dopo quanti giorni una risposta in cache è considerata "
                              "vecchia (default: 7). 0 = non scade mai.")
    parser.add_argument("--svuota-cache", action="store_true",
                         help="Cancella la cache e il freno salvati, poi esce.")
    parser.add_argument("--max-euristiche", type=int, default=3,
                         help="Quante varianti inventate e indipendenti (leetspeak, "
                              "separatori) verificare per ogni username (default: 3). "
                              "Hanno un budget proprio, non i posti avanzati dopo la "
                              "ricerca per prefisso, così ogni username ne prova lo "
                              "stesso numero e la loro resa si può misurare. I suffissi "
                              "(torvalds1...) vengono provati solo se la ricerca per "
                              "prefisso su qualche piattaforma è fallita.")
    parser.add_argument("--campione-oltre-limite", type=int, default=0,
                         help="Oltre ai primi --max-candidates candidati per prefisso "
                              "(i più simili allo username), ne verifica N estratti a "
                              "caso fra quelli esclusi (default: 0). Serve a misurare "
                              "cosa scarta il limite, invece di darlo per giusto. Il "
                              "campione dipende dallo username, quindi è ripetibile.")
    parser.add_argument("--cdx-per-candidato", action="store_true",
                         help="Torna al vecchio modo: una query CDX per ogni candidato "
                              "per sapere le date delle sue catture. Di default invece "
                              "la prima data viene dalla ricerca per prefisso e l'ultima "
                              "dal reindirizzamento della pagina (verificato sul "
                              "servizio vero: coincide con CDX), e CDX, che è la "
                              "parte lenta del servizio, non viene interrogato. Utile "
                              "solo per confrontare i due metodi.")
    parser.add_argument("--controllo-404", action="store_true",
                         help="Prima di ogni query CDX su un candidato chiede la pagina "
                              "archiviata: se l'archivio risponde 404 la query si salta. "
                              "Il comportamento è stato verificato sul servizio vero.")
    parser.add_argument("--timemap", action="store_true",
                         help="Fa le interrogazioni CDX da web.archive.org/web/timemap/json "
                              "invece che da /cdx/search/cdx (per quando il secondo non risponde).")
    parser.add_argument("--solo-cache", action="store_true",
                         help="Nessuna richiesta di rete: usa solo i dati già in cache "
                              "(per quando archive.org è irraggiungibile).")
    parser.add_argument("--senza-euristiche", action="store_true",
                         help="Equivale a --max-euristiche 0.")
    parser.add_argument("--piattaforme",
                         type=lambda t: [p.strip() for p in t.split(",") if p.strip()],
                         default=None,
                         help="Elenco separato da virgole degli indirizzi da controllare, "
                              "per esempio github.com,twitter.com,x.com (default: tutti "
                              "e 9, cioè le 8 piattaforme: twitter.com e x.com sono la "
                              "stessa). Attenzione: multi_platform è una "
                              "frazione sul numero di piattaforme, quindi punteggi "
                              "ottenuti con elenchi diversi non sono confrontabili.")
    parser.add_argument("--riprese", type=int, default=2,
                         help="Nel batch, quante volte rifare le indagini che hanno "
                              "perso dati per congestione della rete (default: 2). "
                              "Costa poco: grazie alla cache ripartono solo le "
                              "richieste perse.")
    parser.add_argument("--pausa-ripresa", type=float, default=180,
                         help="Secondi di pausa prima di ogni ripresa (default: 180), "
                              "per dare tempo ad archive.org di smaltire il carico.")
    parser.add_argument("--no-filtri-server", action="store_true",
                         help="Spegne i filtri lato server (statuscode:200 e "
                              "mimetype:text/html chiesti direttamente ad archive.org). "
                              "Sono ACCESI di default: la sintassi è stata verificata "
                              "confrontando il numero di righe con e "
                              "senza filtri - identico sui profili leggeri (2=2, 3=3), e "
                              "sulle pagine molto archiviate taglia le righe inutili "
                              "(instagram.com/nasa: da 1573 righe e 105 kB a 462 righe e "
                              "32 kB, -70%%). Le righe tolte sono redirect e pagine di "
                              "errore archiviate, che il codice scartava comunque. Usa "
                              "questa opzione solo per confrontare i due comportamenti.")
    return parser


def main():
    # qui definiamo tutte le opzioni che si possono passare da riga di
    # comando (tipo "python osint.py --username torvalds --delay 2")
    parser = _costruisci_parser()
    args = parser.parse_args()

    # controlli di buon senso sui numeri passati da riga di comando: senza
    # questi, un valore assurdo non dà errore subito ma fa crashare lo script
    # più avanti, a metà dell'indagine, in un punto molto meno chiaro
    if args.delay < 0:
        parser.error("--delay non può essere negativo")
    if args.timeout <= 0:
        parser.error("--timeout deve essere maggiore di zero")
    if args.max_candidates < 0:
        parser.error("--max-candidates non può essere negativo (0 = tutti)")
    if args.username and args.lista:
        parser.error("--username e --lista si escludono a vicenda")

    # Dove scrivere. Lanciato dalla cartella del progetto, lo strumento tiene i
    # dati in dati/ (vedi percorsi.py); lanciato da un'altra cartella (per
    # esempio dai test) lavora lì, come ha sempre fatto.
    global FILE_VERIFICA_404
    if os.path.abspath(os.getcwd()) == percorsi.RADICE:
        args.cartella = args.cartella or percorsi.INDAGINI
        args.cache = args.cache or percorsi.CACHE
        FILE_VERIFICA_404 = percorsi.VERIFICA_404
        rete.freno.percorso = percorsi.FRENO
    args.cache = os.path.abspath(args.cache or "osint_cache.sqlite")
    if args.lista:
        args.lista = os.path.abspath(percorsi.lista(args.lista))
    if args.cartella:
        os.makedirs(args.cartella, exist_ok=True)
        if not os.path.isabs(FILE_VERIFICA_404):
            FILE_VERIFICA_404 = os.path.abspath(FILE_VERIFICA_404)
        if not os.path.isabs(rete.freno.percorso):
            rete.freno.percorso = os.path.abspath(rete.freno.percorso)
        os.chdir(args.cartella)
        print(f"[i] risultati in {os.getcwd()}, cache in {args.cache}")

    if args.svuota_cache:
        import os as _os
        for f in (args.cache, rete.freno.percorso):
            try:
                _os.remove(f)
                print(f"[V] rimosso {f}")
            except OSError:
                print(f"[i] {f} non c'era")
        return

    if not osint_foto.PILLOW_DISPONIBILE:
        print("[!!] Pillow non è installato: le foto profilo NON verranno analizzate,")
        print("     e ogni indagine risulterà con Dati_Completi = False. Per installarlo,")
        print("     con lo stesso Python che usi per lanciare questo programma:")
        print("         python3 -m pip install Pillow\n")
    rete.configura(
        nuova_cache=CacheCDX(args.cache, ttl_giorni=args.cache_ttl,
                             attiva=not args.no_cache),
        filtri_server=("" if args.no_filtri_server
                       else "&filter=statuscode:200&filter=mimetype:text/html"),
        solo_cache=args.solo_cache,
        timemap=args.timemap,
    )
    if args.solo_cache:
        args.riprese = 0      # senza rete, riprovare non serve
        print("[i] --solo-cache: nessuna richiesta ad archive.org, uso solo i dati già "
              "scaricati. Quello che manca risulta nel CSV come dato perso.")

    # ------------------------------------------------------- modo batch
    if args.lista:
        try:
            with open(args.lista, encoding="utf-8") as f:
                utenti = [r.strip() for r in f
                          if r.strip() and not r.strip().startswith("#")]
        except OSError as e:
            parser.error(f"non riesco a leggere {args.lista}: {e}")
        if not utenti:
            parser.error(f"{args.lista} non contiene nessun username")

        print(f"[i] Batch: {len(utenti)} username, un processo solo, "
              f"--delay {args.delay} --max-candidates {args.max_candidates}")
        # COME SI EVITA DI PERDERE DATI PER CONGESTIONE.
        # Un'indagine che ha perso delle richieste non si butta e non si tiene
        # per buona: si RIMETTE IN CODA e si rifà alla fine del giro, dopo una
        # pausa. Grazie alla cache, rifarla costa solo le richieste perse -
        # tutto ciò che era arrivato viene riletto dal disco (e le risposte
        # fallite, apposta, in cache non ci sono mai finite). Quindi la
        # congestione non fa perdere dati: li rimanda.
        # Solo se dopo tutte le riprese un'indagine è ancora incompleta, la si
        # tiene così com'è e la si elenca alla fine, marcata nel CSV.
        da_fare = list(utenti)
        incomplete = {}
        interrotto = False
        for giro in range(args.riprese + 1):
            if not da_fare:
                break
            if giro > 0:
                print("\n" + "#" * 66)
                print(f"RIPRESA {giro}/{args.riprese}: {len(da_fare)} indagini con "
                      f"dati persi, le rifaccio dopo {args.pausa_ripresa:.0f}s di pausa")
                print("(la cache rimanda in rete SOLO le richieste perse)")
                print("#" * 66)
                time.sleep(args.pausa_ripresa)
            ancora_incomplete = []
            vuote_di_fila = 0
            for n, u in enumerate(da_fare, 1):
                print("\n" + "=" * 66)
                print(f"[{n}/{len(da_fare)}] {datetime.now():%Y-%m-%d %H:%M:%S} "
                      f"- indagine su: {u}" + (f"  (ripresa {giro})" if giro else ""))
                print("=" * 66)
                try:
                    persi = _indaga(u, None, None, args)
                except KeyboardInterrupt:
                    print("\n[!] Batch interrotto manualmente.")
                    interrotto = True
                    break
                if persi:
                    ancora_incomplete.append(u)
                    incomplete[u] = persi
                else:
                    incomplete.pop(u, None)
                # Tre indagini di fila che non hanno ottenuto NULLA dalla rete
                # vogliono dire che archive.org ci sta tenendo fuori del tutto:
                # meglio fermarsi che produrre CSV vuoti. Si riprende più tardi
                # e la cache conserva tutto quello che è arrivato.
                vuote_di_fila = (vuote_di_fila + 1
                                 if persi and rete.errori_rete.riusciti == 0
                                 and not args.solo_cache else 0)
                if vuote_di_fila >= 3:
                    print("\n[!!] Tre indagini di fila senza nessuna risposta da "
                          "archive.org: ci sta bloccando. Mi fermo qui.")
                    ancora_incomplete.extend(x for x in da_fare[n:] if x not in ancora_incomplete)
                    break
            da_fare = ancora_incomplete
            if interrotto:
                break

        print("\n" + "=" * 66)
        completi = len(utenti) - len(incomplete)
        print(f"BATCH: {completi}/{len(utenti)} indagini con dati completi")
        if incomplete:
            print(f"Ancora incomplete dopo {args.riprese} riprese "
                  f"(nel CSV: Dati_Completi = False):")
            for u, persi in incomplete.items():
                print(f"    {u}: {persi} informazioni perse")
            print("Rilancia lo stesso comando più tardi: ripartono solo queste, e "
                  "solo per le richieste mancanti.")
        _riepilogo_finale()
        return

    # -------------------------------------------------- modo interattivo
    modo_interattivo = not args.username
    username = (args.username or input("Inserisci lo username target da analizzare: ")).strip()
    if not username:
        parser.error("username mancante: fornisci --username, --lista, oppure "
                     "inseriscilo quando richiesto")
    nome, cognome = args.nome, args.cognome
    # Se lo username arriva da riga di comando l'utente sta usando lo script in
    # modo non interattivo: chiedere nome/cognome con input() lo bloccherebbe
    # in attesa di una risposta che non arriverà mai.
    if modo_interattivo:
        if not nome:
            nome = input("Nome della persona (opzionale, INVIO per saltare): ").strip() or None
        if not cognome:
            cognome = input("Cognome della persona (opzionale, INVIO per saltare): ").strip() or None

    # Stesse riprese del batch: se l'indagine ha perso delle richieste per
    # congestione, la si rifà dopo una pausa. Grazie alla cache ripartono solo
    # le richieste perse, e il CSV viene riscritto con i dati completi.
    for giro in range(args.riprese + 1):
        if giro > 0:
            print("\n" + "#" * 66)
            print(f"RIPRESA {giro}/{args.riprese}: l'indagine ha perso {persi} "
                  f"richieste, la rifaccio dopo {args.pausa_ripresa:.0f}s di pausa")
            print("(la cache rimanda in rete SOLO le richieste perse)")
            print("#" * 66)
            try:
                time.sleep(args.pausa_ripresa)
            except KeyboardInterrupt:
                break
        try:
            persi = _indaga(username, nome, cognome, args)
        except KeyboardInterrupt:
            break
        if not persi:
            break
    _riepilogo_finale()
    if rete.errori_rete.dati_persi:
        print("\nIndagine INCOMPLETA: rilancia lo stesso comando fra qualche minuto,"
              "\nripartiranno solo le richieste perse.")


if __name__ == "__main__":
    main()
