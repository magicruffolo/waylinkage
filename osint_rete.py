"""
Il livello di rete: tutto ciò che parla con archive.org, e niente altro.

Prima questa roba stava dentro osint.py insieme all'orchestrazione
dell'indagine e alla riga di comando: novanta kilobyte in un file solo, e per
capire *cosa fa* il programma bisognava scorrere trecento righe di gestione
dei 503. Qui dentro c'è solo il come si parla con archive.org; il cosa si
chiede sta in osint.py.

Le quattro cose che questo modulo garantisce a chi lo usa:

  1. le richieste partono UNA ALLA VOLTA, al ritmo chiesto (limitatore);
  2. quello che è già stato ottenuto non si richiede (cache);
  3. quando archive.org dice di rallentare, si rallenta - e il rallentamento
     sopravvive alla fine del processo (freno);
  4. si distingue fra "non c'è" e "non sono riuscito a chiedere", perché
     confonderli produce punteggi calcolati su dati mancanti.

Una nota sul perché esiste configura(): gli oggetti condivisi (cache, freno,
filtri) sono variabili di modulo, e main() deve poterle sostituire con quelle
costruite dalle opzioni da riga di comando. Farlo con "from osint_rete import
cache" non funzionerebbe: quell'import copia il riferimento, e riassegnarlo
altrove non cambierebbe ciò che vedono le funzioni qui dentro. configura()
rende lo scambio esplicito invece di lasciarlo a un trucco che funziona per
sbaglio.
"""

import json
import re
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import osint_foto
from osint_cache import CacheCDX, FrenoPersistente, Cronometro
from osint_profile import (fetch_archive_html, domain_from_archive_url, testo_della_risposta,
                           CODICI_DEFINITIVI)

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) OSINT Thesis Project v4.0'
}

# Codici HTTP che segnalano un servizio sovraccarico o che ci sta chiedendo
# di rallentare (stessi codici del status_forcelist di build_session, che
# però riguarda solo i retry AUTOMATICI e IMMEDIATI della singola
# richiesta). Qui servono per un'altra cosa: farli contare come "errore di
# rete" anche per _ContatoreErrori, così se la Wayback Machine risponde con
# una raffica di 503 (capitato durante il test su 100 username: decine di
# 503 di fila, MAI un vero ConnectionError) il contatore se ne accorge e fa
# scattare il raffreddamento - prima, un 503 non veniva mai contato come
# errore "vero" (solo come piattaforma_fallita, per non confondere un blocco
# permanente tipo linktr.ee con un errore di rete), quindi centinaia di 503
# di fila non fermavano mai l'indagine: si continuava a macinare candidati
# spendendo comunque il --delay e i retry automatici per ognuno, senza mai
# fermarsi ad aspettare che il servizio si riprendesse.
_CODICI_SOVRACCARICO = {429, 500, 502, 503, 504}

# Oltre questi secondi una richiesta viene segnalata mentre succede: è il
# sintomo di una query troppo pesante, che con un timeout basso diventa un
# finto 'errore di rete'.
_RICHIESTA_LENTA = 8.0

# Pezzo di query che chiede ad archive.org di filtrare lato suo. Vuoto =
# spento; lo accende main() con --filtri-server. Tenuto come variabile di
# modulo e non come parametro perché lo usano due funzioni diverse.
_FILTRI_SERVER = ""

# Di quanto rallentare tutto dopo un timeout. Un timeout dice "sono carico",
# quindi la risposta giusta è la stessa di un 503 - rallentare - non
# "riprova subito" e nemmeno "arrenditi".
_FRENO_DOPO_TIMEOUT = 20

# --solo-cache: nessuna richiesta di rete, si usa solo ciò che è già su
# disco. Serve quando archive.org è irraggiungibile (è successo il 23/9:
# "Internet Archive services are temporarily offline"): si possono comunque
# produrre CSV e schede con i dati già scaricati. Ciò che manca non viene
# inventato: conta come dato perso, e l'indagine risulta incompleta.
_SOLO_CACHE = False

# Indirizzo del servizio CDX. Il 23/9 web.archive.org funzionava ma
# /cdx/search/cdx no: la stessa interrogazione si può fare anche da
# /web/timemap/json, che accetta gli stessi parametri. Con --timemap le
# richieste partono da lì; la chiave della cache resta l'indirizzo CDX
# originale, così le risposte già salvate valgono per entrambi.
_CDX_ORIGINALE = "https://web.archive.org/cdx/search/cdx"
_CDX_TIMEMAP = "https://web.archive.org/web/timemap/json"
_USA_TIMEMAP = False


def _manca_in_cache(dove):
    errori_rete.segna_perdita(dove, "non in cache (--solo-cache)")

# Quante volte si prova la STESSA richiesta CDX quando archive.org risponde
# "sovraccarico" (429/502/503/504). Visto nella prova su torvalds: con un 503
# la richiesta veniva data per persa e si passava subito alla piattaforma
# successiva, che prendeva un altro 503 - in un candidato si sono perse tutte
# e 9 le piattaforme in fila. Ma un sovraccarico è passeggero: aspettando il
# freno e riprovando, il dato arriva. Così la congestione costa tempo invece
# di dati. Si perde la richiesta solo se fallisce anche l'ultimo tentativo.
_TENTATIVI_SOVRACCARICO = 3


# Le piattaforme che controlliamo di default. Per aggiungerne altre basta
# mettere il pezzo di URL che sta prima dello username (con '/' o '@' alla
# fine se lo username va attaccato senza altra barra in mezzo).
#
# linktr.ee non c'è più apposta: la Wayback Machine gli risponde SEMPRE
# con un 403 (accesso negato, non "non trovato" - vedi i commenti su
# fetch_snapshots), su ogni singolo username provato durante lo sviluppo.
# Tenerlo dentro voleva dire solo tempo perso ad ogni run (un 403 su ogni
# candidato controllato) senza mai un dato utile in cambio.
def build_session():
    """Una sessione HTTP unica, condivisa da tutto il programma, con retry
    automatico se qualcosa va storto.

    Wayback Machine ogni tanto tira un rate limit: se fai troppe richieste
    di fila capita un timeout o un "connection refused" a caso. Usando UNA
    sola sessione (tiene la connessione aperta) invece di aprirne una nuova
    ogni volta, e riprovando da sola quando c'è un errore temporaneo,
    questi casini si riducono parecchio.
    """
    session = requests.Session()
    retry = Retry(
        # NOTA sui numeri bassi: prima erano total=4 e backoff_factor=1, che
        # volevano dire attese di 1+2+4+8 = 15 secondi per OGNI richiesta che
        # falliva. Con la Wayback Machine sotto carico (i 503) quei 15 secondi
        # erano quasi sempre buttati - il servizio sovraccarico non si
        # riprende in 15 secondi - e sparivano in silenzio, senza che
        # dall'output si capisse dove fosse finito il tempo. Con questi
        # valori una richiesta che fallisce costa ~1 secondo invece di ~19.
        total=3,                   # al massimo 3 tentativi in tutto
        connect=3,                 # di cui fino a 3 se proprio non si connette
        read=2,                    # e fino a 2 se si connette ma poi non risponde
        backoff_factor=0.5,        # attese di ~0.5s, 1s, 2s (in tutto ~3.5s, non 15)
        # NIENTE codici di sovraccarico qui dentro. Misurato sul test da 100
        # username: 610 risposte 503 e 618 connessioni rifiutate. Rilanciare
        # la stessa richiesta due volte subito dopo un 503 significa mandare
        # ALTRO traffico a un servizio che ha appena detto "sei troppo
        # veloce", ed è esattamente ciò che tiene acceso il rate limiter.
        # I 503 ora li gestisce il codice, frenando TUTTE le richieste
        # successive (vedi _LimitatoreRichieste.frena). Qui restano solo gli
        # errori di connessione veri, che invece un secondo tentativo lo
        # meritano.
        status_forcelist=[],
        respect_retry_after_header=False,
        raise_on_status=False,             # anche dopo aver finito i tentativi, non vogliamo un crash
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)   # applica il retry a tutte le richieste https
    session.mount("http://", adapter)    # e anche a quelle http (giusto per sicurezza)
    session.headers.update(HEADERS)
    return session


# Domini diversi che sono in realtà LA STESSA piattaforma, e che quindi
# devono finire sotto un'unica etichetta. Caso concreto: x.com è Twitter
# rinominato, gli snapshot vecchi stanno sotto twitter.com e quelli nuovi
# sotto x.com, ma l'account è lo stesso identico. Tenerli separati creava
# due problemi veri, visti girando su 'jack':
#   1. lo stesso account veniva confrontato con sé stesso e valutato 4.7
#      su 100 ("DA VERIFICARE") - un falso negativo garantito a ogni run,
#      perché gli snapshot x.com sono tutti dopo il 2023 e quelli
#      twitter.com quasi tutti prima, quindi la sovrapposizione temporale
#      risulta quasi nulla anche se è la stessa persona;
#   2. multi_platform contava 2 piattaforme invece di 1, gonfiando il
#      punteggio (0.222 invece di 0.111 su 9 piattaforme).
# Continuiamo comunque a INTERROGARE tutti e due i domini (in
# DEFAULT_PLATFORMS restano entrambi): cambia solo come etichettiamo i
# risultati, così non perdiamo gli snapshot storici di nessuno dei due.
class _LimitatoreRichieste:
    """Tiene il ritmo delle richieste verso la Wayback Machine.

    Il programma manda le richieste UNA ALLA VOLTA, in fila: è una scelta
    deliberata. Una versione che le mandava a gruppi era più veloce, ma
    faceva alzare troppo il ritmo verso archive.org, che a un certo punto
    ha smesso di accettare le nostre connessioni - e quando le richieste
    falliscono i punteggi vengono calcolati su dati mancanti, che è molto
    peggio di un'indagine lenta. Meglio dieci minuti e risultati
    affidabili.

    Il limitatore tiene il conto del primo istante libero: ogni richiesta
    prenota il suo turno e aspetta quanto serve. Rispetto alla vecchia
    `time.sleep(delay)` sparsa dopo ogni chiamata, il vantaggio è che il
    ritmo è deciso in UN SOLO POSTO e si vede a colpo d'occhio quale sia:
    una richiesta ogni `intervallo` secondi, punto."""

    def __init__(self, freno=None):
        self._prossimo_turno = 0.0
        # Il freno su file è l'unica cosa che attraversa i processi. Il batch
        # lancia un osint.py nuovo per ogni username: senza questo, un 503
        # preso sull'username 37 non rallenta l'username 38, che riparte a
        # ritmo pieno - ed è esattamente ciò che teneva acceso il rate
        # limiter per tutto il test da 100.
        self._freno = freno
        if freno is not None:
            residuo = freno.leggi()
            if residuo > 0:
                print(f"[i] Un'esecuzione precedente ha preso un rallentamento da "
                      f"archive.org: aspetto ancora {residuo:.0f}s prima di partire.")
                self._prossimo_turno = time.monotonic() + residuo

    # RITMO ADATTIVO. Dopo un sovraccarico non basta una pausa: se poi si
    # riparte al ritmo di prima, archive.org torna a rifiutare dopo poco (è
    # quello che si vedeva nei log: raffiche di 503 a distanza di minuti). Qui
    # dopo ogni sovraccarico l'intervallo fra le richieste raddoppia (fino a 4
    # volte --delay), e torna verso il normale solo dopo 30 risposte buone di
    # fila. Più lento nei momenti difficili, ma senza farsi bloccare.
    fattore = 1.0
    _FATTORE_MAX = 4.0
    _BUONE_PER_ACCELERARE = 30

    def rallenta(self):
        self.fattore = min(self.fattore * 2, self._FATTORE_MAX)
        self._buone = 0

    def risposta_buona(self):
        self._buone = getattr(self, "_buone", 0) + 1
        if self.fattore > 1 and self._buone >= self._BUONE_PER_ACCELERARE:
            self.fattore = max(1.0, self.fattore / 2)
            self._buone = 0

    def attendi(self, intervallo):
        if intervallo <= 0:
            return
        intervallo = intervallo * self.fattore
        adesso = time.monotonic()
        turno = max(adesso, self._prossimo_turno)
        self._prossimo_turno = turno + intervallo
        ritardo = turno - adesso
        if ritardo > 0:
            time.sleep(ritardo)

    def frena(self, secondi):
        """Sposta in avanti il turno di TUTTE le richieste successive.

        Serve quando archive.org risponde con un codice di sovraccarico: il
        problema non è quella singola richiesta ma il ritmo complessivo, e
        quindi la risposta giusta non è riprovare più in fretta ma
        rallentare tutto quanto per un po'."""
        if secondi <= 0:
            return
        self._prossimo_turno = max(self._prossimo_turno, time.monotonic()) + secondi
        # e lo scriviamo anche su disco, così vale pure per il prossimo processo
        if self._freno is not None:
            self._freno.scrivi(secondi)


# Oggetti unici per tutto il programma. cache e freno vengono ricreati da
# main() con i parametri da riga di comando; qui servono valori di partenza
# perché le funzioni sotto li usano a livello di modulo.
cache = CacheCDX(attiva=False)     # disattivata finché main() non la accende
freno = FrenoPersistente()
cronometro = Cronometro()

# unico limitatore per tutto il programma
limitatore = _LimitatoreRichieste(freno)


class _ContatoreErrori:
    """Tiene il conto degli errori di rete, per accorgersi quando è
    inutile andare avanti.

    Perché serve: se la Wayback Machine smette di rispondere (di solito
    perché ci ha limitati: troppe richieste ravvicinate e le connessioni
    vengono rifiutate), il programma così com'era continuava imperterrito
    a provare tutti i candidati, stampava "salto questa piattaforma" cento
    volte e alla fine produceva comunque dei PUNTEGGI - calcolati però su
    richieste quasi tutte fallite. Numeri che sembrano validi ma non hanno
    dati dietro: la cosa peggiore che possa capitare, perché non te ne
    accorgi guardando il CSV. Meglio fermarsi e dirlo chiaramente.

    Non gira su più thread (le richieste partono tutte una alla volta,
    vedi sopra): è un contatore condiviso tra le funzioni che fanno
    richieste di rete, ma non serve nessun lock."""

    # In una run che dura ore (tante piattaforme per tanti candidati), un
    # blocco temporaneo di archive.org - un 503 prolungato sotto carico, un
    # rate limit che si scioglie da solo dopo un po' - non è la stessa cosa
    # di un blocco permanente. Prima di arrenderci per il resto della notte
    # concediamo qualche "seconda possibilità": una pausa più lunga (non i
    # ~3.5s dei retry automatici di build_session, minuti veri) e poi si
    # riprova. Solo se anche dopo tutte le pause concesse la rete resta giù,
    # ci arrendiamo davvero.
    RAFFREDDAMENTO_MINUTI = 5
    MAX_RAFFREDDAMENTI = 3

    def __init__(self, soglia=8):
        self.soglia = soglia          # quanti errori di FILA prima di arrendersi
        self.consecutivi = 0
        self.falliti = 0
        self.riusciti = 0
        self.raffreddamenti_usati = 0
        self.sovraccarichi = 0        # 503 consecutivi, per la pausa crescente
        self.lenti = 0                # timeout: risposte mai arrivate in tempo
        # QUALI piattaforme non siamo riusciti a contattare. Senza questo
        # elenco, una piattaforma irraggiungibile risultava indistinguibile
        # da una piattaforma dove lo username non esiste: tutte e due
        # "0 snapshot". Ed è una differenza grossa, perché su quei numeri
        # si sceglie la piattaforma di riferimento dell'intera indagine.
        self.piattaforme_fallite = set()
        # DATI PERSI, contati a parte dagli errori.
        # Sono due domande diverse e prima le confondevo in un contatore solo:
        #   - "devo rallentare?"  -> errori consecutivi, raffreddamento
        #   - "il risultato è completo?" -> dati persi
        # Un timeout, per esempio, NON deve far scattare il raffreddamento (è
        # il servizio lento, non giù), ma è comunque un'informazione che
        # manca. Contandolo solo come "lento" l'indagine risultava pulita pur
        # essendo calcolata su dati mancanti. Qui finisce OGNI cosa che
        # avremmo voluto sapere e non sappiamo: query CDX fallite, pagine non
        # scaricate, foto non scaricate, piattaforme saltate.
        self.dati_persi = 0
        self.perdite = []             # (dove, motivo), per il CSV

    def segna_perdita(self, dove, motivo):
        self.dati_persi += 1
        self.perdite.append((dove, motivo))

    def segna_errore(self, piattaforma=None):
        self.consecutivi += 1
        self.falliti += 1
        if piattaforma:
            self.piattaforme_fallite.add(piattaforma)

    def segna_successo(self):
        self.consecutivi = 0          # basta una risposta buona per ripartire
        self.riusciti += 1
        self.sovraccarichi = 0        # anche il freno riparte da zero

    # pause via via più lunghe se i 503 continuano: la prima volta bastano
    # pochi secondi, se il servizio insiste conviene farsi da parte davvero
    PAUSE_SOVRACCARICO = (15, 30, 60, 120)

    def pausa_per_sovraccarico(self):
        """Quanti secondi frenare tutte le richieste dopo un codice di
        sovraccarico. Cresce se i 503 arrivano uno dietro l'altro."""
        i = min(self.sovraccarichi, len(self.PAUSE_SOVRACCARICO) - 1)
        self.sovraccarichi += 1
        return self.PAUSE_SOVRACCARICO[i]

    @property
    def rete_a_terra(self):
        """Vero quando ci sono stati troppi errori di fila: non ha più
        senso continuare l'indagine, almeno finché non si prova un
        raffreddamento (vedi prova_a_riprendere)."""
        return self.consecutivi >= self.soglia

    def prova_a_riprendere(self):
        """Chiamata quando rete_a_terra è vera: concede, se ne restano,
        un raffreddamento - aspetta qualche minuto vero (altro dai brevi
        retry automatici della sessione HTTP) e poi dà un'altra possibilità
        pulita al contatore. Torna True se ha aspettato ed è il caso di
        riprovare, False se i raffreddamenti concessi sono finiti e conviene
        arrendersi per il resto della run."""
        if self.raffreddamenti_usati >= self.MAX_RAFFREDDAMENTI:
            return False
        self.raffreddamenti_usati += 1
        print(f"\n[!!] {self.consecutivi} errori di rete consecutivi: la Wayback "
              f"Machine sembra irraggiungibile. Pausa di raffreddamento di "
              f"{self.RAFFREDDAMENTO_MINUTI} minuti (tentativo "
              f"{self.raffreddamenti_usati}/{self.MAX_RAFFREDDAMENTI}) prima di "
              f"arrendermi per il resto dell'indagine...\n")
        time.sleep(self.RAFFREDDAMENTO_MINUTI * 60)
        self.consecutivi = 0   # possibilità pulita, come dopo un successo vero
        return True

    def azzera(self):
        self.consecutivi = self.falliti = self.riusciti = 0
        self.raffreddamenti_usati = 0
        self.sovraccarichi = 0
        self.lenti = 0
        self.piattaforme_fallite = set()
        self.dati_persi = 0
        self.perdite = []


# contatore unico, condiviso da tutte le funzioni che fanno richieste
errori_rete = _ContatoreErrori()


def _frena_per_sovraccarico(response, dove):
    """Decide di quanto rallentare dopo un 429/503 e lo fa.

    Se il server manda l'header 'Retry-After' - che con un 429 ("Too Many
    Requests") è la norma - diamo retta a lui invece di tirare a indovinare:
    è il comportamento corretto verso un servizio pubblico gratuito, e in
    più ci dice DA SOLO quanto manca alla fine della limitazione, che senza
    header è un'informazione che non si può ricavare.

    Il valore viene comunque limitato: un 'Retry-After' di un'ora non deve
    lasciare il programma addormentato senza che l'utente sappia perché."""
    TETTO = 300   # oltre i 5 minuti non aspettiamo: meglio fermarsi e dirlo
    grezzo = None
    try:
        grezzo = response.headers.get("Retry-After")
    except Exception:
        grezzo = None
    if grezzo:
        try:
            chiesti = int(float(str(grezzo).strip()))
        except (TypeError, ValueError):
            # può essere anche una data HTTP invece di un numero di secondi:
            # in quel caso non la interpretiamo, usiamo la nostra scala
            chiesti = None
        if chiesti is not None and chiesti > 0:
            print(f"[~] {dove}: archive.org chiede di aspettare {chiesti}s "
                  f"(header Retry-After)")
            if chiesti > TETTO:
                print(f"[!!] Sono più dei {TETTO}s che siamo disposti ad "
                      f"attendere qui. La limitazione durerà ancora un po': "
                      f"conviene interrompere e riprovare fra "
                      f"{chiesti // 60} minuti circa.")
            limitatore.frena(min(chiesti, TETTO))
            return
    pausa = errori_rete.pausa_per_sovraccarico()
    limitatore.rallenta()
    codice = getattr(response, "status_code", "?")
    print(f"[~] {dove}: archive.org sovraccarico (HTTP {codice}), pausa di {pausa}s; "
          f"da ora una richiesta ogni {limitatore.fattore:g}x --delay")
    limitatore.frena(pausa)


def pagina_archiviata(archive_url, session, delay, timeout):
    """Scarica una pagina archiviata, passando dalla cache.

    Perché merita il suo posto in cache: misurato, le pagine archiviate sono
    il 29% delle richieste di un'indagine (18 su 63 su 'torvalds' con 10
    candidati) e sono di gran lunga le più PESANTI - una pagina social
    archiviata sta fra le centinaia di kB e i megabyte, contro i pochi kB di
    una risposta CDX. Senza cache, la parte più costosa del traffico si
    rifaceva da zero a ogni rilancio.

    E sono immutabili: uno snapshot a un timestamp dato non cambia mai più,
    quindi qui non serve nessuna scadenza.

    Nota sull'ordine: il turno nella fila si aspetta DOPO il controllo della
    cache, così una pagina già in cache non costa --delay secondi a vuoto.
    """
    html = cache.leggi_pagina(archive_url)
    if html is None and _SOLO_CACHE:
        _manca_in_cache("pagina archiviata")
        return ""
    if html is not None:
        return html
    limitatore.attendi(delay)
    partenza = time.monotonic()
    html = fetch_archive_html(archive_url, session=session,
                              headers=HEADERS, timeout=timeout)
    dominio = domain_from_archive_url(archive_url) or "pagina"
    if html is None:
        # NON arrivata: è una perdita, e non va in cache (la prossima volta
        # deve essere richiesta di nuovo, non ricordata come vuota)
        cronometro.registra(time.monotonic() - partenza, dominio, "persa")
        errori_rete.segna_perdita(f"pagina {dominio}", "non scaricata")
        return ""
    cronometro.registra(time.monotonic() - partenza, dominio,
                        "ok" if html else "vuota")
    if html:
        cache.scrivi_pagina(archive_url, html)
    return html


def vuoto_se_none(valore):
    """Cella vuota nel CSV solo se il valore è davvero assente. Scritto come
    funzione perché 'valore or ""' sbaglia su 0 e su 0.0, che qui sono
    informazioni vere (distanza 0 = immagini identiche)."""
    return "" if valore is None else valore


def hash_foto(foto_url, username, session, delay, timeout):
    """Hash percettivo della foto profilo, passando dalla cache.

    Torna (hash, motivo). Il motivo è la ragione per cui non c'è un hash
    (immagine troppo piccola, uniforme, non scaricabile): finisce nel CSV, così
    una cella vuota si distingue da "non ci ho provato".

    Come le pagine: lo snapshot è immutabile, quindi l'hash si calcola una
    volta sola per sempre, e il turno nella fila si aspetta solo se la
    richiesta deve partire davvero.
    """
    if not foto_url:
        return None, "nessuna foto nel profilo"
    gia_visto = cache.leggi_foto(foto_url)
    if gia_visto is not None:
        return gia_visto
    if _SOLO_CACHE:
        _manca_in_cache("foto profilo")
        return None, "non in cache (--solo-cache)"

    limitatore.attendi(delay)
    partenza = time.monotonic()
    dati, errore = osint_foto.scarica(foto_url, session, timeout=timeout)
    cronometro.registra(time.monotonic() - partenza, "foto profilo",
                        "ok" if dati else "persa")
    if not dati and (errore in ("HTTP 401", "HTTP 403", "HTTP 404", "HTTP 410", "HTTP 451",
                                 "immagine troppo grande")
                     or any(t in (errore or "") for t in
                            ("InvalidSchema", "MissingSchema", "InvalidURL"))):
        # (InvalidSchema & co.: l'indirizzo della foto preso dalla pagina non è
        # un URL valido. Anche questo è definitivo: riprovare non lo aggiusta.)
        # NON è un problema di rete: archive.org ha risposto, e ha detto che
        # quell'immagine non l'ha mai salvata (404/410) o non la serve (403).
        # È una risposta definitiva, come "0 snapshot": si mette in cache e
        # NON conta come dato perso. Prima contava, e rendeva "incompleta" ogni
        # indagine con un avatar non archiviato: torvalds risultava incompleto
        # per 8 foto mai salvate, e sarebbe stato escluso dalla calibrazione.
        motivo = f"foto non archiviata ({errore})"
        cache.scrivi_foto(foto_url, None, username, motivo)
        return None, motivo
    if not dati:
        # BUG CORRETTO: prima qui si scriveva in cache anche il fallimento,
        # quindi un timeout passeggero diventava "questa foto non ha hash"
        # PER SEMPRE, e nessun rilancio l'avrebbe più riscaricata. Un
        # download fallito è una perdita temporanea: si conta e basta.
        errori_rete.segna_perdita("foto profilo", errore)
        return None, errore
    hash_foto, motivo = osint_foto.dhash(dati)
    if not osint_foto.PILLOW_DISPONIBILE:
        # NON in cache: dipende dal computer, non dall'immagine. Messo in cache
        # (che per le foto non scade mai) vorrebbe dire che, anche dopo aver
        # installato Pillow, quelle foto non verrebbero più analizzate.
        # È un'informazione che volevamo e non abbiamo: conta come perdita.
        errori_rete.segna_perdita("foto profilo", "Pillow non installato")
        return None, motivo
    cache.scrivi_foto(foto_url, hash_foto, username, motivo)
    return hash_foto, motivo


def richiesta_cdx(cdx_url, session, delay, timeout, dove, dove_errore=None,
                 facoltativa=False):
    """Unico punto da cui partono le richieste alla CDX API.

    Prima c'erano due copie quasi identiche di questa logica (una in
    fetch_snapshots, una in discover_prefix_candidates) e ogni correzione
    andava fatta due volte. Adesso tutto passa di qui, e di conseguenza
    cache, freno e cronometro valgono automaticamente per entrambe.

    Ordine delle operazioni, che non è casuale:

      1. la CACHE per prima, PRIMA del controllo sulla rete. Se la risposta
         ce l'abbiamo già su disco, il fatto che archive.org sia
         irraggiungibile in questo momento non ci riguarda: il dato è
         valido lo stesso e non costa niente.
      2. poi il controllo "rete a terra": inutile mettersi in fila per una
         richiesta che sappiamo già che fallirà.
      3. poi il turno nella fila globale (limitatore).
      4. infine la richiesta vera, cronometrata.

    Torna la coppia (dati, esito), dove dati è la lista JSON già decodificata
    (None se non c'è) ed esito è una di queste stringhe:
        'cache'         risolta senza toccare la rete
        'ok'            200 con JSON valido
        'http-<codice>' ha risposto, ma non 200
        'json-rotto'    200 ma corpo illeggibile
        'errore-rete'   timeout, connessione rifiutata, ecc.
        'rete-a-terra'  non ci abbiamo nemmeno provato

    facoltativa=True: chi chiama ha un piano B (un'altra query che dà la
    stessa informazione). Un fallimento allora NON è un dato perso, e non si
    registra come tale: se anche il piano B fallisce, la perdita la registra
    quello. Un 504 qui vuol dire "query troppo pesante", non "servizio
    sovraccarico", quindi non fa frenare; 429/503 invece sì, come sempre.
    """
    corpo = cache.leggi(cdx_url)
    if corpo is not None:
        try:
            return _allinea_colonne(json.loads(corpo), cdx_url), "cache"
        except ValueError:
            pass   # cache corrotta: si rifà la richiesta come se non ci fosse

    if _SOLO_CACHE:
        if not facoltativa:
            _manca_in_cache(dove)
        return None, "rete-a-terra"
    if errori_rete.rete_a_terra:
        errori_rete.segna_perdita(dove, "non richiesta: rete a terra")
        return None, "rete-a-terra"

    for tentativo in range(1, _TENTATIVI_SOVRACCARICO + 1):
        response, durata, esito = _una_richiesta_cdx(cdx_url, session, delay, timeout,
                                                     dove, dove_errore, facoltativa)
        if esito != "sovraccarico":
            break
        if tentativo < _TENTATIVI_SOVRACCARICO:
            print(f"    [~] {dove}: riprovo la stessa richiesta dopo la pausa "
                  f"(tentativo {tentativo + 1}/{_TENTATIVI_SOVRACCARICO})")
    if esito == "sovraccarico":
        # anche una richiesta facoltativa si riprova dopo un 503 (è passeggero);
        # solo il 504, che per lei vuol dire "query troppo pesante", no. Se però
        # fallisce anche l'ultimo tentativo, per lei non è un dato perso.
        if not facoltativa:
            errori_rete.segna_perdita(dove, f"HTTP {response.status_code} "
                                            f"({_TENTATIVI_SOVRACCARICO} tentativi)")
        return None, f"http-{response.status_code}"
    if esito != "ok":
        return None, esito

    # segniamo il successo SOLO su 200: un 503 "perdonato" qui azzererebbe il
    # contatore degli errori consecutivi e il raffreddamento non scatterebbe mai
    errori_rete.segna_successo()
    limitatore.risposta_buona()
    cronometro.registra(durata, dove, "ok")
    if durata >= _RICHIESTA_LENTA:
        # una richiesta che ci mette molto è quella che rischia di sbattere
        # contro il timeout e di essere contata come "errore di rete" quando
        # errore non è: meglio vederlo mentre succede
        print(f"    [~] {dove}: la CDX ha impiegato {durata:.1f}s "
              f"(timeout impostato a {timeout:.0f}s)")

    testo = response.text
    if not testo.strip():
        cache.scrivi(cdx_url, 200, "[]")
        return [], "ok"
    try:
        dati = _allinea_colonne(response.json(), cdx_url)
    except ValueError:
        # 200 ma JSON troncato o corrotto: capita quando il servizio è sotto
        # carico. NON va messo in cache e NON va trattato come "nessun
        # risultato": è un dato mancante.
        if not facoltativa:
            errori_rete.segna_perdita(dove, "JSON troncato")
        return None, "json-rotto"
    cache.scrivi(cdx_url, 200, testo)
    return dati, "ok"


def _una_richiesta_cdx(cdx_url, session, delay, timeout, dove, dove_errore, facoltativa):
    """Un solo tentativo: attende il turno, fa la richiesta, registra l'esito.
    Torna (risposta, durata, esito), con esito 'ok', 'sovraccarico' (da
    riprovare: il freno è già stato tirato) oppure l'esito finale da
    restituire ('troppo-lento', 'errore-rete', 'http-<codice>')."""
    limitatore.attendi(delay)
    partenza = time.monotonic()
    try:
        indirizzo = (cdx_url.replace(_CDX_ORIGINALE, _CDX_TIMEMAP, 1) if _USA_TIMEMAP else cdx_url)
        response = session.get(indirizzo, timeout=timeout)
    except requests.exceptions.Timeout as e:
        # UNA RISPOSTA LENTA NON È UN SERVIZIO GIÙ. Misurato sul campo: la
        # CDX può metterci 33s per due righe e 15s per 4667, cioè il tempo
        # dipende dal carico del servizio, non dalla query. Contare un timeout
        # come "errore di rete" alla pari di una connessione rifiutata voleva
        # dire far scattare raffreddamenti da 5 minuti per colpa di una
        # lentezza passeggera. Qui lo registriamo, rallentiamo un po' (il
        # servizio è evidentemente carico) ma NON lo facciamo contare verso
        # gli errori consecutivi.
        cronometro.registra(time.monotonic() - partenza, dove, type(e).__name__)
        errori_rete.lenti += 1
        if facoltativa:
            return None, 0.0, "troppo-lento"
        limitatore.frena(_FRENO_DOPO_TIMEOUT)
        print(f"[~] {dove}: nessuna risposta entro {timeout:.0f}s. Non è un errore "
              f"di rete, è il servizio lento: rallento di {_FRENO_DOPO_TIMEOUT}s.")
        errori_rete.segna_perdita(dove, f"nessuna risposta entro {timeout:.0f}s")
        return None, 0.0, "troppo-lento"
    except requests.exceptions.RequestException as e:
        cronometro.registra(time.monotonic() - partenza, dove, type(e).__name__)
        errori_rete.segna_errore(dove_errore)
        if not facoltativa:
            errori_rete.segna_perdita(dove, type(e).__name__)
        return None, 0.0, "errore-rete"
    durata = time.monotonic() - partenza

    if response.status_code != 200:
        cronometro.registra(durata, dove, f"http-{response.status_code}")
        if facoltativa and response.status_code == 504:
            return response, durata, "http-504"
        if response.status_code in _CODICI_SOVRACCARICO:
            # il problema è il ritmo complessivo, non questa richiesta:
            # si frena tutto e lo si conta come errore vero, se no una
            # raffica di 503 non fa mai scattare il raffreddamento
            errori_rete.segna_errore(dove_errore)
            _frena_per_sovraccarico(response, dove)
            return response, durata, "sovraccarico"
        if not facoltativa:
            errori_rete.segna_perdita(dove, f"HTTP {response.status_code}")
        return response, durata, f"http-{response.status_code}"
    return response, durata, "ok"



def _allinea_colonne(dati, cdx_url):
    """Controlla che le colonne della risposta siano quelle chieste con fl=.
    Il codice legge le righe per posizione (timestamp, original, ...): se un
    servizio restituisse colonne diverse o in un altro ordine, le righe
    verrebbero scartate in silenzio e un elenco pieno sembrerebbe vuoto.
    Se l'intestazione contiene le colonne chieste le riordina, altrimenti
    solleva ValueError (risposta illeggibile: dato perso, non "zero")."""
    m = re.search(r"[?&]fl=([^&]+)", cdx_url)
    if not m or not dati or not isinstance(dati, list) or not dati[0]:
        return dati
    chieste = m.group(1).split(",")
    intest = dati[0]
    if intest == chieste:
        return dati
    if not all(c in intest for c in chieste):
        raise ValueError(f"colonne inattese: {intest}")
    pos = [intest.index(c) for c in chieste]
    fuori = [chieste]
    for riga in dati[1:]:
        if isinstance(riga, list) and len(riga) == len(intest):
            fuori.append([riga[i] for i in pos])
        else:
            fuori.append(riga)      # righe della chiave di ripresa ([] e [chiave])
    return fuori


def configura(nuova_cache=None, filtri_server=None, solo_cache=None, timemap=None):
    """Sostituisce gli oggetti condivisi del modulo. La chiama main() dopo aver
    letto le opzioni da riga di comando (vedi la nota in cima al file)."""
    global cache, limitatore, _FILTRI_SERVER, _SOLO_CACHE, _USA_TIMEMAP
    if timemap is not None:
        _USA_TIMEMAP = timemap
    if solo_cache is not None:
        _SOLO_CACHE = solo_cache
    if nuova_cache is not None:
        cache = nuova_cache
    if filtri_server is not None:
        _FILTRI_SERVER = filtri_server
    return cache


def filtri_server():
    """Il pezzo di query che chiede ad archive.org di filtrare lato suo.
    Serve come funzione perché chi costruisce le URL (osint.py) deve leggere
    il valore CORRENTE, non quello del momento dell'import."""
    return _FILTRI_SERVER


# Una data nel futuro: Wayback reindirizza alla cattura PIÙ VICINA, cioè
# all'ultima. Verificato sul servizio vero: in 3 casi su 3
# la data d'arrivo coincideva con l'ultima cattura data da CDX.
_DATA_FUTURA = "99991231235959"
_RE_ARCHIVIO = re.compile(r"^https?://web\.archive\.org/web/(\d{14})[a-z_]*/(.+)$")


def archiviato(originale, session, delay, timeout, dove="controllo 404"):
    """Controllo veloce: la Wayback Machine ha QUALCOSA per questo indirizzo?

    Si chiede la pagina a una data nel futuro SENZA seguire il rimando: se
    l'archivio ha almeno una copia risponde con un rimando (3xx) alla più
    recente, se non ha niente risponde 404. Costa circa 2 secondi, contro i
    10-60 di una query CDX. Torna:
      False  -> sicuramente non archiviato (404): la query CDX si può saltare
      True   -> qualcosa c'è: serve la query CDX per sapere cosa e quando
      None   -> non si sa (errore, sovraccarico): si fa la query CDX come prima
    Solo il "False" fa risparmiare, ed è l'unico caso che è stato verificato
    sul servizio vero prima di usarlo.
    Il risultato va nella cache con scadenza, come le risposte CDX."""
    chiave = f"archiviato::{originale}"
    salvato = cache.leggi(chiave)
    if salvato in ("si", "no"):
        return salvato == "si"
    if _SOLO_CACHE or errori_rete.rete_a_terra:
        return None
    limitatore.attendi(delay)
    partenza = time.monotonic()
    try:
        r = session.get(f"https://web.archive.org/web/{_DATA_FUTURA}/{originale}",
                        headers=HEADERS, timeout=timeout, allow_redirects=False)
    except requests.exceptions.RequestException as e:
        cronometro.registra(time.monotonic() - partenza, dove, type(e).__name__)
        return None
    cronometro.registra(time.monotonic() - partenza, dove, f"http-{r.status_code}")
    if r.status_code in _CODICI_SOVRACCARICO:
        errori_rete.segna_errore(None)
        _frena_per_sovraccarico(r, dove)
        return None
    if r.status_code == 404:
        errori_rete.segna_successo()
        limitatore.risposta_buona()
        cache.scrivi(chiave, 200, "no")
        return False
    if r.status_code in (200, 301, 302, 303, 307, 308):
        errori_rete.segna_successo()
        limitatore.risposta_buona()
        cache.scrivi(chiave, 200, "si")
        return True
    return None


def ultima_cattura(originale, session, delay, timeout, dove="pagina"):
    """L'ULTIMA cattura di un URL, senza passare da CDX.

    Perché esiste: per ogni candidato servivano una query CDX (per sapere le
    date delle catture) e una pagina (per nome, bio e link). Misurato sul
    servizio vero, CDX impiega 12 s di mediana e ogni tanto risponde 503;
    una pagina 2 s. Chiedendo a Wayback una data nel futuro si riceve
    direttamente l'ultima cattura, e l'indirizzo finale del reindirizzamento ne
    contiene la data: con UNA richiesta alla parte veloce del servizio si hanno
    sia la pagina sia la data, e la query CDX non serve più.

    Torna (url_archivio_finale, timestamp_14_cifre, html) oppure None.
    None può voler dire due cose diverse, e chi chiama le distingue così:
      - perdita di rete: è già stata registrata qui (segna_perdita);
      - nessuna data leggibile nell'indirizzo finale: niente perdita
        registrata, chi chiama ripiega sulla query CDX.
    """
    chiave = f"ultima::{originale}"
    # L'ULTIMA cattura cambia nel tempo (se ne aggiungono di nuove): la
    # corrispondenza va nella cache CON scadenza. La pagina invece, una volta
    # nota la sua data, è immutabile e va nella cache delle pagine.
    salvato = cache.leggi(chiave)
    if salvato:
        m = _RE_ARCHIVIO.match(salvato)
        html = cache.leggi_pagina(salvato)
        if m and html is not None:
            return salvato, m.group(1), html

    if _SOLO_CACHE:
        _manca_in_cache(dove)
        return None
    if errori_rete.rete_a_terra:
        errori_rete.segna_perdita(dove, "non richiesta: rete a terra")
        return None
    limitatore.attendi(delay)
    partenza = time.monotonic()
    try:
        r = session.get(f"https://web.archive.org/web/{_DATA_FUTURA}/{originale}",
                        headers=HEADERS, timeout=timeout)
    except requests.exceptions.Timeout as e:
        cronometro.registra(time.monotonic() - partenza, dove, type(e).__name__)
        errori_rete.lenti += 1
        errori_rete.segna_perdita(dove, f"nessuna risposta entro {timeout:.0f}s")
        limitatore.frena(_FRENO_DOPO_TIMEOUT)
        return None
    except requests.exceptions.RequestException as e:
        cronometro.registra(time.monotonic() - partenza, dove, type(e).__name__)
        errori_rete.segna_errore(dove)
        errori_rete.segna_perdita(dove, type(e).__name__)
        return None
    cronometro.registra(time.monotonic() - partenza, dove,
                        "ok" if r.status_code == 200 else f"http-{r.status_code}")
    if r.status_code in CODICI_DEFINITIVI:
        # l'ultima cattura è una pagina d'errore (account chiuso, 404, 403):
        # risposta DEFINITIVA, non una perdita. Si torna None SENZA registrare
        # perdite, e chi chiama ripiega sulla query CDX, che coi filtri tiene
        # solo le catture con risposta 200.
        errori_rete.segna_successo()
        limitatore.risposta_buona()
        return None
    if r.status_code != 200:
        if r.status_code in _CODICI_SOVRACCARICO:
            errori_rete.segna_errore(dove)
            _frena_per_sovraccarico(r, dove)
        errori_rete.segna_perdita(dove, f"HTTP {r.status_code}")
        return None
    errori_rete.segna_successo()
    limitatore.risposta_buona()
    finale = getattr(r, "url", None) or ""
    m = _RE_ARCHIVIO.match(finale)
    if not m:
        return None          # nessuna data leggibile: chi chiama usa CDX
    finale_pulito = f"https://web.archive.org/web/{m.group(1)}/{m.group(2)}"
    cache.scrivi(chiave, 200, finale_pulito)
    testo = testo_della_risposta(r)
    if testo:
        cache.scrivi_pagina(finale_pulito, testo)
    return finale_pulito, m.group(1), testo
