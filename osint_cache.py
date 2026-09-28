"""
Memoria fra una richiesta e l'altra, e fra un processo e l'altro.

Perché esiste questo file
--------------------------
Il batch da 100 username lancia osint.py come processo separato per ogni
username. Ogni volta che il processo finisce, muoiono con lui il limitatore
di richieste e il contatore degli errori: il freno messo dopo un 503
sull'username numero 37 non arriva mai all'username numero 38, che riparte
a ritmo pieno. Dal punto di vista di archive.org siamo un client che ogni
volta dimentica di essersi sentito dire "rallenta".

Qui dentro ci sono le tre cose che devono sopravvivere alla morte del
processo:

  CacheCDX          le risposte già ottenute, su disco. Rilanciare il
                    batch dopo un blocco non ricosta 8431 richieste: costa
                    solo quelle nuove.
  FrenoPersistente  l'istante prima del quale non si deve mandare nulla,
                    scritto su file. Così il freno attraversa i processi.
  Cronometro        quanto ci mette ogni richiesta, per sapere DOVE se ne
                    va il tempo invece di immaginarlo.

Nessuna dipendenza esterna: sqlite3 e json stanno nella libreria standard.
"""

import gzip
import json
import os
import sqlite3
import time

# --------------------------------------------------------------------------
# 1. Cache delle risposte CDX
# --------------------------------------------------------------------------

# SQLite memorizza gli interi come 64 bit CON SEGNO: il massimo è 2^63 - 1.
# Un dHash è un intero a 64 bit SENZA segno, e circa la metà degli hash
# reali ha il bit più alto acceso, cioè vale 2^63 o più: inserirlo così
# com'è fa esplodere sqlite3 con OverflowError. Nei primi test non si vedeva
# perché l'avatar di prova aveva, per caso, un hash piccolo.
# La soluzione standard: si salva la stessa sequenza di 64 bit letta come
# numero con segno, e la si riconverte in lettura. Nessuna informazione persa.
_DUE_ALLA_63 = 1 << 63
_DUE_ALLA_64 = 1 << 64


def _hash_a_sqlite(h):
    return None if h is None else (h - _DUE_ALLA_64 if h >= _DUE_ALLA_63 else h)


def _hash_da_sqlite(h):
    return None if h is None else (h + _DUE_ALLA_64 if h < 0 else h)


class CacheCDX:
    """Ricorda su disco le risposte della CDX API, con chiave l'URL completo.

    Cosa si mette in cache e cosa no:
      - SOLO le risposte 200. Un 429 o un 503 dicono "adesso non posso",
        non "questo URL non esiste": ricordarseli vorrebbe dire trascinare
        un errore temporaneo per giorni.
      - Con una scadenza (ttl_giorni). Gli snapshot nuovi si aggiungono di
        continuo, quindi una risposta di un mese fa è probabilmente
        incompleta. Una settimana è un compromesso ragionevole: durante lo
        sviluppo si rilancia lo stesso username decine di volte nello stesso
        giorno, ed è lì che serve.

    La cache NON cambia i risultati: cambia solo quante volte si disturba
    archive.org per ottenerli.
    """

    def __init__(self, percorso="osint_cache.sqlite", ttl_giorni=7, attiva=True):
        self.percorso = percorso
        self.ttl = max(0, float(ttl_giorni)) * 86400
        self.attiva = attiva
        self.letture = 0        # quante volte abbiamo evitato una richiesta
        self.scritture = 0      # quante risposte nuove abbiamo salvato
        self.scadute = 0        # quante trovate ma troppo vecchie
        self.pagine_lette = 0   # pagine archiviate riprese dalla cache
        self.pagine_scritte = 0
        self.foto_lette = 0     # hash di foto ripresi dalla cache
        self.foto_scritte = 0
        self._db = None
        if self.attiva:
            self._apri()

    def _apri(self):
        try:
            self._db = sqlite3.connect(self.percorso)
            self._db.execute("""
                CREATE TABLE IF NOT EXISTS risposte (
                    url      TEXT PRIMARY KEY,
                    stato    INTEGER NOT NULL,
                    corpo    TEXT NOT NULL,
                    salvata  REAL NOT NULL
                )
            """)
            # Tabella separata per le PAGINE archiviate, e separata per un
            # motivo preciso: una query CDX cambia col tempo (ogni giorno si
            # aggiungono catture nuove, quindi ha senso una scadenza), mentre
            # https://web.archive.org/web/20150101120000/... è congelato per
            # sempre. Una pagina archiviata a un timestamp dato non cambierà
            # mai più: non serve TTL, e ricaricarla è sempre spreco.
            # Il corpo è compresso perché sono pagine HTML intere di social
            # network, non righe di indice: senza gzip la cache diventerebbe
            # enorme in fretta.
            self._db.execute("""
                CREATE TABLE IF NOT EXISTS pagine (
                    url      TEXT PRIMARY KEY,
                    html     BLOB NOT NULL,
                    salvata  REAL NOT NULL
                )
            """)
            # Hash delle foto profilo. Non salviamo i byte dell'immagine ma
            # solo la sua firma a 64 bit: è tutto ciò che serve al confronto
            # e occupa niente. Come le pagine, uno snapshot è immutabile,
            # quindi nessuna scadenza.
            # 'username' serve alla guardia sugli avatar di default: è su
            # quanti username DIVERSI compare lo stesso hash che si capisce se
            # l'immagine identifica una persona o è la sagoma grigia che la
            # piattaforma dà a tutti (vedi osint_foto.hash_distintivo).
            self._db.execute("""
                CREATE TABLE IF NOT EXISTS foto (
                    url       TEXT PRIMARY KEY,
                    hash      INTEGER,
                    username  TEXT,
                    motivo    TEXT,
                    salvata   REAL NOT NULL
                )
            """)
            self._db.commit()
        except sqlite3.Error as e:
            # una cache che non si apre non deve impedire l'indagine: si
            # continua senza, dicendolo
            print(f"[!] Cache non disponibile ({e}); proseguo senza.")
            self.attiva = False
            self._db = None

    def leggi(self, url):
        """Torna il corpo della risposta salvata, o None se non c'è o è
        scaduta."""
        if not self.attiva or self._db is None:
            return None
        try:
            riga = self._db.execute(
                "SELECT corpo, salvata FROM risposte WHERE url = ?", (url,)
            ).fetchone()
        except sqlite3.Error:
            return None
        if not riga:
            return None
        corpo, salvata = riga
        if self.ttl and (time.time() - salvata) > self.ttl:
            self.scadute += 1
            return None
        self.letture += 1
        return corpo

    def scrivi(self, url, stato, corpo):
        """Salva SOLO le risposte 200 (vedi docstring della classe)."""
        if not self.attiva or self._db is None or stato != 200:
            return
        try:
            self._db.execute(
                "INSERT OR REPLACE INTO risposte (url, stato, corpo, salvata) "
                "VALUES (?, ?, ?, ?)",
                (url, stato, corpo, time.time()),
            )
            self._db.commit()
            self.scritture += 1
        except sqlite3.Error:
            pass   # se il salvataggio fallisce pazienza, si è solo perso un risparmio

    # ---------------------------- pagine archiviate (immutabili, senza TTL)

    TETTO_PAGINA = 4 * 1024 * 1024   # oltre i 4 MB non la teniamo

    def leggi_pagina(self, url):
        """Torna l'HTML salvato per questo snapshot, o None."""
        if not self.attiva or self._db is None:
            return None
        try:
            riga = self._db.execute(
                "SELECT html FROM pagine WHERE url = ?", (url,)
            ).fetchone()
        except sqlite3.Error:
            return None
        if not riga:
            return None
        try:
            testo = gzip.decompress(riga[0]).decode("utf-8", "replace")
        except (OSError, EOFError, UnicodeError):
            return None
        self.pagine_lette += 1
        return testo

    def scrivi_pagina(self, url, html):
        if not self.attiva or self._db is None or not html:
            return
        dati = html.encode("utf-8", "replace")
        if len(dati) > self.TETTO_PAGINA:
            return
        try:
            self._db.execute(
                "INSERT OR REPLACE INTO pagine (url, html, salvata) VALUES (?, ?, ?)",
                (url, gzip.compress(dati, 6), time.time()),
            )
            self._db.commit()
            self.pagine_scritte += 1
        except sqlite3.Error:
            pass

    def pagine_salvate(self):
        if not self.attiva or self._db is None:
            return 0
        try:
            return self._db.execute("SELECT COUNT(*) FROM pagine").fetchone()[0]
        except sqlite3.Error:
            return 0

    # ------------------------------------------- hash delle foto profilo

    def leggi_foto(self, url):
        """Torna (hash, motivo) se questo URL è già stato hashato, altrimenti
        None. Si ricorda anche il MOTIVO dello scarto: se un'immagine era
        troppo piccola resta troppo piccola, non serve riscaricarla."""
        if not self.attiva or self._db is None:
            return None
        try:
            riga = self._db.execute(
                "SELECT hash, motivo FROM foto WHERE url = ?", (url,)).fetchone()
        except sqlite3.Error:
            return None
        if not riga:
            return None
        self.foto_lette += 1
        return (_hash_da_sqlite(riga[0]), riga[1] or "")

    def scrivi_foto(self, url, hash_foto, username, motivo=""):
        if not self.attiva or self._db is None:
            return
        try:
            self._db.execute(
                "INSERT OR REPLACE INTO foto (url, hash, username, motivo, salvata) "
                "VALUES (?, ?, ?, ?, ?)",
                (url, _hash_a_sqlite(hash_foto), username, motivo, time.time()))
            self._db.commit()
            self.foto_scritte += 1
        except (sqlite3.Error, OverflowError):
            # OverflowError non è un sqlite3.Error: prima non veniva
            # intercettato e interrompeva l'intera indagine
            pass

    def censimento_foto(self):
        """Tutte le coppie (hash, username) viste finora, per la guardia sugli
        avatar di default. La tabella resta piccola (un hash per profilo
        analizzato), quindi leggerla intera è irrilevante."""
        if not self.attiva or self._db is None:
            return []
        try:
            return [(_hash_da_sqlite(h), u) for h, u in self._db.execute(
                "SELECT hash, username FROM foto WHERE hash IS NOT NULL")]
        except sqlite3.Error:
            return []

    def righe_salvate(self):
        if not self.attiva or self._db is None:
            return 0
        try:
            return self._db.execute("SELECT COUNT(*) FROM risposte").fetchone()[0]
        except sqlite3.Error:
            return 0

    def riepilogo(self):
        if not self.attiva:
            return "cache disattivata"
        return (f"cache CDX: {self.letture} richieste evitate, "
                f"{self.scritture} risposte nuove, {self.scadute} scadute, "
                f"{self.righe_salvate()} in archivio\n"
                f"cache pagine: {self.pagine_lette} download evitati, "
                f"{self.pagine_scritte} pagine nuove, "
                f"{self.pagine_salvate()} in archivio\n"
                f"cache foto: {self.foto_lette} hash riusati, "
                f"{self.foto_scritte} foto nuove hashate")


# --------------------------------------------------------------------------
# 2. Freno che sopravvive al processo
# --------------------------------------------------------------------------

class FrenoPersistente:
    """Scrive su file l'istante prima del quale non si deve mandare nulla.

    È volutamente stupido: un solo numero, il timestamp assoluto (time.time,
    non time.monotonic, perché monotonic non ha senso fra processi diversi).
    Lo legge chi parte, lo scrive chi frena.
    """

    def __init__(self, percorso="osint_freno.json", attivo=True):
        self.percorso = percorso
        self.attivo = attivo

    def leggi(self):
        """Quanti secondi bisogna ancora aspettare (0 se nessuno)."""
        if not self.attivo:
            return 0.0
        try:
            with open(self.percorso, "r", encoding="utf-8") as f:
                dati = json.load(f)
            manca = float(dati.get("non_prima_di", 0)) - time.time()
            return max(0.0, manca)
        except (OSError, ValueError, TypeError):
            return 0.0

    def scrivi(self, secondi):
        if not self.attivo or secondi <= 0:
            return
        scadenza = time.time() + secondi
        # non accorciare mai un freno già scritto da qualcun altro
        try:
            with open(self.percorso, "r", encoding="utf-8") as f:
                esistente = float(json.load(f).get("non_prima_di", 0))
            scadenza = max(scadenza, esistente)
        except (OSError, ValueError, TypeError):
            pass
        try:
            with open(self.percorso, "w", encoding="utf-8") as f:
                json.dump({"non_prima_di": scadenza}, f)
        except OSError:
            pass

    def azzera(self):
        try:
            os.remove(self.percorso)
        except OSError:
            pass


# --------------------------------------------------------------------------
# 3. Cronometro delle richieste
# --------------------------------------------------------------------------

class Cronometro:
    """Tiene i tempi di ogni richiesta di rete davvero partita.

    Le richieste risolte dalla cache NON si contano: non sono richieste.
    Serve a rispondere alla domanda "dove se ne va il tempo" con dei numeri
    invece che a naso - ed è anche il modo per accorgersi che un timeout
    troppo corto sta trasformando le query lente in 'errori di rete'.
    """

    def __init__(self):
        self.tempi = []        # (secondi, dove, esito)
        self.inizio = time.time()

    def registra(self, secondi, dove, esito):
        self.tempi.append((secondi, dove, esito))

    @property
    def totale_richieste(self):
        return len(self.tempi)

    def _percentile(self, valori_ordinati, q):
        if not valori_ordinati:
            return 0.0
        i = int(round((len(valori_ordinati) - 1) * q))
        return valori_ordinati[i]

    def riepilogo(self, quante_lente=5):
        if not self.tempi:
            return "nessuna richiesta di rete effettuata (tutto dalla cache?)"
        secondi = sorted(t for t, _, _ in self.tempi)
        somma = sum(secondi)
        righe = [
            f"richieste di rete: {len(secondi)}",
            f"tempo speso in attesa di archive.org: {somma:.0f}s "
            f"({somma / 60:.1f} min) su {time.time() - self.inizio:.0f}s totali",
            f"per richiesta - minimo {secondi[0]:.2f}s, "
            f"mediana {self._percentile(secondi, 0.50):.2f}s, "
            f"90esimo percentile {self._percentile(secondi, 0.90):.2f}s, "
            f"massimo {secondi[-1]:.2f}s",
        ]
        lente = sorted(self.tempi, reverse=True)[:quante_lente]
        if lente:
            righe.append("le più lente:")
            for s, dove, esito in lente:
                righe.append(f"    {s:6.2f}s  {dove}  [{esito}]")
        return "\n".join(righe)
