# WayLinkage

Strumento OSINT per il collegamento di identità digitali fra piattaforme, basato
esclusivamente sulle copie archiviate dalla Wayback Machine. Sviluppato per la tesi
*Sviluppo di uno strumento OSINT per la correlazione di identità digitali
multi-piattaforma tramite profile matching* (Ingegneria Informatica, a.a. 2025/2026).

Il nome: *Way* richiama la Wayback Machine, da cui provengono tutti i dati, e la strada
che collega gli account di una stessa persona; *Linkage* il problema affrontato, lo
*user identity linkage*.

Dato uno username, WayLinkage cerca gli account che la stessa persona può avere su otto
piattaforme (GitHub, Twitter/X, Instagram, Reddit, Medium, Telegram, TikTok, Keybase),
con lo stesso nome o con nomi simili. Per ogni account trovato non dà un verdetto: calcola
un punteggio da 0 a 100 e riporta il valore di ciascun indizio su cui si basa, così che la
decisione finale resti a chi legge.

## Scelte di progetto
- **Nessun accesso riservato:** nessun login, nessun account creato.
- **Nessuna richiesta alle piattaforme:** solo copie pubbliche della Wayback Machine
  (CDX API e pagine archiviate), una richiesta alla volta, rallentando quando l'archivio
  lo chiede.
- **Minimizzazione:** si leggono solo nome, biografia, link esterni e foto del profilo;
  della foto si conserva un'impronta numerica (difference hash), non l'immagine.
- **Un dato mancante non deve mai sembrare un dato:** ogni informazione che l'archivio non
  ha fornito viene registrata con il motivo, e ogni indagine dichiara se è completa.

## Installazione
Serve Python 3 (provato con la 3.13 e la 3.14).
```bash
git clone https://github.com/magicruffolo/waylinkage.git
cd waylinkage
python3 -m venv .env
.env/bin/python3 -m pip install -r requirements.txt
```
Le librerie sono `requests`, `pandas` e `Pillow` (per le foto).

## Uso
Tutti i comandi si lanciano dalla cartella del repository.

**Un'indagine:**
```bash
.env/bin/python3 osint.py -u <username>
```

**Più indagini di fila**, da un file con uno username per riga:
```bash
.env/bin/python3 osint.py --lista nomi.txt
```

**Le opzioni usate per le indagini della tesi:**
```bash
.env/bin/python3 osint.py -u <username> --max-candidates 100 --campione-oltre-limite 30 \
    --max-euristiche 3 --delay 3 --controllo-404 --timemap
```

**Tutte le opzioni:**
```bash
.env/bin/python3 osint.py --help
```

## Dove finiscono i risultati
Tutto viene scritto nella cartella `dati/`, creata alla prima indagine:

| Percorso | Contenuto |
|---|---|
| `dati/indagini/OSINT_<username>_correlato.csv` | una riga per ogni copia archiviata di ogni candidato: punteggio, fascia di confidenza, valore di ogni indizio, pesi usati e stato della raccolta |
| `dati/indagini/OSINT_<username>_profilo.json` | la scheda riassuntiva della persona |
| `dati/osint_cache.sqlite` | le risposte dell'archivio già ricevute (database SQLite, un solo file) |
| `dati/osint_freno.json` | fino a quando non fare richieste, se l'archivio ha chiesto di rallentare |

Con `--cartella X` i risultati vanno nella cartella X.

Grazie alla cache, rilanciando un'indagine incompleta ripartono solo le richieste
mancanti. Le risposte della ricerca CDX scadono dopo 7 giorni (`--cache-ttl`, 0 = mai);
le pagine e le foto archiviate non scadono, perché una copia archiviata non cambia.
Con `--solo-cache` un'indagine si ripete senza rete, usando solo ciò che è già in cache.

## Il punteggio
È una media pesata di otto indizi, ciascuno fra 0 e 1:
- somiglianza dello username;
- somiglianza del testo di nome e biografia;
- sovrapposizione dei periodi di presenza nell'archivio;
- contenimento di un periodo nell'altro;
- presenza su più piattaforme, corretta per la rarità dello username;
- link esterni in comune;
- collegamento esplicito fra gli account (un account che linka l'altro);
- somiglianza della foto.

I pesi, in `osint_scoring.py`, sono stati stimati con una regressione logistica su
candidati giudicati a mano, separatamente per i candidati con lo stesso username e per
le varianti.

## Collegamenti espliciti fra gli account
`trova_collegamenti.py` è il modulo che calcola l'indizio del collegamento esplicito:
riconosce nei link delle pagine archiviate gli indirizzi degli account (anche le prove
verificate di Keybase) e controlla se l'account di partenza e il candidato si linkano.
Lanciato da solo, cerca questi collegamenti in tutte le indagini di `dati/indagini`
(con `--lista` solo in alcune) e li scrive in `collegamenti_dichiarati.csv`:
```bash
.env/bin/python3 trova_collegamenti.py
```

## File
```
osint.py                 coordina l'indagine e salva i risultati
osint_rete.py            unico punto da cui partono le richieste: ritmo, pause, tentativi, perdite
osint_cache.py           cache locale delle risposte (SQLite)
osint_variants.py        varianti dello username
osint_profile.py         lettura di nome, biografia, link e foto dalle pagine archiviate
osint_foto.py            impronta delle foto
osint_scoring.py         indizi e punteggio (con i pesi stimati)
osint_report.py          scheda finale della persona
trova_collegamenti.py    collegamenti espliciti fra gli account
percorsi.py              dove vengono salvati i file
requirements.txt         librerie necessarie
```

## Limiti
WayLinkage vede solo ciò che la Wayback Machine ha archiviato: non trovare un account non
significa che non esista. Trova candidati solo se iniziano come lo username di partenza o
corrispondono a poche varianti costruite, quindi non trova pseudonimi del tutto diversi.
Ogni collegamento è un'ipotesi da verificare.

## Nota sui dati
I risultati delle indagini riguardano persone reali: non vanno pubblicati. Il file
`.gitignore` esclude la cartella `dati/`, la cache, i file `OSINT_*` e l'ambiente `.env/`.
