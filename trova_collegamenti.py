"""
Cerca in TUTTI i candidati di ogni indagine (non solo in quelli estratti per
l'etichettatura) i collegamenti dichiarati con l'account di partenza, usando
i link esterni che lo strumento ha già letto (colonna Link_Esterni del CSV).

Serve a rispondere a una domanda che l'etichettatura a campione non copre
bene: ci sono collegamenti veri a cui lo strumento ha dato un punteggio basso?
Un collegamento dichiarato non dipende dal punteggio, quindi si trova anche
sotto la soglia.

Livelli, dal più forte:
  verificato  la pagina dell'ANCORA linka l'account del candidato (può
              scriverlo solo il titolare dell'ancora), oppure il candidato è
              su Keybase o Medium e linka l'ancora (collegamento verificato
              dalla piattaforma: prova crittografica / account collegato);
  dichiarato  il candidato linka l'account dell'ancora (chiunque può farlo:
              va controllato a mano, può essere un fan o un impostore).
Il caso "linkano lo stesso sito esterno" NON è usato come prova: è
esattamente l'indizio shared_links del punteggio, e usarlo renderebbe la
verifica circolare.

Uso:  python3 trova_collegamenti.py                (tutte le indagini in dati/indagini)
      python3 trova_collegamenti.py --lista nomi.txt
Scrive collegamenti_dichiarati.csv nella cartella dei CSV (di solito dati/indagini).
"""
import percorsi
import argparse
import csv
import os
import re
import gzip
import sqlite3
import statistics

CACHE = percorsi.CACHE

# ---- riconoscimento degli account nei link --------------------------------

_RE_WB = re.compile(r"^(?:https?:)?(?://web\.archive\.org)?/web/[0-9]{1,14}[a-z_]*/", re.I)
# host -> nome della piattaforma (twitter e x sono la stessa)
_PIATTAFORME = {
    "twitter.com": "twitter", "x.com": "twitter", "mobile.twitter.com": "twitter",
    "github.com": "github", "instagram.com": "instagram", "reddit.com": "reddit",
    "old.reddit.com": "reddit", "medium.com": "medium", "t.me": "telegram",
    "tiktok.com": "tiktok", "keybase.io": "keybase",
}
# primi segmenti di percorso che non sono account
_NON_ACCOUNT = {"", "intent", "share", "home", "search", "hashtag", "i", "login",
                "signup", "about", "explore", "settings", "tos", "privacy", "_",
                "features", "topics", "sponsors", "orgs", "notifications", "p",
                "tag", "tags", "s", "r", "discover", "legal"}


def account(url):
    """Riduce un indirizzo a (piattaforma, handle) se è la pagina di un
    account su una delle piattaforme note, altrimenti None."""
    u = _RE_WB.sub("", (url or "").strip())
    u = re.sub(r"^https?://", "", u, flags=re.I)
    u = re.sub(r"^(www\.|m\.)", "", u, flags=re.I)
    u = re.split(r"[?#]", u)[0].rstrip("/")
    parti = u.split("/")
    host = parti[0].lower()
    piatt = _PIATTAFORME.get(host)
    if not piatt or len(parti) < 2:
        return None
    seg = parti[1]
    if piatt == "reddit":
        if seg.lower() not in ("user", "u") or len(parti) < 3:
            return None
        seg = parti[2]
    elif piatt in ("medium", "tiktok"):
        if not seg.startswith("@"):
            return None
        seg = seg[1:]
    elif seg.startswith("@"):
        seg = seg[1:]
    seg = seg.strip().lower()
    if seg in _NON_ACCOUNT or not re.fullmatch(r"[a-z0-9_.\-]{1,40}", seg):
        return None
    return piatt, seg


class Pagine:
    def __init__(self, percorso=CACHE):
        self.db = None
        if os.path.exists(percorso):
            # connessione normale ma usata SOLO per leggere: in sola lettura
            # ("mode=ro") SQLite non riesce ad aprire il file condiviso del
            # journal WAL quando un batch sta scrivendo nella stessa cache
            self.db = sqlite3.connect(percorso, timeout=30)

    def html(self, url):
        if not self.db or not url:
            return None
        riga = self.db.execute("SELECT html FROM pagine WHERE url = ?", (url,)).fetchone()
        if not riga:
            return None
        try:
            return gzip.decompress(riga[0]).decode("utf-8", "replace")
        except Exception:
            return None


# ---- prove di Keybase: link verificati con una firma crittografica -------

_RE_HREF = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.I)
_RE_HANDLE = re.compile(r"[A-Za-z0-9_.\-]{1,40}")
# account della piattaforma stessa, che compaiono in ogni pagina di Keybase
_DI_SERVIZIO = {"keybase", "keybaseio", "keybase_io"}


def _pulisci(href):
    u = _RE_WB.sub("", href.strip())
    u = re.sub(r"^https?://", "", u, flags=re.I)
    u = re.sub(r"^(www\.|mobile\.|old\.)", "", u, flags=re.I)
    return re.split(r"[?#]", u)[0].rstrip("/")


_RE_PROVA = re.compile(
    r"""<a[^>]+href=["']([^"']+)["'][^>]*rel=["']me["'][^>]*>.{0,200}?"""
    r"""proof-tag-state-(\d)""", re.I | re.S)
_PIATT_KEYBASE = (("twitter", r"(?:twitter|x)\.com/([^/]+)"), ("github", r"github\.com/([^/]+)"),
                  ("reddit", r"reddit\.com/(?:user|u)/([^/]+)"))


def prove_keybase(html):
    """Versione strutturata: nelle pagine di Keybase ogni prova è un link
    all'account con rel="me" seguito dall'etichetta della prova, che ne dice
    lo stato (state-1 = verificata; gli altri stati sono prove rotte o
    revocate, e non si contano). Se la pagina non ha questa struttura (le
    copie più vecchie), si ripiega sul riconoscimento per coppie di link."""
    trovate = _RE_PROVA.findall(html or "")
    if not trovate:
        return _prove_keybase_vecchie(html)
    fuori = set()
    for href, stato in trovate:
        if stato != "1":
            continue
        u = _pulisci(href)
        for piatt, rx in _PIATT_KEYBASE:
            m = re.fullmatch(rx, u, re.I)
            if m and _RE_HANDLE.fullmatch(m.group(1)) and m.group(1).lower() not in _DI_SERVIZIO:
                fuori.add((piatt, m.group(1).lower()))
    return fuori


def _prove_keybase_vecchie(html):
    """Account provati nella pagina di un profilo Keybase: {(piattaforma, handle)}.

    Una prova si riconosce da DUE link: quello all'account e quello al
    messaggio di prova (il tweet su Twitter, il gist su GitHub, il post nel
    subreddit KeybaseProofs su Reddit). Il solo link all'account non basta,
    perché la pagina contiene anche i link a chi segue e a chi è seguito."""
    link = [_pulisci(h) for h in _RE_HREF.findall(html or "")]
    trovati = set()
    # Twitter: twitter.com/<h>/status/<id>
    for u in link:
        m = re.match(r"(?:twitter|x)\.com/([^/]+)/status/\d+", u, re.I)
        if m and _RE_HANDLE.fullmatch(m.group(1)) and m.group(1).lower() not in _DI_SERVIZIO:
            trovati.add(("twitter", m.group(1).lower()))
    # GitHub: serve un gist nella pagina, e l'account è github.com/<h>
    if any(u.lower().startswith("gist.github.com/") for u in link):
        for u in link:
            m = re.fullmatch(r"github\.com/([^/]+)", u, re.I)
            if m and _RE_HANDLE.fullmatch(m.group(1)) and m.group(1).lower() not in _DI_SERVIZIO:
                trovati.add(("github", m.group(1).lower()))
    # Reddit: serve un post in r/KeybaseProofs, e l'account è reddit.com/user/<h>
    if any(re.match(r"reddit\.com/r/keybaseproofs/", u, re.I) for u in link):
        for u in link:
            m = re.fullmatch(r"reddit\.com/(?:user|u)/([^/]+)", u, re.I)
            if m and _RE_HANDLE.fullmatch(m.group(1)):
                trovati.add(("reddit", m.group(1).lower()))
    return trovati


# indirizzi scritti come testo nella biografia (es. "github.com/nome"), che non
# sono link veri e quindi non finiscono in Link_Esterni
_RE_URL_TESTO = re.compile(r"(?:https?://)?(?:www\.)?((?:twitter|x|github|instagram|reddit|medium|tiktok|keybase)"
                           r"\.(?:com|io)/[^\s,;)]+|t\.me/[^\s,;)]+)", re.I)


def _da_testo(testo):
    return {m.group(1) for m in _RE_URL_TESTO.finditer(testo or "")}


# link che il titolare dichiara come "suoi" (rel="me"): GitHub li usa per gli
# account social del profilo, Keybase per le prove. Non finiscono in
# Link_Esterni, quindi si leggono dalle pagine già nella cache.
_RE_A = re.compile(r"<a\b[^>]*>", re.I)


def _rel_me(html):
    fuori = set()
    for a in _RE_A.findall(html or ""):
        if re.search(r'rel="[^"]*\bme\b', a, re.I):
            m = re.search(r'href="([^"]+)"', a)
            if m:
                fuori.add(m.group(1))
    return fuori

_PIATT = {"twitter/x": "twitter", "github": "github", "instagram": "instagram",
          "reddit": "reddit", "medium": "medium", "t.me": "telegram",
          "tiktok": "tiktok", "keybase.io": "keybase"}
_VERIFICATE = {"keybase", "medium"}


def utenti(lista):
    with open(lista, encoding="utf-8") as f:
        return [r.strip() for r in f if r.strip() and not r.startswith("#")]


def analizza(percorso, u, pagine=None):
    with open(percorso, encoding="utf-8-sig") as f:
        righe = list(csv.DictReader(f))
    return analizza_righe(righe, u, pagine)


def valore_indizio(livello):
    """Indizio account_links: 1 se il collegamento è verificato (l'ancora
    linka il candidato, o la piattaforma certifica il link), 0,5 se è solo
    dichiarato dal candidato, 0 se non c'è."""
    return {"verificato": 1.0, "dichiarato": 0.5}.get(livello, 0.0)


def analizza_righe(righe, u, pagine=None):
    righe = [{k: ("" if v is None else str(v)) for k, v in r.items()} for r in righe]
    if not righe:
        return []
    anc_piatt = next((_PIATT.get(r["Piattaforma"], r["Piattaforma"]) for r in righe
                      if r["Tipo"] == "Target"), None)
    if not anc_piatt:
        return []
    ancora = (anc_piatt, u.lower())
    link_ancora = set()
    for r in righe:
        if r["Tipo"] == "Target":
            link_ancora |= {x.strip() for x in (r.get("Link_Esterni") or "").split("|") if x.strip()}
            link_ancora |= _da_testo(r.get("Bio_Rilevata"))
    if pagine is not None:
        url_ancora = sorted({r["URL_Archivio"] for r in righe
                             if r["Tipo"] == "Target" and r.get("URL_Archivio")})[-20:]
        for url in url_ancora:
            link_ancora |= _rel_me(pagine.html(url))
    acc_ancora = {account(l) for l in link_ancora} - {None}
    cand = {}
    for r in righe:
        if r["Tipo"] == "Target":
            continue
        k = (_PIATT.get(r["Piattaforma"], r["Piattaforma"]), (r["Username_Testato"] or "").lower())
        c = cand.setdefault(k, {"tipo": r["Tipo"], "score": 0.0, "link": set(), "pagine": set()})
        if r.get("URL_Archivio"):
            c["pagine"].add(r["URL_Archivio"])
        c["link"] |= _da_testo(r.get("Bio_Rilevata"))
        try:
            c["score"] = max(c["score"], float(r["Score"]))
        except ValueError:
            pass
        c["link"] |= {x.strip() for x in (r.get("Link_Esterni") or "").split("|") if x.strip()}
    fuori = []
    for k, c in cand.items():
        if pagine is not None and k[0] != "keybase":
            for url in c["pagine"]:
                c["link"] |= _rel_me(pagine.html(url))
        livello, prova = "", ""
        if k in acc_ancora:
            livello, prova = "verificato", f"la pagina dell'ancora ({anc_piatt}) linka {k[0]}/{k[1]}"
        else:
            for l in c["link"]:
                if account(l) == ancora:
                    if k[0] in _VERIFICATE:
                        livello, prova = "verificato", f"{k[0]}/{k[1]} linka l'ancora ({l}), verificato dalla piattaforma"
                    else:
                        livello, prova = "dichiarato", f"{k[0]}/{k[1]} linka l'ancora ({l})"
                    break
        if not livello and k[0] == "keybase" and pagine is not None:
            # Keybase: le prove si leggono dalla pagina archiviata (link rel="me"
            # con stato verificato), perché Link_Esterni non le contiene
            for url in c["pagine"]:
                if ancora in prove_keybase(pagine.html(url) or ""):
                    livello, prova = "verificato", f"prova Keybase di {k[1]} verso l'ancora ({ancora[0]}/{ancora[1]})"
                    break
        if livello:
            fuori.append({"Target": u, "Piattaforma": k[0], "Candidato": k[1], "Tipo": c["tipo"],
                          "Score": c["score"], "Livello": livello, "Prova": prova})
    return fuori


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lista", default=None,
                    help="file con un username per riga (default: tutte le indagini della cartella)")
    ap.add_argument("--cartella", default=percorsi.INDAGINI)
    a = ap.parse_args()
    tutte, indagini, candidati = [], 0, 0
    pagine = Pagine()
    if a.lista:
        nomi = utenti(percorsi.lista(a.lista))
    else:
        nomi = sorted(f[len("OSINT_"):-len("_correlato.csv")]
                      for f in (os.listdir(a.cartella) if os.path.isdir(a.cartella) else [])
                      if f.startswith("OSINT_") and f.endswith("_correlato.csv"))
    for u in nomi:
        p = os.path.join(a.cartella, f"OSINT_{u}_correlato.csv")
        if not os.path.exists(p):
            continue
        indagini += 1
        tutte += analizza(p, u, pagine)
    if not indagini:
        print(f"Nessuna indagine trovata in {a.cartella}: prima lancia osint.py")
        return
    uscita = os.path.join(a.cartella, "collegamenti_dichiarati.csv")
    with open(uscita, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["Target", "Piattaforma", "Candidato", "Tipo", "Score", "Livello", "Prova"])
        w.writeheader()
        w.writerows(sorted(tutte, key=lambda r: (r["Target"], -r["Score"])))
    print(f"Indagini lette: {indagini}. Collegamenti trovati: {len(tutte)} "
          f"(verificati {sum(r['Livello'] == 'verificato' for r in tutte)}, "
          f"dichiarati {sum(r['Livello'] == 'dichiarato' for r in tutte)})")
    for tipo in ("Stesso username", "Variante"):
        s = [r["Score"] for r in tutte if r["Tipo"] == tipo]
        if s:
            print(f"  {tipo:16s} n={len(s)}  mediana {statistics.median(s):.1f}  "
                  f"sotto 40: {sum(x < 40 for x in s)}  da 40 in su: {sum(x >= 40 for x in s)}")
    for r in sorted(tutte, key=lambda r: r["Score"]):
        print(f"  {r['Score']:5.1f}  {r['Livello']:10s} {r['Target']:14s} {r['Tipo']:15s} {r['Prova'][:90]}")
    print(f"\nScritto {uscita}")


if __name__ == "__main__":
    main()
