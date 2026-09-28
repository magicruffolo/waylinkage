"""
Qui dentro tiriamo fuori le info di profilo (nome mostrato, bio, foto,
link esterni) dalle pagine ARCHIVIATE su Wayback Machine.

Niente richieste al sito vero: si scarica solo lo snapshot già salvato da
archive.org (stesso discorso "solo Wayback Machine" del controllo di
esistenza). Per estrarre i dati usiamo delle semplici regex sui tag
<title>/<meta> standard (title, og:title, description, og:description,
og:image) - sono gli stessi campi che qualsiasi sito mette per l'anteprima
sui social (Open Graph), quindi dovrebbero esserci anche sugli snapshot
vecchi.

Limite che conosciamo bene: non avendo un parser HTML vero (per non dover
aggiungere dipendenze oltre a requests/pandas), non riusciamo a prendere
campi specifici di una singola piattaforma (tipo 'location'/'company' su
GitHub). Su GitHub in particolare la og:description spesso è un messaggio
automatico tipo "X ha N repository, segui il suo codice" - NON è la bio
scritta a mano dalla persona, quindi in quei casi non c'è molto altro da
tirare fuori anche se il codice funziona bene (è un limite del dato
disponibile, non un bug nell'estrazione). Possibile miglioramento futuro:
un parser dedicato per ogni piattaforma, per andare a pescare i campi
giusti invece di accontentarsi dei tag OG.
"""

import html
import re

import requests

# domini/pezzi di URL da scartare quando cerchiamo 'link esterni' utili per
# andare a controllare a mano (roba tipo asset statici, tracking, la stessa
# Wayback Machine, CDN dei social più comuni). "archive.org" da solo basta
# a coprire tutte le varianti del dominio di Wayback (compresi i sottodomini
# tipo web-static.archive.org, che prima ci scappavano).
_IGNORED_LINK_SUBSTRINGS = (
    "archive.org",
    "googleapis.com", "gstatic.com", "google-analytics.com", "googletagmanager.com",
    "cloudflare.com", "doubleclick.net",
    "fonts.google", "w3.org", "schema.org",
    "githubassets.com", "githubusercontent.com", "amazonaws.com", "fastly.net",
    "twimg.com", "fbcdn.net", "licdn.com", "cdninstagram.com",
    # risorse grafiche delle piattaforme: nella prova su torvalds le pagine
    # Reddit davano come "link esterni" le proprie favicon, e due account
    # Reddit qualsiasi risultavano avere "link in comune"
    "redditstatic.com", "redditmedia.com", "tiktokcdn.com", "medium.com/_/",
    "miro.medium.com", "keybase.pub/_/",
    # la pagina Google+ di Medium stessa, nel piè di pagina dei profili Medium
    # di qualche anno fa: nella seconda serie di prove faceva risultare "link in
    # comune" fra troyhunt e un account dal nome simile di un'altra persona
    "plus.google.com/103654360130207659246",
)
# ...e in generale nessun file statico (immagini, fogli di stile, script)
_ESTENSIONI_RISORSE = re.compile(
    r"\.(?:png|jpe?g|gif|svg|ico|webp|css|js|woff2?|ttf|json|xml)(?:[?#].*)?$", re.I)


# Codici con cui archive.org risponde in modo DEFINITIVO: la cattura esiste ma
# è una pagina d'errore, oppure l'indirizzo non è servito. Non sono problemi
# di rete: rilanciare darebbe lo stesso risultato, quindi non sono "dati persi".
# 408 e 429 (tempo scaduto, troppe richieste) NON sono qui: quelli sono passeggeri.
CODICI_DEFINITIVI = (400, 401, 403, 404, 410, 451)


def fetch_archive_html(archive_url, session=None, headers=None, timeout=15):
    """Scarica UNA pagina archiviata su Wayback Machine.

    Torna l'HTML se la pagina è arrivata, e None se NON è arrivata.
    Prima tornava "" in entrambi i casi, ed era un modo silenzioso di
    falsare i dati: una pagina persa per congestione della rete diventava
    indistinguibile da una pagina davvero vuota, e content_similarity = 0
    per un timeout sembrava "le bio sono diverse". Adesso chi chiama può
    contare la perdita come tale."""
    getter = session.get if session is not None else requests.get
    try:
        resp = getter(archive_url, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            return testo_della_risposta(resp)
        if resp.status_code in CODICI_DEFINITIVI:
            # risposta DEFINITIVA, non un problema di rete: archive.org dice
            # che quella cattura è una pagina d'errore (404, account chiuso,
            # 403...). Riprovare darebbe lo stesso risultato: si torna "" (pagina
            # senza contenuto leggibile), che NON conta come dato perso.
            print(f"[i] {archive_url}: la cattura è una pagina HTTP "
                  f"{resp.status_code} (definitiva): niente nome/bio/foto da qui.")
            return ""
        # se non è 200, non è un errore di rete ma la pagina non si legge
        # comunque - lo diciamo, se no sembra solo "questo profilo non ha
        # bio/nome" quando magari è solo un problema temporaneo (rate limit)
        print(f"[!] {archive_url}: risposta HTTP {resp.status_code}, "
              f"nome/bio/foto per questa pagina resteranno vuoti.")
    except requests.exceptions.RequestException as e:
        print(f"[!] {archive_url}: errore di rete ({type(e).__name__}), "
              f"nome/bio/foto per questa pagina resteranno vuoti.")
    return None


def domain_from_archive_url(archive_url):
    """Tira fuori il dominio originale da un URL Wayback tipo
    'https://web.archive.org/web/20260101000000/https://github.com/torvalds'
    (funziona anche se dopo il timestamp c'è un modificatore, tipo
    '.../20260101000000if_/...')."""
    m = re.search(r'/web/\d+(?:[a-z]{2}_)?/https?://([^/]+)', archive_url)
    return m.group(1).lower() if m else ""


def _find(pattern, html_text):
    # cerca la regex nell'HTML e torna solo il primo "gruppo" catturato
    # (quello tra parentesi nella regex), oppure stringa vuota se non trova niente
    m = re.search(pattern, html_text, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip() if m else ""


def _clean_text(text):
    # ripulisce il testo preso dall'HTML: sistema le entità HTML più comuni
    # (&amp; -> &, ecc.) e schiaccia spazi/a-capo multipli in uno solo
    if not text:
        return ""
    # TUTTE le entità HTML, non solo le tre più comuni: nei CSV c'era
    # "Zac (&#064;test)" al posto di "Zac (@test)"
    text = html.unescape(text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def _external_links(html_text, own_domain, limit=5):
    """Prende i link a domini ESTERNI trovati nella pagina: potrebbero
    essere il sito personale della persona, o un altro suo account social -
    utili come spunto per andare a controllare a mano (non li seguiamo in
    automatico, sia chiaro)."""
    hrefs = re.findall(r'href=["\'](https?://[^"\']+)["\']', html_text, re.IGNORECASE)
    seen = []
    for href in hrefs:
        low = href.lower()
        if own_domain and own_domain in low:
            continue
        if any(bad in low for bad in _IGNORED_LINK_SUBSTRINGS):
            continue
        if _ESTENSIONI_RISORSE.search(low):
            continue
        if href not in seen:
            seen.append(href)
        if len(seen) >= limit:
            break
    return seen



# ---------------------------------------------------------------------------
#  Riconoscimento delle pagine SEGNAPOSTO (le "lapidi")
# ---------------------------------------------------------------------------
#
# Il problema, con il caso che lo ha rivelato.
#
# Nel test da 100 username, l'indagine su 'torvalds' ha prodotto
# nome_probabile = "ToRvaLDs" e bio = "You can contact @torvalds right away."
# Non è Linus Torvalds: è la pagina che Telegram mostra per un handle che
# NON ESISTE. Quella pagina ha metadati OpenGraph perfettamente formati
# (<title>Telegram: Contact @torvalds</title>, og:description con quella
# frase), quindi l'estrazione qui sotto fa esattamente il suo lavoro e non ha
# alcun modo di accorgersi che sta leggendo una lapide invece di un profilo.
#
# Perché nessun controllo precedente la intercetta:
#   - lo stato HTTP è 200 (la pagina esiste, dice solo che l'account no);
#   - l'HTML è valido;
#   - i tag og: sono al loro posto.
# Ed è un errore particolarmente insidioso perché il nome inventato entra
# poi in content_similarity e quindi nei punteggi di tutti i candidati.
#
# Peggio ancora: _profile_data_for prova per PRIMO lo snapshot più recente,
# che per un account cancellato, sospeso o rinominato è proprio la lapide.
#
# La soluzione: se il testo estratto corrisponde a una firma nota di pagina
# segnaposto, questa funzione torna vuoto. _profile_data_for lo interpreta
# come "pagina che non ha dato niente" e passa da sola al tentativo
# successivo, più indietro nella storia dell'account - dove il profilo, se
# è mai esistito, c'è davvero.
#
# LIMITE: sono euristiche testuali e dipendono dalla
# lingua in cui la piattaforma ha risposto al crawler. Coprono i casi
# incontrati durante lo sviluppo, non tutti i casi possibili. Una lapide con
# una formulazione non prevista passa ancora.
_SEGNAPOSTO = (
    # --- Telegram: il caso 'torvalds' ---
    "you can contact @",
    "if you have telegram, you can contact",
    "if you have telegram, you can view",
    # --- Twitter / X ---
    "this account doesn't exist",
    "questo account non esiste",
    "account suspended",
    "account sospeso",
    "log in to twitter",
    "sign up for twitter",
    # --- Instagram ---
    "sorry, this page isn't available",
    "spiacenti, questa pagina non è disponibile",
    "questa pagina non è disponibile",
    # --- GitHub / generici 404 ---
    "page not found",
    "pagina non trovata",
    # --- Reddit ---
    "nobody on reddit goes by that name",
    # --- Medium (la sua pagina di errore) ---
    "out of nothing, something",
    # --- TikTok ---
    "couldn't find this account",
    # --- la pagina di errore della Wayback Machine stessa: se l'archivio
    #     risponde con il proprio messaggio, non c'è nessun profilo da
    #     leggere e prenderne i metadati sarebbe il peggiore degli errori ---
    "wayback machine has not archived",
    "got an http 302 response at crawl time",
    "this content is not available in the wayback machine",
)

# Titoli che sono il nome GENERICO della piattaforma, non di una persona:
# capita quando lo snapshot ha catturato una pagina di login o un guscio
# JavaScript non ancora popolato. Confronto sull'INTERO titolo, non come
# sottostringa, altrimenti si scarterebbe una persona che ha davvero
# "instagram" nella bio.
_TITOLI_GENERICI = {
    "instagram", "github", "twitter", "x", "telegram", "reddit", "medium",
    "tiktok", "keybase", "github · where software is built",
    "reddit - dive into anything", "instagram login", "make your day",
    "telegram: contact", "just a moment...", "attenzione",
    # visto sul servizio vero (reddit.com/user/spez): è lo
    # slogan attuale di Reddit, che finiva nel CSV come nome della persona
    "reddit - the heart of the internet", "reddit", "tiktok - make your day",
    # copie recenti di x.com: guscio JavaScript il cui titolo è solo il dominio
    "x.com", "reddit: the front page of the internet",
}


# Apostrofi e virgolette che le piattaforme usano nei testi veri: quelli
# TIPOGRAFICI (’ ‘ ” “), non quelli dritti che uno scrive nel codice. Senza
# normalizzarli la firma "this account doesn't exist" non scatta sulla pagina
# reale di Twitter, che scrive "doesn’t" - trovato provando le firme su HTML
# vero invece che inventato.
_APOSTROFI = {"\u2019": "'", "\u2018": "'", "\u201c": '"', "\u201d": '"',
              "\u00b4": "'", "\u02bc": "'"}


def _normalizza_apostrofi(testo):
    for strano, dritto in _APOSTROFI.items():
        testo = testo.replace(strano, dritto)
    return testo


def pagina_segnaposto(testo, nome=""):
    """Dice se il testo estratto viene da una pagina segnaposto invece che da
    un profilo vero. Torna la firma che ha fatto scattare il riconoscimento
    (utile per capire perché, invece di un semplice True), o None."""
    minuscolo = _normalizza_apostrofi((testo or "").lower())
    for firma in _SEGNAPOSTO:
        if firma in minuscolo:
            return firma
    if nome and nome.strip().lower().rstrip(":") in _TITOLI_GENERICI:
        return f"titolo generico della piattaforma ({nome.strip()})"
    return None



# ---------------------------------------------------------------------------
#  Testo standard delle piattaforme
# ---------------------------------------------------------------------------
#
# Molte piattaforme mettono nella descrizione di OGNI profilo una frase fissa,
# con dentro solo il nome e qualche numero. Misurato sui CSV del batch da 100,
# cercando le frasi di 5 parole ripetute su molti account DIVERSI della stessa
# piattaforma:
#
#   keybase    97% dei profili  "... is now on Keybase, an open source app for
#                                encryption and cryptography."
#   github     75%              "... has N repositories available. Follow their
#                                code on GitHub."
#   tiktok     73%              "... on TikTok | N Likes. N Fans. ... Watch the
#                                latest video from ..."
#   instagram  51%              "N Followers, N Following, N Posts - See
#                                Instagram photos and videos from ..."
#   medium     43%              "Read writing from ... on Medium. ... Every day,
#                                ... and thousands of other voices read, write,
#                                and share important stories on Medium."
#   twitter/x, reddit, t.me: nessuna frase ricorrente sopra il 25%.
#
# content_similarity trattava queste frasi come contenuto: due profili GitHub
# QUALSIASI risultavano simili perché entrambi "have repositories available
# and follow their code on GitHub". Un indizio di identità che in realtà è
# un indizio di piattaforma. Qui le si toglie, lasciando solo ciò che ha
# scritto la persona. Medium e TikTok AVVOLGONO la bio vera: si toglie
# l'involucro e resta il contenuto in mezzo.
#
# Si toglie anche "(@handle)" dopo il nome: è il modo in cui la piattaforma
# formatta il titolo, e l'handle è già misurato da username_similarity -
# lasciarlo qui lo avrebbe contato due volte.
_NUM = r"[\d.,]+\s?[kmb]?"
_MODELLI_TESTO = [re.compile(p, re.I) for p in (
    # github
    r"\S+ has (?:\d[\d,]*|one|no) repositor(?:y|ies) available\.\s*follow their code on github\.?",
    r"contribute to .{1,80}? development by creating an account on github\.?",
    # instagram
    rf"{_NUM} followers,\s*{_NUM} following,\s*{_NUM} posts\s*-\s*see instagram photos and videos from .{{0,100}}?\(@[\w.]+\)",
    # instagram, versione vecchia senza i numeri davanti (DOPO quella completa,
    # se no si mangia la coda della completa e lascia i numeri)
    r"see instagram photos and videos from .{0,100}?\(@[\w.]+\)",
    # keybase
    r"\S+(?:\s\([^)]*\))? is now on keybase, an open source app for encryption and cryptography\.?",
    # medium: l'involucro, prima e dopo la bio vera
    r"read writing from .{1,100}? on medium\.?",
    r"every day, .{1,100}? and thousands of other voices read, write, and share important stories on medium\.?",
    # tiktok: l'involucro, prima e dopo la bio vera
    # (due versioni: con e senza "(@handle)" prima di "on TikTok")
    rf".{{0,100}}? on tiktok\s*\|\s*{_NUM} likes\.\s*{_NUM} (?:fans|followers)\.?",
    r"watch the latest video from .{0,100}?\(@[\w.]+\)\.?",
    # twitter, versione vecchia
    r"the latest tweets from .{0,100}?\(@\w+\)\.?",
    # reddit: la "bio" è solo l'handle
    r"^u/[\w-]+$",
    # reddit, versione vecchia (fino al 2018): lo slogan del sito finiva come bio
    r"reddit: the front page of the internet\.?",
)]
_MODELLI_NOME = [re.compile(p, re.I) for p in (
    r"\s*[•·]\s*instagram photos and videos$", r"\s*[•·|]\s*instagram$", r"\s+on instagram$",
    r"\s*\|\s*keybase$", r"\s*[–—-]\s*medium$",
    r"\s*\(u/[\w-]+\)", r"\s*-\s*reddit$", r"^overview for\s+",
    r"\s*\|\s*tiktok$", r"\s*-\s*make your day$", r"\s*tiktok\s*\|\s*watch\b.*$",
    r"\s+on x$", r"\s*[|/]\s*twitter$", r"\s+on twitter$", r"^twitter\s*/\s*", r"^(?:media )?tweets?(?: (?:with replies|and replies))? by\s+", r"^(?:posts|replies|media|likes) (?:by|from)\s+",
    r"^telegram:\s*contact\s*", r"\s*·\s*github$", r"\s+-\s+overview$",
    r"\s*\(@[\w.]+\)",
)]


def togli_testo_standard(testo, nome=False):
    """Toglie le frasi fisse delle piattaforme e lascia il testo della persona.
    Con nome=True applica anche le code fisse dei titoli (" | Keybase",
    " – Medium", "(@handle)" ...)."""
    if not testo:
        return ""
    for modello in (_MODELLI_TESTO + (_MODELLI_NOME if nome else [])):
        testo = modello.sub(" ", testo)
    testo = re.sub(r"\s+", " ", testo)
    return testo.strip(" .|·•-–—:")


def testo_della_risposta(risposta):
    """Il testo di una risposta HTTP con la codifica giusta.

    requests, se l'intestazione non dice la codifica, assume ISO-8859-1: una
    pagina scritta in UTF-8 esce storpiata, e "•" diventa "â¢" (visto nei
    CSV su Instagram). Lo stesso nome scritto in due modi sembra due nomi
    diversi. Quasi tutto il web è UTF-8: si prova quello per primo."""
    dati = risposta.content or b""
    try:
        return dati.decode("utf-8")
    except UnicodeDecodeError:
        return dati.decode(risposta.encoding or "latin-1", errors="replace")


def extract_profile_fields(html_text, own_domain="", handle=None):
    """
    Tira fuori dalla pagina archiviata: nome mostrato, bio/descrizione, URL
    della foto profilo, ed eventuali link esterni.

    Ritorna anche 'content_snippet', un pezzo di testo unico che poi il
    motore di scoring usa per confrontare i profili tra loro
    (osint_scoring.content_similarity).
    """
    empty = {
        "nome_rilevato": "", "bio_rilevata": "", "foto_url": "",
        "link_esterni": [], "content_snippet": "", "motivo_scarto": "",
    }
    if not html_text:
        return empty

    # tiriamo fuori i 5 campi che ci interessano, ognuno con la sua regex
    title = _find(r"<title[^>]*>(.*?)</title>", html_text)
    og_title = _find(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\'](.*?)["\']', html_text)
    description = _find(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', html_text)
    og_desc = _find(r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\'](.*?)["\']', html_text)
    og_image = _find(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\'](.*?)["\']', html_text)

    # Microformati h-card (p-name, p-note): li usa GitHub, e sono l'unico
    # punto della pagina con il NOME VERO. Nella prova su torvalds l'og:title
    # era "torvalds - Overview" e il nome rilevato risultava "torvalds",
    # mentre la pagina diceva "Linus Torvalds": la scheda persona e il
    # confronto dei contenuti partivano da un'ancora senza nome.
    hcard_nome = _clean_text(_find(r'class=["\'][^"\']*\bp-name\b[^"\']*["\'][^>]*>([^<]*)<', html_text))
    hcard_bio = _clean_text(re.sub(r"<[^>]+>", " ", _find(
        r'class=["\'][^"\']*\bp-note\b[^"\']*["\'][^>]*>([\s\S]{0,2000}?)</div>', html_text)))

    # mettiamo insieme tutti i pezzi di testo trovati (solo quelli non vuoti)
    parts = [p for p in [title, og_title, description, og_desc, hcard_nome, hcard_bio] if p]

    # per nome/bio preferiamo la versione "og:" se c'è (di solito è più
    # pulita), altrimenti ripieghiamo su title/description normali
    nome = _clean_text(og_title or title)
    # GitHub mette " - Overview" in coda al titolo di ogni profilo: è la
    # sezione della pagina, non una parte del nome, e compare su TUTTI i
    # profili GitHub - quindi confondeva il confronto fra due profili.
    nome = re.sub(r"\s+-\s+overview$", "", nome, flags=re.I)
    bio = _clean_text(og_desc or description)
    snippet = " | ".join(_clean_text(p) for p in parts)

    # Prima di restituire qualsiasi cosa: questa pagina è un profilo vero o
    # una lapide? (vedi il commento su _SEGNAPOSTO qui sopra)
    firma = pagina_segnaposto(snippet, nome)
    if firma:
        vuoto = dict(empty)
        vuoto["motivo_scarto"] = firma
        return vuoto

    # DOPO il controllo delle lapidi (che ha bisogno del titolo originale):
    # via il testo standard delle piattaforme, resta quello della persona
    nome = togli_testo_standard(nome, nome=True)
    bio = togli_testo_standard(bio)
    # Se il "nome" è soltanto l'handle (o manca), il nome vero può stare
    # nell'h-card o nel titolo "handle (Nome Cognome) · GitHub".
    solo_handle = not nome or (handle and nome.lower() == handle.lower()) \
        or nome.lower() == _clean_text(_find(r'class=["\'][^"\']*\bp-nickname\b[^"\']*["\'][^>]*>([^<]*)<', html_text)).lower()
    if solo_handle:
        tra_parentesi = _find(r"^\s*\S+\s+\(([^)]+)\)\s*[·|]", _clean_text(title))
        nome = hcard_nome or _clean_text(tra_parentesi) or nome
    if not bio and hcard_bio:
        bio = togli_testo_standard(hcard_bio)
    snippet = " | ".join(p for p in (togli_testo_standard(x, nome=True) for x in parts) if p)
    # L'handle della pagina stessa si toglie dal testo di CONFRONTO (non dal
    # nome mostrato). Una pagina GitHub senza nome reale contiene solo
    # l'handle, e due handle simili - che i candidati per prefisso sono per
    # costruzione - facevano sembrare simili i contenuti: era username_similarity
    # contato una seconda volta. Resta invece, apposta, una MENZIONE dell'handle
    # di qualcun altro: "account secondario di gvanrossum" è un indizio vero.
    if handle:
        snippet = re.sub(rf"(?<![\w.])(?:@|u/)?{re.escape(handle)}(?![\w.])", " ",
                         snippet, flags=re.I)
        snippet = " | ".join(p.strip(" .|·•-–—:()") for p in snippet.split("|")
                             if p.strip(" .|·•-–—:()"))

    return {
        "nome_rilevato": nome,
        "bio_rilevata": bio,
        "foto_url": og_image.strip(),
        "link_esterni": _external_links(html_text, own_domain),
        "content_snippet": snippet,
        "motivo_scarto": "",
    }
