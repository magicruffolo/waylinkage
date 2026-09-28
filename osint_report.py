"""
Qui mettiamo insieme la 'scheda persona' finale: prendiamo tutte le righe
raccolte (target + candidati confermati) e le riassumiamo in un unico
riepilogo leggibile su chi è il target - non il solito elenco grezzo di
snapshot, ma nome probabile, bio, foto e la lista degli account collegati
con il loro punteggio di affidabilità.
"""

import json
from collections import defaultdict, Counter

# Sopra questa soglia un account viene considerato abbastanza affidabile da
# contribuire ai campi "in cima" alla scheda (nome/bio/foto/link): senza
# questo filtro, bastava un match poco affidabile (tipo lo stesso username
# su una piattaforma che non c'entra niente) trovato per primo, e la sua
# bio finiva in cima come se fosse quella giusta.
SOGLIA_AFFIDABILE = 40.0


def _account_key(row):
    """Decide come raggruppare le righe nella scheda persona.

    Le righe 'Stesso username' vanno valutate UNA PER PIATTAFORMA: lo
    stesso username può avere punteggi molto diversi da una piattaforma
    all'altra (tipo Medium=9 e Telegram=35 - sono due verifiche
    indipendenti fatte contro l'ancora), quindi si raggruppano anche per
    piattaforma. Se no il punteggio più alto avrebbe "vinto" e nascosto
    quello più basso sotto un'unica riga - proprio il bug che avevamo
    trovato con Medium. Le righe 'Target' e 'Variante' invece hanno un
    punteggio unico su tutte le loro piattaforme, quindi per quelle basta
    raggruppare per username."""
    tipo = row.get("Tipo", "Variante")
    if tipo == "Stesso username":
        return (row["Username_Testato"], tipo, row["Piattaforma"])
    return (row["Username_Testato"], tipo)


def build_person_summary(username, rows):
    """
    rows: le righe che arrivano da OsintUsernameInvestigator (ognuna ha i
    campi Username_Testato, Piattaforma, Score, Tipo, Tecnica_Variante e,
    quando ci sono, Nome_Rilevato / Bio_Rilevata / Foto_URL / Link_Esterni).
    """
    accounts = defaultdict(lambda: {
        "username": "", "piattaforme": set(), "score": 0.0,
        "tecniche": set(), "tipo": "Variante",
    })
    nomi = Counter()
    nomi_gia_contati = set()   # vedi sotto: un voto per ACCOUNT, non per riga
    bio_candidates = []
    foto_url = ""
    link_esterni = []

    for r in rows:
        chiave = _account_key(r)
        acc = accounts[chiave]
        acc["username"] = r["Username_Testato"]
        acc["tipo"] = r.get("Tipo", "Variante")
        acc["piattaforme"].add(r["Piattaforma"])
        acc["score"] = max(acc["score"], float(r.get("Score", 0) or 0))
        tecnica = r.get("Tecnica_Variante", "-")
        if tecnica and tecnica != "-":
            acc["tecniche"].add(tecnica)

        # I campi in cima alla scheda (nome/bio/foto/link) li riempiamo
        # solo con righe affidabili (Target o punteggio sopra soglia): un
        # match dubbio non deve poter "rubare" il posto alla bio giusta.
        affidabile = acc["tipo"] == "Target" or float(r.get("Score", 0) or 0) >= SOGLIA_AFFIDABILE
        if not affidabile:
            continue

        # Occhio: un account con tanti snapshot (tante pagine archiviate nel
        # tempo) genera tante righe TUTTE con lo stesso Nome_Rilevato. Se
        # contassimo un voto per ogni riga, un account con 30 snapshot
        # "batterebbe" a suon di quantità un account con 2 snapshot, anche
        # se quest'ultimo è il Target vero - il numero di snapshot non ha
        # niente a che vedere con l'affidabilità. Quindi ogni account vota
        # al massimo UNA volta, si o no quanti snapshot ha.
        nome = (r.get("Nome_Rilevato") or "").strip()
        if nome and chiave not in nomi_gia_contati:
            nomi[nome] += 1
            nomi_gia_contati.add(chiave)

        bio = (r.get("Bio_Rilevata") or "").strip()
        if bio and bio not in bio_candidates:
            bio_candidates.append(bio)

        if not foto_url and r.get("Foto_URL"):
            foto_url = r["Foto_URL"]

        for link in (r.get("Link_Esterni") or "").split(" | "):
            link = link.strip()
            if link and link not in link_esterni:
                link_esterni.append(link)

    account_list = sorted(
        [
            {
                "username": a["username"],
                "piattaforme": sorted(a["piattaforme"]),
                "score": a["score"],
                "tipo": a["tipo"],
                "tecniche": sorted(a["tecniche"]),
            }
            for a in accounts.values()
        ],
        key=lambda a: a["score"], reverse=True,
    )

    return {
        "username_analizzato": username,
        "nome_probabile": nomi.most_common(1)[0][0] if nomi else "",
        "bio": " | ".join(bio_candidates[:3]),
        "foto_url": foto_url,
        "account_collegati": account_list,
        "link_esterni": link_esterni[:10],
    }


def print_person_summary(summary):
    print("\n" + "=" * 64)
    print(f" SCHEDA PERSONA - {summary['username_analizzato']}")
    print("=" * 64)
    if summary["nome_probabile"]:
        print(f"Nome rilevato:    {summary['nome_probabile']}")
    if summary["bio"]:
        print(f"Bio/descrizione:  {summary['bio']}")
    if summary["foto_url"]:
        print(f"Foto profilo:     {summary['foto_url']}")

    print(f"\nAccount collegati trovati ({len(summary['account_collegati'])}):")
    # una riga di stampa per ogni account trovato (sono già ordinati dal
    # punteggio più alto al più basso, vedi account_list sopra)
    for acc in summary["account_collegati"]:
        piattaforme = ", ".join(acc["piattaforme"])
        tecniche = f"  [{', '.join(acc['tecniche'])}]" if acc["tecniche"] else ""
        # il Target mostra la scritta "TARGET" invece del numero, per farlo
        # risaltare rispetto agli altri account
        etichetta = "TARGET" if acc["tipo"] == "Target" else f"{acc['score']:>5.1f}"
        tipo_tag = f"  ({acc['tipo']})" if acc["tipo"] != "Target" else ""
        print(f"  - {acc['username']:<25} score={etichetta:>6}  "
              f"piattaforme=({piattaforme}){tipo_tag}{tecniche}")

    if summary["link_esterni"]:
        print(f"\nLink esterni trovati nei profili ({len(summary['link_esterni'])}):")
        for link in summary["link_esterni"]:
            print(f"  - {link}")

    print("=" * 64 + "\n")


def export_person_summary(summary, filename):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    return filename
