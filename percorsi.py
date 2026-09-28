"""
Dove WayLinkage salva i suoi file. Lanciato da questa cartella, lo strumento
scrive tutto in dati/ (creata alla prima indagine):

  dati/indagini/           risultati delle indagini (OSINT_<nome>_correlato.csv e _profilo.json)
  dati/osint_cache.sqlite  risposte dell'archivio già scaricate
  dati/liste/              liste di username (per --lista si può dare solo il nome del file)

La cartella dati/ è esclusa da .gitignore: contiene informazioni su persone reali.
"""
import os

RADICE = os.path.dirname(os.path.abspath(__file__))
DATI = os.path.join(RADICE, "dati")
INDAGINI = os.path.join(DATI, "indagini")
LISTE = os.path.join(DATI, "liste")
CACHE = os.path.join(DATI, "osint_cache.sqlite")
FRENO = os.path.join(DATI, "osint_freno.json")
VERIFICA_404 = os.path.join(DATI, "verifica_404_campione.csv")


def indagine(nome, cartella=INDAGINI):
    """Percorso del CSV di un'indagine."""
    return os.path.join(cartella, f"OSINT_{nome}_correlato.csv")


def lista(nome):
    """Una lista di username: se non è un percorso esistente, la cerca in dati/liste."""
    return nome if os.path.exists(nome) else os.path.join(LISTE, os.path.basename(nome))
