import os

# Was ersetzt werden soll
ersetzungen = {
    'maintrance_mode': 'maintrance_mode',
    'maintrance': 'maintrance'
}

# Welche Dateitypen durchsucht werden
dateitypen = ['.py', '.html', '.json', '.txt']

def ersetze_in_datei(pfad):
    with open(pfad, 'r', encoding='utf-8') as file:
        inhalt = file.read()

    original = inhalt
    for alt, neu in ersetzungen.items():
        inhalt = inhalt.replace(alt, neu)

    if inhalt != original:
        with open(pfad, 'w', encoding='utf-8') as file:
            file.write(inhalt)
        print(f'✅ Ersetzt in: {pfad}')

def durchsuche_ordner(pfad='.'):
    for root, dirs, files in os.walk(pfad):
        for datei in files:
            if any(datei.endswith(ext) for ext in dateitypen):
                ersetze_in_datei(os.path.join(root, datei))

if __name__ == "__main__":
    durchsuche_ordner()
    print("🔁 Fertig mit allen Ersetzungen.")
