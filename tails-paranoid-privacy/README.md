# Paranoid Edition — Privacy-Tool für Tails OS

Ein automatisiertes **Defense-in-Depth**-Privacy-Werkzeug für [Tails OS](https://tails.net).
Reines Python-Standardbibliotheks-Skript (keine pip-Abhängigkeiten), CLI über `argparse`.

> ## ⚠️ Wichtiger Hinweis
> Tails erzwingt Tor **bereits auf Systemebene** (ferm/iptables) und bringt eigene,
> geprüfte Mechanismen mit: MAC-Spoofing (Welcome Screen), Bridges
> (Tor Connection Assistant) und Leak-Schutz (ferm-Firewall).
>
> Dieses Tool ist eine **zusätzliche, experimentelle Automatisierungsschicht** und
> **ersetzt diese eingebauten Mechanismen nicht**. Für den Produktiveinsatz sind die
> offiziellen Tails-Wege vorzuziehen.

## Funktionen

1. **MAC-Randomisierung** — generiert eine zufällige, gültige MAC (Unicast,
   lokal administriert) und setzt sie via `ip link` **oder** NM-konform via `nmcli`.
2. **Obfs4-Bridges** — injiziert validierte obfs4-Bridge-Zeilen nach
   `/etc/tor/torrc.d/` und lädt `tor@default` neu.
3. **Kill-Switch** — Monitor-Thread prüft Tor-Dienst + echte Konnektivität durch
   Tor; bei Ausfall wird das Interface **sofort** deaktiviert (`ip link ... down`).

## Voraussetzungen

In Tails alles vorinstalliert. Auf anderen Debian-Systemen ggf.:

```bash
apt install iproute2 network-manager tor obfs4proxy curl
```

## Nutzung

Benötigt Root (`sudo`):

```bash
# MAC randomisieren (ip link)
sudo python3 paranoid_tails.py -i wlan0 --spoof-mac

# MAC randomisieren (NM-konform, robuster in Tails)
sudo python3 paranoid_tails.py -i wlan0 --use-nmcli --spoof-mac

# Obfs4-Bridges aus Datei injizieren
sudo python3 paranoid_tails.py -i eth0 --add-bridges bridges.txt

# Kill-Switch starten (blockiert bis Ctrl-C)
sudo python3 paranoid_tails.py -i eth0 --kill-switch

# Alles zusammen
sudo python3 paranoid_tails.py -i eth0 --all --add-bridges bridges.txt
```

Obfs4-Bridges bekommst du über <https://bridges.torproject.org/> oder per E-Mail
an `bridges@torproject.org`. Format-Beispiel siehe `bridges.txt.example`.

## Tails-spezifische Fallstricke

- **Amnesie:** torrc-Änderungen überleben **keinen Reboot**. Für Persistenz das
  Skript bei jedem Boot (z. B. aus dem Persistent Storage) erneut ausführen.
- **AppArmor:** `tor` läuft unter AppArmor und liest Fragmente aus
  `/etc/tor/torrc.d/` — dorthin schreibt das Tool (statt die Haupt-torrc zu
  zerstören). Ein Backup (`.paranoid.bak`) wird angelegt.
- **NetworkManager:** Ein manuelles `ip link`-MAC-Setzen kann von NM beim
  Reconnect überschrieben werden → `--use-nmcli` verwenden.

## Rechtlicher Hinweis

Dient dem Schutz der eigenen Privatsphäre. MAC-Spoofing und Bridges können in
manchen Netzwerken/Jurisdiktionen Regeln verletzen — Nutzung in eigener Verantwortung.
