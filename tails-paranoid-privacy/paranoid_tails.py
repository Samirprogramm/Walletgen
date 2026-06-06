#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
paranoid_tails.py  --  "Paranoid Edition"
=========================================

Automatisiertes Privacy-/Defense-in-Depth-Tool fuer Tails OS
(The Amnesic Incognito Live System).

Funktionen:
    1. MAC-Adressen-Randomisierung (Unicast, lokal administriert)
    2. Tor-Traffic-Verschleierung via obfs4-Bridges
    3. Netzwerk-Kill-Switch (harter Not-Aus bei Tor-Verlust)

------------------------------------------------------------------------------
WICHTIGER HINWEIS ZU TAILS
------------------------------------------------------------------------------
Tails erzwingt Tor bereits auf Systemebene (ferm/iptables) und bringt eigene,
gepruefte Mechanismen mit:

    * MAC-Spoofing  -> Welcome Screen (standardmaessig AN)
    * Bridges       -> Tor Connection Assistant / Welcome Screen
    * Leak-Schutz   -> ferm-Firewall (filtert ALLES ausser Tor)

Dieses Tool ist eine ZUSAETZLICHE, EXPERIMENTELLE Automatisierungsschicht
(Defense-in-Depth). Es ersetzt NICHT die eingebauten Mechanismen.

Konkrete Tails-Fallstricke, die der Code beruecksichtigt / vor denen er warnt:
    * Amnesie: Aenderungen an /etc/tor/torrc ueberleben KEINEN Reboot.
      Fuer Persistenz muss das Skript bei jedem Boot (z. B. aus dem
      Persistent Storage) erneut ausgefuehrt werden.
    * AppArmor: tor laeuft unter einem AppArmor-Profil. Es liest torrc-
      Fragmente bevorzugt aus /etc/tor/torrc.d/ -- wir schreiben dorthin
      statt die Haupt-torrc zu zerstoeren.
    * NetworkManager: Tails nutzt NM. Ein manuelles `ip link`-MAC-Setzen kann
      von NM ueberschrieben werden -> wir bieten optional den NM-Weg an.
    * tor laeuft als Instanz `tor@default` (systemctl restart tor@default).

------------------------------------------------------------------------------
THEORETISCH ERFORDERLICHE PAKETE
------------------------------------------------------------------------------
In Tails ist praktisch alles davon vorinstalliert. Auf anderen Debian-Systemen
ggf. nachzuinstallieren:

    iproute2        # `ip link` (Interface up/down, MAC setzen)   -> vorinstalliert
    network-manager # `nmcli`                                     -> vorinstalliert
    tor             # Tor-Daemon (Instanz tor@default)            -> vorinstalliert
    obfs4proxy      # /usr/bin/obfs4proxy (Pluggable Transport)   -> vorinstalliert
    systemd         # `systemctl` (Dienststeuerung)               -> vorinstalliert
    curl ODER python3-pysocks  # Konnektivitaetstest durch Tor

    apt install iproute2 network-manager tor obfs4proxy curl

Nur Python-Standardbibliothek wird importiert (keine pip-Abhaengigkeiten),
damit das Tool im amnesischen System ohne Netzwerk lauffaehig bleibt.

------------------------------------------------------------------------------
AUSFUEHRUNG
------------------------------------------------------------------------------
Benoetigt Root (sudo). Beispiele:

    sudo python3 paranoid_tails.py --interface eth0 --spoof-mac
    sudo python3 paranoid_tails.py --interface wlan0 --use-nmcli --spoof-mac
    sudo python3 paranoid_tails.py --interface eth0 --add-bridges bridges.txt
    sudo python3 paranoid_tails.py --interface eth0 --kill-switch
    sudo python3 paranoid_tails.py --interface eth0 --all --add-bridges bridges.txt

ACHTUNG: --kill-switch deaktiviert bei Tor-Verlust SOFORT das Interface.
Das kappt deine gesamte Netzwerkverbindung. Das ist beabsichtigt.

Rechtlicher/ethischer Hinweis: Dieses Tool dient dem Schutz der eigenen
Privatsphaere und Anonymitaet. MAC-Spoofing und Bridges koennen in manchen
Netzwerken/Jurisdiktionen Regeln verletzen -- Nutzung in eigener Verantwortung.
"""

import argparse
import logging
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime

# ---------------------------------------------------------------------------
# Konstanten (Tails-spezifisch)
# ---------------------------------------------------------------------------

TORRC_DROPIN_DIR = "/etc/tor/torrc.d"          # bevorzugtes Drop-in-Verzeichnis
TORRC_MAIN = "/etc/tor/torrc"                  # Fallback, falls kein Drop-in
TORRC_FRAGMENT_NAME = "99-paranoid-bridges.conf"
OBFS4_PROXY_PATH = "/usr/bin/obfs4proxy"       # Standardpfad in Tails/Debian
TOR_SERVICE = "tor@default"                    # Tails-Tor-Instanz
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050                          # Tails-SOCKS-Port
TOR_CHECK_URL = "https://check.torproject.org/api/ip"

KILL_SWITCH_INTERVAL = 5                        # Sekunden zwischen Checks
KILL_SWITCH_FAILURES_BEFORE_TRIP = 2            # Toleranz gegen Flapping

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("paranoid")


def setup_logging(verbose: bool = False) -> None:
    """Konfiguriert das Logging auf stderr (amnesisch -- kein File-Log)."""
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] %(levelname)-7s %(message)s",
                          datefmt="%H:%M:%S")
    )
    logger.setLevel(level)
    logger.addHandler(handler)


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

class CommandError(Exception):
    """Wird geworfen, wenn ein Systembefehl fehlschlaegt."""


def run_command(cmd: list, timeout: int = 30, check: bool = True) -> subprocess.CompletedProcess:
    """
    Fuehrt einen Systembefehl sicher aus (Liste statt Shell-String ->
    keine Shell-Injection) und liefert das Ergebnis.

    Wirft CommandError bei Fehlern. Faengt insbesondere Tails-typische
    Probleme ab: fehlende Rechte (PermissionError) und AppArmor-Blockaden
    (zeigen sich meist als 'Permission denied' / non-zero exit).
    """
    logger.debug("Befehl: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
        )
    except FileNotFoundError as exc:
        raise CommandError(
            f"Befehl nicht gefunden: {cmd[0]!r}. "
            f"Ist das zugehoerige Paket installiert?"
        ) from exc
    except PermissionError as exc:
        raise CommandError(
            f"Keine Berechtigung fuer {cmd[0]!r}. Script als root (sudo) "
            f"ausfuehren -- und AppArmor-Profil pruefen."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise CommandError(f"Timeout nach {timeout}s bei: {' '.join(cmd)}") from exc

    if check and result.returncode != 0:
        stderr = (result.stderr or "").strip()
        # Heuristik fuer typische Tails/AppArmor-Hinweise
        hint = ""
        if "Permission denied" in stderr or "Operation not permitted" in stderr:
            hint = (" -> Moegliche Ursache: fehlende Root-Rechte oder ein "
                   "AppArmor-Profil blockiert den Zugriff.")
        raise CommandError(
            f"Befehl fehlgeschlagen (exit {result.returncode}): "
            f"{' '.join(cmd)}\n  stderr: {stderr}{hint}"
        )
    return result


def require_root() -> None:
    """Stellt sicher, dass das Skript mit Root-Rechten laeuft."""
    if os.geteuid() != 0:
        logger.error("Dieses Skript benoetigt Root-Rechte. Bitte mit 'sudo' starten.")
        sys.exit(1)


def require_binary(name: str) -> str:
    """Prueft, ob ein Binary im PATH vorhanden ist; gibt den Pfad zurueck."""
    path = shutil.which(name)
    if not path:
        raise CommandError(f"Benoetigtes Programm '{name}' nicht gefunden (PATH).")
    return path


def interface_exists(interface: str) -> bool:
    """Prueft via sysfs, ob die Netzwerkschnittstelle existiert."""
    return os.path.isdir(f"/sys/class/net/{interface}")


def get_current_mac(interface: str) -> str:
    """Liest die aktuelle MAC-Adresse aus sysfs."""
    try:
        with open(f"/sys/class/net/{interface}/address", "r") as fh:
            return fh.read().strip()
    except OSError as exc:
        raise CommandError(f"MAC von {interface} nicht lesbar: {exc}") from exc


# ===========================================================================
# FUNKTION 1: MAC-Adressen-Randomisierung
# ===========================================================================

def generate_random_mac() -> str:
    """
    Erzeugt eine zufaellige, formattechnisch gueltige MAC-Adresse.

    Das erste Oktett wird so maskiert, dass:
        * Bit 0 (LSB) = 0  -> Unicast (kein Multicast)
        * Bit 1       = 1  -> "locally administered" (kein Hersteller-OUI)

    Maske: (byte & 0b1111_1100) | 0b0000_0010
    Damit erfuellt die Adresse die Konvention fuer lokal generierte MACs.
    """
    first_octet = (random.randint(0x00, 0xFF) & 0xFC) | 0x02
    octets = [first_octet] + [random.randint(0x00, 0xFF) for _ in range(5)]
    mac = ":".join(f"{o:02x}" for o in octets)
    logger.debug("Generierte MAC: %s (unicast, locally administered)", mac)
    return mac


def _validate_mac(mac: str) -> bool:
    """Validiert das MAC-Format aa:bb:cc:dd:ee:ff."""
    return bool(re.fullmatch(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac))


def spoof_mac_iplink(interface: str, new_mac: str = None) -> str:
    """
    MAC-Spoofing ueber `ip link` (iproute2).

    Ablauf: Interface DOWN -> MAC setzen -> Interface UP.

    HINWEIS (Tails/NetworkManager): NM kann eine manuell gesetzte MAC beim
    naechsten Connect ueberschreiben. Fuer NM-konformes Spoofing siehe
    spoof_mac_nmcli().
    """
    if new_mac is None:
        new_mac = generate_random_mac()
    if not _validate_mac(new_mac):
        raise CommandError(f"Ungueltiges MAC-Format: {new_mac!r}")

    old_mac = get_current_mac(interface)
    logger.info("MAC-Spoofing (ip link) auf %s: %s -> %s", interface, old_mac, new_mac)

    run_command(["ip", "link", "set", "dev", interface, "down"])
    try:
        run_command(["ip", "link", "set", "dev", interface, "address", new_mac])
    finally:
        # Interface IMMER wieder hochfahren, selbst wenn das Setzen scheitert.
        run_command(["ip", "link", "set", "dev", interface, "up"])

    applied = get_current_mac(interface)
    if applied.lower() != new_mac.lower():
        logger.warning("MAC wurde gesetzt, aktueller Wert ist aber %s "
                      "(evtl. von NetworkManager ueberschrieben).", applied)
    else:
        logger.info("MAC erfolgreich geaendert: %s", applied)
    return applied


def spoof_mac_nmcli(interface: str, new_mac: str = None) -> str:
    """
    MAC-Spoofing NM-konform ueber `nmcli`.

    Setzt die geklonte MAC auf der aktiven Verbindung des Interfaces, sodass
    NetworkManager den Wert respektiert und beim Reconnect nicht ueberschreibt.
    Dies ist auf Tails (NM-basiert) der robustere Weg.

    `cloned-mac-address` akzeptiert auch die Schluesselworte 'random' / 'stable',
    wir setzen hier aber eine konkrete, von uns kontrollierte MAC.
    """
    if new_mac is None:
        new_mac = generate_random_mac()
    if not _validate_mac(new_mac):
        raise CommandError(f"Ungueltiges MAC-Format: {new_mac!r}")

    require_binary("nmcli")

    # Aktiven Verbindungsnamen fuer das Interface ermitteln.
    result = run_command(
        ["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"]
    )
    conn_name = None
    for line in result.stdout.splitlines():
        # Format: NAME:DEVICE  (Doppelpunkte im Namen sind escaped als '\:')
        parts = line.rsplit(":", 1)
        if len(parts) == 2 and parts[1] == interface:
            conn_name = parts[0].replace("\\:", ":")
            break

    if not conn_name:
        raise CommandError(
            f"Keine aktive NetworkManager-Verbindung fuer {interface} gefunden. "
            f"Bitte zuerst verbinden oder den --use-nmcli-Modus weglassen."
        )

    # Spoofing-Property je nach Interface-Typ (wifi vs. ethernet) bestimmen.
    is_wifi = os.path.isdir(f"/sys/class/net/{interface}/wireless")
    prop = "wifi.cloned-mac-address" if is_wifi else "ethernet.cloned-mac-address"

    logger.info("MAC-Spoofing (nmcli) auf Verbindung %r (%s): %s -> %s",
                conn_name, prop, get_current_mac(interface), new_mac)

    run_command(["nmcli", "connection", "modify", conn_name, prop, new_mac])
    # Verbindung neu aufbauen, damit die neue MAC greift.
    run_command(["nmcli", "connection", "down", conn_name], check=False)
    run_command(["nmcli", "connection", "up", conn_name])

    applied = get_current_mac(interface)
    logger.info("Aktuelle MAC nach nmcli-Reconnect: %s", applied)
    return applied


# ===========================================================================
# FUNKTION 2: Tor-Traffic-Verschleierung via obfs4-Bridges
# ===========================================================================

# Erwartetes Bridge-Format (eine Zeile pro Bridge):
#   obfs4 <IP:PORT> <FINGERPRINT> cert=<...> iat-mode=<0|1|2>
_BRIDGE_RE = re.compile(
    r"^obfs4\s+\S+:\d+\s+[0-9A-Fa-f]{40}\s+cert=\S+\s+iat-mode=[0-2]\s*$"
)


def parse_bridges_file(path: str) -> list:
    """
    Liest obfs4-Bridge-Zeilen aus einer Datei. Leer-/Kommentarzeilen (#)
    werden ignoriert; jede Bridge-Zeile wird gegen das obfs4-Format validiert.
    """
    if not os.path.isfile(path):
        raise CommandError(f"Bridge-Datei nicht gefunden: {path}")

    bridges = []
    with open(path, "r") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Toleriere ein vorangestelltes "Bridge "-Keyword.
            line = re.sub(r"^Bridge\s+", "", line, flags=re.IGNORECASE)
            if not _BRIDGE_RE.match(line):
                raise CommandError(
                    f"Zeile {lineno} ist keine gueltige obfs4-Bridge:\n  {line}\n"
                    f"Erwartet: obfs4 <IP:PORT> <FINGERPRINT> cert=<...> iat-mode=<0|1|2>"
                )
            bridges.append(line)

    if not bridges:
        raise CommandError(f"Keine gueltigen Bridges in {path} gefunden.")
    logger.info("%d obfs4-Bridge(s) eingelesen.", len(bridges))
    return bridges


def build_torrc_fragment(bridges: list) -> str:
    """Baut das torrc-Fragment fuer obfs4-Bridges zusammen."""
    if not os.path.exists(OBFS4_PROXY_PATH):
        logger.warning("obfs4proxy nicht unter %s gefunden -- Tor wird die "
                      "Bridges nicht nutzen koennen.", OBFS4_PROXY_PATH)

    lines = [
        "# --- paranoid_tails.py: obfs4-Bridges (Defense-in-Depth) ---",
        f"# Generiert: {datetime.now().isoformat(timespec='seconds')}",
        "# Hinweis: In Tails amnesisch -- ueberlebt KEINEN Reboot.",
        "UseBridges 1",
        f"ClientTransportPlugin obfs4 exec {OBFS4_PROXY_PATH}",
    ]
    lines += [f"Bridge {b}" for b in bridges]
    lines.append("")  # abschliessender Zeilenumbruch
    return "\n".join(lines)


def inject_obfs4_bridges(bridges: list) -> str:
    """
    Schreibt das obfs4-Fragment in die Tor-Konfiguration.

    Bevorzugt das Drop-in-Verzeichnis /etc/tor/torrc.d/ (sauberer und von
    Tails' AppArmor-Profil gelesen). Faellt auf Anhaengen an die Haupt-torrc
    zurueck, falls kein Drop-in unterstuetzt wird.

    Eine Sicherungskopie der Zieldatei wird angelegt (.bak), bevor geschrieben
    wird -- so laesst sich der Originalzustand wiederherstellen.
    """
    fragment = build_torrc_fragment(bridges)

    if os.path.isdir(TORRC_DROPIN_DIR):
        target = os.path.join(TORRC_DROPIN_DIR, TORRC_FRAGMENT_NAME)
        logger.info("Schreibe obfs4-Konfiguration in Drop-in: %s", target)
        _backup_file(target)
        _atomic_write(target, fragment, mode=0o644)
    else:
        # Fallback: an Haupt-torrc anhaengen (mit klar markiertem Block).
        logger.warning("Kein %s -- haenge an %s an (Fallback).",
                      TORRC_DROPIN_DIR, TORRC_MAIN)
        _backup_file(TORRC_MAIN)
        with open(TORRC_MAIN, "a") as fh:
            fh.write("\n" + fragment)
        target = TORRC_MAIN

    restart_tor()
    return target


def _backup_file(path: str) -> None:
    """Legt eine .bak-Kopie an, falls die Datei existiert und noch kein Backup hat."""
    if os.path.isfile(path):
        backup = path + ".paranoid.bak"
        if not os.path.exists(backup):
            shutil.copy2(path, backup)
            logger.debug("Backup angelegt: %s", backup)


def _atomic_write(path: str, content: str, mode: int = 0o644) -> None:
    """Schreibt Inhalt atomar (temp -> rename), um halbe Schreibvorgaenge zu vermeiden."""
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(content)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def restart_tor() -> None:
    """
    Laedt den Tor-Dienst neu. In Tails ist Tor die Instanz tor@default.

    Probiert zuerst 'restart', faellt bei Bedarf auf 'reload' zurueck.
    """
    require_binary("systemctl")
    logger.info("Starte Tor-Dienst neu: %s", TOR_SERVICE)
    try:
        run_command(["systemctl", "restart", TOR_SERVICE], timeout=60)
    except CommandError as exc:
        logger.warning("restart fehlgeschlagen (%s) -- versuche reload.", exc)
        run_command(["systemctl", "reload", TOR_SERVICE], timeout=60)
    logger.info("Tor-Dienst neu geladen. Bootstrap kann einige Sekunden dauern.")


# ===========================================================================
# FUNKTION 3: Netzwerk-Kill-Switch
# ===========================================================================

def tor_service_active() -> bool:
    """True, wenn systemd den Tor-Dienst als 'active' meldet."""
    result = run_command(["systemctl", "is-active", TOR_SERVICE], check=False)
    return result.stdout.strip() == "active"


def tor_connectivity_ok() -> bool:
    """
    Prueft die Konnektivitaet DURCH das Tor-Netzwerk.

    Bevorzugt einen Request ueber den SOCKS-Port (curl --socks5-hostname), um
    sicherzustellen, dass tatsaechlich Verkehr durch Tor fliesst -- nicht nur,
    dass der Dienst laeuft. Faellt auf einen reinen SOCKS-Port-Check zurueck.
    """
    curl = shutil.which("curl")
    if curl:
        result = run_command(
            [curl, "--silent", "--max-time", "15",
             "--socks5-hostname", f"{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
             TOR_CHECK_URL],
            timeout=20, check=False,
        )
        # check.torproject.org liefert JSON mit "IsTor":true bei Erfolg.
        return result.returncode == 0 and '"IsTor":true' in result.stdout.replace(" ", "")

    # Fallback: nur pruefen, ob der SOCKS-Port erreichbar ist.
    return _socks_port_open()


def _socks_port_open() -> bool:
    """Minimaler TCP-Connect-Test auf den Tor-SOCKS-Port (stdlib socket)."""
    import socket
    try:
        with socket.create_connection((TOR_SOCKS_HOST, TOR_SOCKS_PORT), timeout=5):
            return True
    except OSError:
        return False


def trip_kill_switch(interface: str) -> None:
    """
    Harter Not-Aus: deaktiviert das Interface sofort physikalisch.

    Verhindert, dass nach einem Tor-Ausfall unverschluesselter Verkehr
    leaken kann. Beabsichtigt aggressiv -- kappt jegliche Konnektivitaet.
    """
    logger.critical("KILL-SWITCH AUSGELOEST -- deaktiviere %s SOFORT.", interface)
    try:
        run_command(["ip", "link", "set", "dev", interface, "down"])
        logger.critical("Interface %s ist DOWN. Netzwerk gekappt.", interface)
    except CommandError as exc:
        # Wenn selbst das Abschalten scheitert, ist das ein kritischer Zustand.
        logger.critical("KONNTE INTERFACE NICHT DEAKTIVIEREN: %s", exc)
        logger.critical("MANUELL EINGREIFEN: WLAN/Kabel physisch trennen!")


class KillSwitch:
    """
    Ueberwachungs-Thread: prueft kontinuierlich Tor-Dienst + Konnektivitaet.

    Nach KILL_SWITCH_FAILURES_BEFORE_TRIP aufeinanderfolgenden Fehlschlaegen
    (Toleranz gegen kurzes Flapping) wird der Kill-Switch ausgeloest und der
    Monitor beendet sich.
    """

    def __init__(self, interface: str, interval: int = KILL_SWITCH_INTERVAL):
        self.interface = interface
        self.interval = interval
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, name="kill-switch", daemon=True)
        self._consecutive_failures = 0
        self.tripped = False

    def start(self) -> None:
        logger.info("Kill-Switch aktiv. Ueberwache Tor alle %ds "
                   "(Ausloesung nach %d Fehlern in Folge).",
                   self.interval, KILL_SWITCH_FAILURES_BEFORE_TRIP)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def join(self) -> None:
        self._thread.join()

    def _check_once(self) -> bool:
        """Ein Pruefzyklus. True = alles ok, False = Tor-Problem erkannt."""
        if not tor_service_active():
            logger.warning("Tor-Dienst (%s) ist NICHT aktiv.", TOR_SERVICE)
            return False
        if not tor_connectivity_ok():
            logger.warning("Keine Konnektivitaet durch das Tor-Netzwerk.")
            return False
        return True

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                ok = self._check_once()
            except CommandError as exc:
                logger.error("Fehler im Kill-Switch-Check: %s", exc)
                ok = False

            if ok:
                if self._consecutive_failures:
                    logger.info("Tor wieder ok -- Fehlerzaehler zurueckgesetzt.")
                self._consecutive_failures = 0
            else:
                self._consecutive_failures += 1
                logger.warning("Tor-Check fehlgeschlagen (%d/%d).",
                              self._consecutive_failures,
                              KILL_SWITCH_FAILURES_BEFORE_TRIP)
                if self._consecutive_failures >= KILL_SWITCH_FAILURES_BEFORE_TRIP:
                    trip_kill_switch(self.interface)
                    self.tripped = True
                    self._stop_event.set()
                    break

            # Schlafen, aber auf Stop-Signal reagierbar bleiben.
            self._stop_event.wait(self.interval)

        logger.info("Kill-Switch-Monitor beendet.")


# ===========================================================================
# CLI / Main
# ===========================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="paranoid_tails.py",
        description="Paranoid Edition -- Privacy/Defense-in-Depth-Tool fuer Tails OS.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Beispiele:\n"
            "  sudo python3 %(prog)s -i wlan0 --spoof-mac\n"
            "  sudo python3 %(prog)s -i wlan0 --use-nmcli --spoof-mac\n"
            "  sudo python3 %(prog)s -i eth0 --add-bridges bridges.txt\n"
            "  sudo python3 %(prog)s -i eth0 --kill-switch\n"
            "  sudo python3 %(prog)s -i eth0 --all --add-bridges bridges.txt\n"
        ),
    )
    parser.add_argument("-i", "--interface", required=True,
                        help="Netzwerkschnittstelle (z. B. eth0, wlan0).")
    parser.add_argument("--spoof-mac", action="store_true",
                        help="MAC-Adresse randomisieren.")
    parser.add_argument("--use-nmcli", action="store_true",
                        help="MAC NM-konform via nmcli setzen (robuster in Tails).")
    parser.add_argument("--mac", metavar="AA:BB:CC:DD:EE:FF",
                        help="Konkrete MAC erzwingen statt Zufall.")
    parser.add_argument("--add-bridges", metavar="DATEI",
                        help="Datei mit obfs4-Bridge-Zeilen in torrc injizieren.")
    parser.add_argument("--kill-switch", action="store_true",
                        help="Kill-Switch-Monitor starten (blockiert bis Ctrl-C).")
    parser.add_argument("--all", action="store_true",
                        help="Alle Funktionen: MAC-Spoofing, Bridges, Kill-Switch.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Debug-Ausgaben aktivieren.")
    return parser


def main(argv=None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose)

    # --all entfaltet die Einzelflags.
    do_spoof = args.spoof_mac or args.all
    do_bridges = bool(args.add_bridges) or (args.all and args.add_bridges)
    do_killswitch = args.kill_switch or args.all

    if not (do_spoof or do_bridges or do_killswitch):
        parser.error("Keine Aktion gewaehlt. Mind. eine von "
                     "--spoof-mac / --add-bridges / --kill-switch (oder --all).")

    require_root()

    if not interface_exists(args.interface):
        logger.error("Schnittstelle %r existiert nicht. Verfuegbar: %s",
                     args.interface, ", ".join(os.listdir("/sys/class/net")))
        return 1

    # --- 1) MAC-Spoofing -----------------------------------------------------
    if do_spoof:
        try:
            if args.use_nmcli:
                spoof_mac_nmcli(args.interface, args.mac)
            else:
                spoof_mac_iplink(args.interface, args.mac)
        except CommandError as exc:
            logger.error("MAC-Spoofing fehlgeschlagen: %s", exc)
            return 1

    # --- 2) obfs4-Bridges ----------------------------------------------------
    if do_bridges:
        try:
            bridges = parse_bridges_file(args.add_bridges)
            target = inject_obfs4_bridges(bridges)
            logger.info("obfs4-Bridges aktiv. Konfiguration: %s", target)
        except CommandError as exc:
            logger.error("Bridge-Injektion fehlgeschlagen: %s", exc)
            return 1

    # --- 3) Kill-Switch ------------------------------------------------------
    if do_killswitch:
        kill_switch = KillSwitch(args.interface)

        # Sauberes Beenden bei Ctrl-C / SIGTERM.
        def _handle_signal(signum, _frame):
            logger.info("Signal %d empfangen -- beende Kill-Switch.", signum)
            kill_switch.stop()

        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

        kill_switch.start()
        try:
            # Hauptthread blockiert, bis der Monitor endet (Trip oder Stop).
            while kill_switch._thread.is_alive():
                time.sleep(0.5)
        finally:
            kill_switch.stop()
            kill_switch.join()

        if kill_switch.tripped:
            logger.critical("Kill-Switch wurde ausgeloest. Interface ist DOWN.")
            return 2

    logger.info("Fertig.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
