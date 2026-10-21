# -*- coding: utf-8 -*-
"""DraveVault - lokale, versleutelde wachtwoord- en notitiekluis (Dravenlock).

Volledig offline. Een hoofdwachtwoord ontgrendelt de kluis; daaruit wordt via
scrypt een sleutel afgeleid en wordt de hele kluis met AES (Fernet) versleuteld.
Het hoofdwachtwoord wordt nergens bewaard. Portable: de kluis staat naast de app
in DraveVault-data.
"""
import os
import sys
import json
import time
import base64
import secrets
import string
import traceback

APP_NAAM = "DraveVault"
APP_VERSIE = "0.1"
DONATIE_URL = "https://paypal.me/roger076"
CONTACT = "service@dravenlock.nl"

WINDOWS = (os.name == "nt")

if getattr(sys, "frozen", False):
    BASIS = os.path.dirname(sys.executable)
else:
    BASIS = os.path.dirname(os.path.abspath(__file__))
FOUT_BESTAND = os.path.join(BASIS, "app-fout.txt")
DATA_MAP = os.path.join(BASIS, "DraveVault-data")
KLUIS_BESTAND = os.path.join(DATA_MAP, "kluis.dat")
CONFIG_BESTAND = os.path.join(DATA_MAP, "instellingen.json")


def zorg_voor_mappen():
    try:
        os.makedirs(DATA_MAP, exist_ok=True)
    except OSError:
        pass


# ---- huisstijl ----
BG = "#0e0e11"
PANEL = "#16161b"
PANEL2 = "#1c1c22"
TEXT = "#d4d4d4"
MUTED = "#8a8a94"
ACCENT = "#6fa3d6"
LINE = "#23232b"
WARN = "#d68a6f"
GOED = "#7fb069"


def _excepthook(soort, waarde, tb):
    try:
        with open(FOUT_BESTAND, "w", encoding="utf-8") as f:
            f.write("DraveVault startfout\n\n")
            f.write("".join(traceback.format_exception(soort, waarde, tb)))
    except Exception:
        pass
    sys.__excepthook__(soort, waarde, tb)


sys.excepthook = _excepthook


# ---------------------------------------------------------------------------
# Instellingen
# ---------------------------------------------------------------------------
STANDAARD_CONFIG = {
    "taal": "auto",
    "auto_lock_min": 5,       # automatisch vergrendelen na X minuten inactiviteit (0 = uit)
    "klembord_wis_sec": 20,   # klembord wissen na X seconden (0 = uit)
}


def laad_config():
    cfg = dict(STANDAARD_CONFIG)
    try:
        with open(CONFIG_BESTAND, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            cfg.update(data)
    except Exception:
        pass
    return cfg


def bewaar_config(cfg):
    try:
        tmp = CONFIG_BESTAND + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        os.replace(tmp, CONFIG_BESTAND)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Versleuteling (scrypt -> AES/Fernet)
# ---------------------------------------------------------------------------
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1


def _afleiden(wachtwoord, salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    ruw = kdf.derive(wachtwoord.encode("utf-8"))
    return base64.urlsafe_b64encode(ruw)


class KluisBeheer:
    """Beheert de versleutelde kluis in het geheugen en op schijf."""

    def __init__(self):
        self.data = None          # {"logins": [...], "notities": [...]}
        self._sleutel = None      # Fernet-sleutel (bytes)
        self._env = None          # envelope-metadata (salt, scrypt-parameters)

    def bestaat(self):
        return os.path.isfile(KLUIS_BESTAND)

    def vergrendeld(self):
        return self.data is None or self._sleutel is None

    def nieuw(self, wachtwoord):
        """Maak een lege, versleutelde kluis met dit hoofdwachtwoord."""
        salt = secrets.token_bytes(16)
        self._sleutel = _afleiden(wachtwoord, salt)
        self._env = {"versie": 1, "kdf": "scrypt", "n": SCRYPT_N,
                     "r": SCRYPT_R, "p": SCRYPT_P,
                     "salt": base64.b64encode(salt).decode()}
        self.data = {"logins": [], "notities": []}
        self.opslaan()

    def openen(self, wachtwoord):
        """Open een bestaande kluis. Geeft True bij juist wachtwoord."""
        from cryptography.fernet import Fernet, InvalidToken
        try:
            with open(KLUIS_BESTAND, encoding="utf-8") as f:
                env = json.load(f)
            salt = base64.b64decode(env["salt"])
            sleutel = _afleiden(wachtwoord, salt, env.get("n", SCRYPT_N),
                                env.get("r", SCRYPT_R), env.get("p", SCRYPT_P))
            ruw = Fernet(sleutel).decrypt(env["token"].encode("utf-8"))
        except InvalidToken:
            return False
        except Exception:
            return False
        data = json.loads(ruw.decode("utf-8"))
        data.setdefault("logins", [])
        data.setdefault("notities", [])
        self.data = data
        self._sleutel = sleutel
        self._env = {k: env[k] for k in ("versie", "kdf", "n", "r", "p", "salt")
                     if k in env}
        return True

    def opslaan(self):
        """Versleutel en schrijf de kluis (veilig via temp + os.replace)."""
        from cryptography.fernet import Fernet
        if self._sleutel is None or self.data is None:
            return
        token = Fernet(self._sleutel).encrypt(
            json.dumps(self.data, ensure_ascii=False).encode("utf-8"))
        env = dict(self._env)
        env["token"] = token.decode()
        tmp = KLUIS_BESTAND + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(env, f)
        os.replace(tmp, KLUIS_BESTAND)

    def wijzig_wachtwoord(self, nieuw_wachtwoord):
        """Versleutel de kluis opnieuw met een nieuw hoofdwachtwoord."""
        salt = secrets.token_bytes(16)
        self._sleutel = _afleiden(nieuw_wachtwoord, salt)
        self._env = {"versie": 1, "kdf": "scrypt", "n": SCRYPT_N,
                     "r": SCRYPT_R, "p": SCRYPT_P,
                     "salt": base64.b64encode(salt).decode()}
        self.opslaan()

    def vergrendel(self):
        """Wis sleutel en gegevens uit het geheugen."""
        self.data = None
        self._sleutel = None


# ---------------------------------------------------------------------------
# Wachtwoordgenerator
# ---------------------------------------------------------------------------
def genereer_wachtwoord(lengte, klein=True, hoofd=True, cijfers=True,
                        symbolen=True):
    groepen = []
    if klein:
        groepen.append(string.ascii_lowercase)
    if hoofd:
        groepen.append(string.ascii_uppercase)
    if cijfers:
        groepen.append(string.digits)
    if symbolen:
        groepen.append("!@#$%^&*()-_=+[]{}:,.?")
    if not groepen:
        groepen = [string.ascii_letters + string.digits]
    alles = "".join(groepen)
    lengte = max(4, int(lengte))
    # zorg dat elke gekozen groep minstens 1 teken levert
    teken = [secrets.choice(g) for g in groepen]
    while len(teken) < lengte:
        teken.append(secrets.choice(alles))
    secrets.SystemRandom().shuffle(teken)
    return "".join(teken[:lengte])


def wachtwoord_sterkte(w):
    """Geeft (0..4, label-sleutel)."""
    if not w:
        return 0, "st_leeg"
    score = 0
    if len(w) >= 8:
        score += 1
    if len(w) >= 12:
        score += 1
    soorten = sum(bool(set(w) & set(g)) for g in (
        string.ascii_lowercase, string.ascii_uppercase, string.digits,
        "!@#$%^&*()-_=+[]{}:,.?<>/\\|~`"))
    if soorten >= 2:
        score += 1
    if soorten >= 3 and len(w) >= 10:
        score += 1
    sleutels = ["st_zwak", "st_zwak", "st_matig", "st_goed", "st_sterk"]
    return score, sleutels[min(score, 4)]


# ---------------------------------------------------------------------------
# Taal
# ---------------------------------------------------------------------------
def detecteer_taal():
    try:
        from PyQt6.QtCore import QLocale
        return "nl" if QLocale.system().name().lower().startswith("nl") else "en"
    except Exception:
        return "en"


TEKST = {
    "nl": {
        "ondertitel": "Veilige kluis voor wachtwoorden en notities - lokaal en offline",
        "menu_kluis": "Kluis", "menu_help": "Help",
        "vergrendelen": "Vergrendelen", "wachtwoord_wijzigen": "Hoofdwachtwoord wijzigen",
        "instellingen": "Instellingen", "afsluiten": "Afsluiten",
        "snelgids": "Snelgids", "over": "Over DraveVault", "donatie": "Donatie",
        "sluiten": "Sluiten", "opslaan": "Opslaan", "annuleren": "Annuleren",
        "ok": "OK", "ja": "Ja", "nee": "Nee",
        # ontgrendelen
        "ontgrendel_titel": "Kluis ontgrendelen",
        "nieuw_titel": "Nieuwe kluis maken",
        "hoofdww": "Hoofdwachtwoord",
        "hoofdww_herhaal": "Hoofdwachtwoord (herhaal)",
        "ontgrendel_knop": "Ontgrendelen",
        "nieuw_knop": "Kluis maken",
        "nieuw_uitleg": "Kies een sterk hoofdwachtwoord. Hiermee wordt je kluis "
                        "versleuteld. LET OP: vergeet je het, dan is de kluis NIET "
                        "te openen - er is geen herstel.",
        "ontgrendel_uitleg": "Vul je hoofdwachtwoord in om de kluis te openen.",
        "ww_leeg": "Vul een hoofdwachtwoord in.",
        "ww_kort": "Gebruik minstens 8 tekens.",
        "ww_verschil": "De twee wachtwoorden zijn niet gelijk.",
        "ww_fout": "Onjuist hoofdwachtwoord.",
        "toon": "Tonen", "verberg": "Verbergen",
        # tabs
        "tab_logins": "Wachtwoorden", "tab_notities": "Notities",
        "zoeken": "Zoeken...",
        "nieuw": "Nieuw", "bewerken": "Bewerken", "verwijderen": "Verwijderen",
        "kopieer_gebruiker": "Kopieer gebruiker", "kopieer_ww": "Kopieer wachtwoord",
        "open_url": "Open URL", "generator": "Wachtwoordgenerator",
        "leeg_logins": "Nog geen wachtwoorden. Klik op 'Nieuw' om er een toe te voegen.",
        "leeg_notities": "Nog geen notities. Klik op 'Nieuw' om er een toe te voegen.",
        # login-velden
        "v_titel": "Titel", "v_gebruiker": "Gebruikersnaam", "v_ww": "Wachtwoord",
        "v_url": "Website (URL)", "v_notitie": "Notitie",
        "login_nieuw": "Nieuw wachtwoord", "login_bewerk": "Wachtwoord bewerken",
        "titel_leeg": "Geef een titel.",
        # notitie
        "n_titel": "Titel", "n_tekst": "Tekst",
        "notitie_nieuw": "Nieuwe notitie", "notitie_bewerk": "Notitie bewerken",
        # generator
        "gen_titel": "Wachtwoordgenerator", "gen_lengte": "Lengte",
        "gen_klein": "kleine letters (a-z)", "gen_hoofd": "HOOFDLETTERS (A-Z)",
        "gen_cijfers": "cijfers (0-9)", "gen_symbolen": "symbolen (!@#...)",
        "gen_maak": "Genereren", "gen_gebruik": "Gebruiken", "gen_kopieer": "Kopieren",
        # kopieren
        "gekopieerd": "Gekopieerd naar klembord (wordt automatisch gewist).",
        "geen_selectie": "Selecteer eerst een item.",
        "verwijder_vraag": "'{naam}' echt verwijderen?",
        # sterkte
        "st_leeg": "", "st_zwak": "zwak", "st_matig": "matig", "st_goed": "goed",
        "st_sterk": "sterk", "sterkte": "Sterkte",
        # instellingen
        "inst_taal": "Taal", "inst_taal_auto": "Automatisch (computertaal)",
        "inst_autolock": "Automatisch vergrendelen na (minuten, 0 = uit)",
        "inst_klembord": "Klembord wissen na (seconden, 0 = uit)",
        # wachtwoord wijzigen
        "ww_huidig": "Huidig hoofdwachtwoord", "ww_nieuw": "Nieuw hoofdwachtwoord",
        "ww_nieuw_herhaal": "Nieuw hoofdwachtwoord (herhaal)",
        "ww_gewijzigd": "Hoofdwachtwoord gewijzigd.",
        # over
        "over_tekst": "DraveVault v{versie}\n\nEen lokale, versleutelde kluis voor "
                      "wachtwoorden en notities. Volledig offline; je gegevens "
                      "blijven op je eigen pc.\n\nContact: {contact}\nDonatie: {donatie}",
        "afsluiten_vraag": "DraveVault afsluiten?",
    },
    "en": {
        "ondertitel": "Secure vault for passwords and notes - local and offline",
        "menu_kluis": "Vault", "menu_help": "Help",
        "vergrendelen": "Lock", "wachtwoord_wijzigen": "Change master password",
        "instellingen": "Settings", "afsluiten": "Quit",
        "snelgids": "Quick guide", "over": "About DraveVault", "donatie": "Donate",
        "sluiten": "Close", "opslaan": "Save", "annuleren": "Cancel",
        "ok": "OK", "ja": "Yes", "nee": "No",
        "ontgrendel_titel": "Unlock vault",
        "nieuw_titel": "Create new vault",
        "hoofdww": "Master password",
        "hoofdww_herhaal": "Master password (repeat)",
        "ontgrendel_knop": "Unlock",
        "nieuw_knop": "Create vault",
        "nieuw_uitleg": "Choose a strong master password. It encrypts your vault. "
                        "NOTE: if you forget it, the vault CANNOT be opened - there "
                        "is no recovery.",
        "ontgrendel_uitleg": "Enter your master password to open the vault.",
        "ww_leeg": "Enter a master password.",
        "ww_kort": "Use at least 8 characters.",
        "ww_verschil": "The two passwords do not match.",
        "ww_fout": "Incorrect master password.",
        "toon": "Show", "verberg": "Hide",
        "tab_logins": "Passwords", "tab_notities": "Notes",
        "zoeken": "Search...",
        "nieuw": "New", "bewerken": "Edit", "verwijderen": "Delete",
        "kopieer_gebruiker": "Copy username", "kopieer_ww": "Copy password",
        "open_url": "Open URL", "generator": "Password generator",
        "leeg_logins": "No passwords yet. Click 'New' to add one.",
        "leeg_notities": "No notes yet. Click 'New' to add one.",
        "v_titel": "Title", "v_gebruiker": "Username", "v_ww": "Password",
        "v_url": "Website (URL)", "v_notitie": "Note",
        "login_nieuw": "New password", "login_bewerk": "Edit password",
        "titel_leeg": "Enter a title.",
        "n_titel": "Title", "n_tekst": "Text",
        "notitie_nieuw": "New note", "notitie_bewerk": "Edit note",
        "gen_titel": "Password generator", "gen_lengte": "Length",
        "gen_klein": "lowercase (a-z)", "gen_hoofd": "UPPERCASE (A-Z)",
        "gen_cijfers": "digits (0-9)", "gen_symbolen": "symbols (!@#...)",
        "gen_maak": "Generate", "gen_gebruik": "Use", "gen_kopieer": "Copy",
        "gekopieerd": "Copied to clipboard (will be cleared automatically).",
        "geen_selectie": "Select an item first.",
        "verwijder_vraag": "Really delete '{naam}'?",
        "st_leeg": "", "st_zwak": "weak", "st_matig": "fair", "st_goed": "good",
        "st_sterk": "strong", "sterkte": "Strength",
        "inst_taal": "Language", "inst_taal_auto": "Automatic (system language)",
        "inst_autolock": "Auto-lock after (minutes, 0 = off)",
        "inst_klembord": "Clear clipboard after (seconds, 0 = off)",
        "ww_huidig": "Current master password", "ww_nieuw": "New master password",
        "ww_nieuw_herhaal": "New master password (repeat)",
        "ww_gewijzigd": "Master password changed.",
        "over_tekst": "DraveVault v{versie}\n\nA local, encrypted vault for passwords "
                      "and notes. Fully offline; your data stays on your own PC.\n\n"
                      "Contact: {contact}\nDonate: {donatie}",
        "afsluiten_vraag": "Quit DraveVault?",
    },
}

_TAAL = "nl"


def T(sleutel):
    return TEKST.get(_TAAL, TEKST["nl"]).get(sleutel, sleutel)


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QListWidget, QListWidgetItem, QTabWidget,
    QMessageBox, QDialog, QFormLayout, QTextEdit, QSpinBox, QCheckBox,
    QComboBox, QStatusBar, QSplitter,
)
from PyQt6.QtGui import QAction, QIcon, QDesktopServices, QGuiApplication
from PyQt6.QtCore import Qt, QUrl, QTimer, QEvent


def _bundel_bestand(naam):
    basis = getattr(sys, "_MEIPASS", BASIS)
    return os.path.join(basis, naam)


def app_icoon():
    for naam in ("app.ico", "logo.png"):
        pad = _bundel_bestand(naam)
        if os.path.isfile(pad):
            ic = QIcon(pad)
            if not ic.isNull():
                return ic
    return QIcon()


def STIJL():
    return """
    QWidget { background: %(bg)s; color: %(text)s; font-size: 15px; }
    QLabel#titel { font-size: 26px; font-weight: bold; color: %(text)s; }
    QLabel#sub { color: %(muted)s; }
    QLabel#kop { font-size: 17px; font-weight: bold; color: %(text)s; }
    QLabel#uitleg { color: %(muted)s; }
    QLineEdit, QTextEdit, QSpinBox, QComboBox {
        background: %(panel2)s; color: %(text)s; border: 1px solid %(line)s;
        border-radius: 8px; padding: 8px; selection-background-color: %(accent)s;
        selection-color: #0b0b0e; }
    QLineEdit:focus, QTextEdit:focus, QSpinBox:focus, QComboBox:focus {
        border: 1px solid %(accent)s; }
    QListWidget {
        background: %(panel)s; color: %(text)s; border: 1px solid %(line)s;
        border-radius: 10px; padding: 4px; }
    QListWidget::item { padding: 10px; border-radius: 6px; }
    QListWidget::item:selected { background: %(accent)s; color: #0b0b0e; }
    QPushButton {
        background: %(panel2)s; color: %(text)s; border: 1px solid %(line)s;
        border-radius: 9px; padding: 9px 14px; }
    QPushButton:hover { border: 1px solid %(accent)s; }
    QPushButton:disabled { color: %(muted)s; }
    QPushButton#primair { background: %(accent)s; color: #0b0b0e; border: none;
        font-weight: bold; }
    QPushButton#primair:hover { background: #84b4e0; }
    QPushButton#gevaar { border: 1px solid %(warn)s; color: %(warn)s; }
    QTabWidget::pane { border: 1px solid %(line)s; border-radius: 10px; top: -1px; }
    QTabBar::tab { background: %(panel)s; color: %(muted)s; padding: 9px 18px;
        border: 1px solid %(line)s; border-bottom: none;
        border-top-left-radius: 8px; border-top-right-radius: 8px; }
    QTabBar::tab:selected { background: %(panel2)s; color: %(text)s; }
    QMenuBar { background: %(bg)s; color: %(text)s; }
    QMenuBar::item:selected { background: %(panel2)s; }
    QMenu { background: %(panel)s; color: %(text)s; border: 1px solid %(line)s; }
    QMenu::item:selected { background: %(accent)s; color: #0b0b0e; }
    QStatusBar { background: %(bg)s; color: %(muted)s; }
    QSplitter::handle { background: %(line)s; }
    """ % {"bg": BG, "panel": PANEL, "panel2": PANEL2, "text": TEXT,
           "muted": MUTED, "accent": ACCENT, "line": LINE, "warn": WARN}


def centreer_op_scherm(dialoog, ouder=None):
    try:
        scherm = (ouder.screen() if ouder else None) or QGuiApplication.primaryScreen()
        geo = scherm.availableGeometry()
        dialoog.move(geo.center().x() - dialoog.width() // 2,
                     geo.center().y() - dialoog.height() // 2)
    except Exception:
        pass


class OntgrendelDialoog(QDialog):
    """Hoofdwachtwoord instellen (nieuwe kluis) of invullen (bestaande)."""

    def __init__(self, kluis, nieuw, ouder=None):
        super().__init__(ouder)
        self.kluis = kluis
        self.nieuw = nieuw
        self.setWindowTitle(T("nieuw_titel") if nieuw else T("ontgrendel_titel"))
        self.setWindowIcon(app_icoon())
        self.resize(480, 300)
        self.setStyleSheet(STIJL())
        lay = QVBoxLayout(self)

        kop = QLabel(APP_NAAM)
        kop.setObjectName("titel")
        lay.addWidget(kop)
        uit = QLabel(T("nieuw_uitleg") if nieuw else T("ontgrendel_uitleg"))
        uit.setObjectName("uitleg")
        uit.setWordWrap(True)
        lay.addWidget(uit)

        form = QFormLayout()
        self.ww = QLineEdit()
        self.ww.setEchoMode(QLineEdit.EchoMode.Password)
        self.ww.returnPressed.connect(self._ok)
        form.addRow(T("hoofdww"), self.ww)
        if nieuw:
            self.ww2 = QLineEdit()
            self.ww2.setEchoMode(QLineEdit.EchoMode.Password)
            self.ww2.returnPressed.connect(self._ok)
            form.addRow(T("hoofdww_herhaal"), self.ww2)
        lay.addLayout(form)

        self.toon = QCheckBox(T("toon"))
        self.toon.toggled.connect(self._toon)
        lay.addWidget(self.toon)

        self.melding = QLabel("")
        self.melding.setStyleSheet("color:%s;" % WARN)
        self.melding.setWordWrap(True)
        lay.addWidget(self.melding)
        lay.addStretch(1)

        rij = QHBoxLayout()
        rij.addStretch(1)
        self.knop = QPushButton(T("nieuw_knop") if nieuw else T("ontgrendel_knop"))
        self.knop.setObjectName("primair")
        self.knop.clicked.connect(self._ok)
        rij.addWidget(self.knop)
        lay.addLayout(rij)
        QTimer.singleShot(0, lambda: (centreer_op_scherm(self, ouder),
                                      self.ww.setFocus()))

    def _toon(self, aan):
        m = QLineEdit.EchoMode.Normal if aan else QLineEdit.EchoMode.Password
        self.ww.setEchoMode(m)
        if self.nieuw:
            self.ww2.setEchoMode(m)

    def _ok(self):
        ww = self.ww.text()
        if not ww:
            self.melding.setText(T("ww_leeg"))
            return
        if self.nieuw:
            if len(ww) < 8:
                self.melding.setText(T("ww_kort"))
                return
            if ww != self.ww2.text():
                self.melding.setText(T("ww_verschil"))
                return
            try:
                self.kluis.nieuw(ww)
            except Exception as e:
                self.melding.setText(str(e))
                return
            self.accept()
        else:
            if self.kluis.openen(ww):
                self.accept()
            else:
                self.melding.setText(T("ww_fout"))
                self.ww.selectAll()
                self.ww.setFocus()


class LoginDialoog(QDialog):
    def __init__(self, ouder, item=None):
        super().__init__(ouder)
        self.item = dict(item) if item else {}
        self.setWindowTitle(T("login_bewerk") if item else T("login_nieuw"))
        self.setWindowIcon(app_icoon())
        self.resize(560, 460)
        self.setStyleSheet(STIJL())
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.titel = QLineEdit(self.item.get("titel", ""))
        self.gebruiker = QLineEdit(self.item.get("gebruiker", ""))
        self.ww = QLineEdit(self.item.get("wachtwoord", ""))
        self.ww.setEchoMode(QLineEdit.EchoMode.Password)
        self.url = QLineEdit(self.item.get("url", ""))
        form.addRow(T("v_titel"), self.titel)
        form.addRow(T("v_gebruiker"), self.gebruiker)

        ww_rij = QHBoxLayout()
        ww_rij.addWidget(self.ww, 1)
        self.toon = QPushButton(T("toon"))
        self.toon.setCheckable(True)
        self.toon.toggled.connect(
            lambda a: self.ww.setEchoMode(
                QLineEdit.EchoMode.Normal if a else QLineEdit.EchoMode.Password))
        ww_rij.addWidget(self.toon)
        gen = QPushButton(T("generator"))
        gen.clicked.connect(self._genereer)
        ww_rij.addWidget(gen)
        ww_wid = QWidget()
        ww_wid.setLayout(ww_rij)
        form.addRow(T("v_ww"), ww_wid)

        self.sterkte = QLabel("")
        self.sterkte.setObjectName("uitleg")
        self.ww.textChanged.connect(self._sterkte)
        form.addRow("", self.sterkte)

        form.addRow(T("v_url"), self.url)
        lay.addLayout(form)
        lay.addWidget(QLabel(T("v_notitie")))
        self.notitie = QTextEdit(self.item.get("notitie", ""))
        lay.addWidget(self.notitie, 1)

        rij = QHBoxLayout()
        rij.addStretch(1)
        ann = QPushButton(T("annuleren"))
        ann.clicked.connect(self.reject)
        rij.addWidget(ann)
        ok = QPushButton(T("opslaan"))
        ok.setObjectName("primair")
        ok.clicked.connect(self._ok)
        rij.addWidget(ok)
        lay.addLayout(rij)
        self._sterkte()
        QTimer.singleShot(0, lambda: centreer_op_scherm(self, ouder))

    def _sterkte(self):
        _, sl = wachtwoord_sterkte(self.ww.text())
        self.sterkte.setText((T("sterkte") + ": " + T(sl)) if self.ww.text() else "")

    def _genereer(self):
        d = GeneratorDialoog(self)
        if d.exec() and d.resultaat:
            self.ww.setText(d.resultaat)
            self.toon.setChecked(True)

    def _ok(self):
        if not self.titel.text().strip():
            QMessageBox.information(self, APP_NAAM, T("titel_leeg"))
            return
        self.item.update({
            "titel": self.titel.text().strip(),
            "gebruiker": self.gebruiker.text(),
            "wachtwoord": self.ww.text(),
            "url": self.url.text().strip(),
            "notitie": self.notitie.toPlainText(),
        })
        self.accept()


class NotitieDialoog(QDialog):
    def __init__(self, ouder, item=None):
        super().__init__(ouder)
        self.item = dict(item) if item else {}
        self.setWindowTitle(T("notitie_bewerk") if item else T("notitie_nieuw"))
        self.setWindowIcon(app_icoon())
        self.resize(560, 460)
        self.setStyleSheet(STIJL())
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.titel = QLineEdit(self.item.get("titel", ""))
        form.addRow(T("n_titel"), self.titel)
        lay.addLayout(form)
        lay.addWidget(QLabel(T("n_tekst")))
        self.tekst = QTextEdit(self.item.get("tekst", ""))
        lay.addWidget(self.tekst, 1)
        rij = QHBoxLayout()
        rij.addStretch(1)
        ann = QPushButton(T("annuleren"))
        ann.clicked.connect(self.reject)
        rij.addWidget(ann)
        ok = QPushButton(T("opslaan"))
        ok.setObjectName("primair")
        ok.clicked.connect(self._ok)
        rij.addWidget(ok)
        lay.addLayout(rij)
        QTimer.singleShot(0, lambda: centreer_op_scherm(self, ouder))

    def _ok(self):
        if not self.titel.text().strip():
            QMessageBox.information(self, APP_NAAM, T("titel_leeg"))
            return
        self.item.update({"titel": self.titel.text().strip(),
                          "tekst": self.tekst.toPlainText()})
        self.accept()


class GeneratorDialoog(QDialog):
    def __init__(self, ouder=None):
        super().__init__(ouder)
        self.resultaat = ""
        self.setWindowTitle(T("gen_titel"))
        self.setWindowIcon(app_icoon())
        self.resize(480, 320)
        self.setStyleSheet(STIJL())
        lay = QVBoxLayout(self)
        self.uitvoer = QLineEdit()
        self.uitvoer.setReadOnly(True)
        f = self.uitvoer.font()
        f.setPointSize(f.pointSize() + 3)
        self.uitvoer.setFont(f)
        lay.addWidget(self.uitvoer)

        form = QFormLayout()
        self.lengte = QSpinBox()
        self.lengte.setRange(4, 128)
        self.lengte.setValue(20)
        form.addRow(T("gen_lengte"), self.lengte)
        lay.addLayout(form)
        self.klein = QCheckBox(T("gen_klein")); self.klein.setChecked(True)
        self.hoofd = QCheckBox(T("gen_hoofd")); self.hoofd.setChecked(True)
        self.cijfers = QCheckBox(T("gen_cijfers")); self.cijfers.setChecked(True)
        self.symbolen = QCheckBox(T("gen_symbolen")); self.symbolen.setChecked(True)
        for c in (self.klein, self.hoofd, self.cijfers, self.symbolen):
            lay.addWidget(c)
            c.toggled.connect(self._maak)
        self.lengte.valueChanged.connect(self._maak)
        lay.addStretch(1)

        rij = QHBoxLayout()
        maak = QPushButton(T("gen_maak"))
        maak.clicked.connect(self._maak)
        rij.addWidget(maak)
        rij.addStretch(1)
        ann = QPushButton(T("annuleren"))
        ann.clicked.connect(self.reject)
        rij.addWidget(ann)
        self.gebruik = QPushButton(T("gen_gebruik"))
        self.gebruik.setObjectName("primair")
        self.gebruik.clicked.connect(self._gebruik)
        rij.addWidget(self.gebruik)
        lay.addLayout(rij)
        self._maak()
        QTimer.singleShot(0, lambda: centreer_op_scherm(self, ouder))

    def _maak(self):
        self.uitvoer.setText(genereer_wachtwoord(
            self.lengte.value(), self.klein.isChecked(), self.hoofd.isChecked(),
            self.cijfers.isChecked(), self.symbolen.isChecked()))

    def _gebruik(self):
        self.resultaat = self.uitvoer.text()
        self.accept()


class InstellingenDialoog(QDialog):
    def __init__(self, ouder, cfg):
        super().__init__(ouder)
        self.cfg = cfg
        self.setWindowTitle(T("instellingen"))
        self.setWindowIcon(app_icoon())
        self.resize(460, 240)
        self.setStyleSheet(STIJL())
        lay = QFormLayout(self)
        self.taal = QComboBox()
        self.taal.addItem(T("inst_taal_auto"), "auto")
        self.taal.addItem("Nederlands", "nl")
        self.taal.addItem("English", "en")
        i = max(0, self.taal.findData(cfg.get("taal", "auto")))
        self.taal.setCurrentIndex(i)
        lay.addRow(T("inst_taal"), self.taal)
        self.autolock = QSpinBox(); self.autolock.setRange(0, 240)
        self.autolock.setValue(int(cfg.get("auto_lock_min", 5)))
        lay.addRow(T("inst_autolock"), self.autolock)
        self.klembord = QSpinBox(); self.klembord.setRange(0, 300)
        self.klembord.setValue(int(cfg.get("klembord_wis_sec", 20)))
        lay.addRow(T("inst_klembord"), self.klembord)
        rij = QHBoxLayout()
        rij.addStretch(1)
        ann = QPushButton(T("annuleren")); ann.clicked.connect(self.reject)
        rij.addWidget(ann)
        ok = QPushButton(T("opslaan")); ok.setObjectName("primair")
        ok.clicked.connect(self._ok)
        rij.addWidget(ok)
        lay.addRow(rij)
        QTimer.singleShot(0, lambda: centreer_op_scherm(self, ouder))

    def _ok(self):
        self.cfg["taal"] = self.taal.currentData()
        self.cfg["auto_lock_min"] = self.autolock.value()
        self.cfg["klembord_wis_sec"] = self.klembord.value()
        self.accept()


class WachtwoordWijzigDialoog(QDialog):
    def __init__(self, ouder, kluis):
        super().__init__(ouder)
        self.kluis = kluis
        self.setWindowTitle(T("wachtwoord_wijzigen"))
        self.setWindowIcon(app_icoon())
        self.resize(480, 260)
        self.setStyleSheet(STIJL())
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.huidig = QLineEdit(); self.huidig.setEchoMode(QLineEdit.EchoMode.Password)
        self.nieuw = QLineEdit(); self.nieuw.setEchoMode(QLineEdit.EchoMode.Password)
        self.herhaal = QLineEdit(); self.herhaal.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow(T("ww_huidig"), self.huidig)
        form.addRow(T("ww_nieuw"), self.nieuw)
        form.addRow(T("ww_nieuw_herhaal"), self.herhaal)
        lay.addLayout(form)
        self.melding = QLabel(""); self.melding.setStyleSheet("color:%s;" % WARN)
        self.melding.setWordWrap(True)
        lay.addWidget(self.melding)
        lay.addStretch(1)
        rij = QHBoxLayout(); rij.addStretch(1)
        ann = QPushButton(T("annuleren")); ann.clicked.connect(self.reject)
        rij.addWidget(ann)
        ok = QPushButton(T("opslaan")); ok.setObjectName("primair")
        ok.clicked.connect(self._ok)
        rij.addWidget(ok)
        lay.addLayout(rij)
        QTimer.singleShot(0, lambda: centreer_op_scherm(self, ouder))

    def _ok(self):
        # huidig wachtwoord verifieren via een verse open-poging
        proef = KluisBeheer()
        if not proef.openen(self.huidig.text()):
            self.melding.setText(T("ww_fout")); return
        if len(self.nieuw.text()) < 8:
            self.melding.setText(T("ww_kort")); return
        if self.nieuw.text() != self.herhaal.text():
            self.melding.setText(T("ww_verschil")); return
        self.kluis.wijzig_wachtwoord(self.nieuw.text())
        self.accept()


SNELGIDS_NL = """
<h2>DraveVault - Snelgids</h2>
<p>DraveVault bewaart je wachtwoorden en notities <b>versleuteld</b> op je eigen
pc. Een <b>hoofdwachtwoord</b> opent de kluis; daarmee wordt alles met AES
versleuteld. Niemand kan erbij zonder dat wachtwoord - ook jij niet als je het
vergeet, dus kies iets dat je onthoudt.</p>
<h3>1. Eerste keer</h3>
<p>Kies een sterk hoofdwachtwoord (minstens 8 tekens). De kluis komt portable in
<code>DraveVault-data</code> naast de app te staan.</p>
<h3>2. Wachtwoorden</h3>
<p>Tabblad <b>Wachtwoorden</b> -&gt; <b>Nieuw</b>: titel, gebruikersnaam,
wachtwoord (of via de <b>generator</b>), website en een notitie. Met
<b>Kopieer gebruiker</b> / <b>Kopieer wachtwoord</b> zet je het op het klembord;
dat wordt na een tijdje <b>automatisch gewist</b>.</p>
<h3>3. Notities</h3>
<p>Tabblad <b>Notities</b> voor vrije, versleutelde tekst (codes, herstelsleutels,
enz.).</p>
<h3>4. Vergrendelen</h3>
<p>Via <b>Kluis -&gt; Vergrendelen</b>, of automatisch na een tijdje niets doen
(in te stellen bij <b>Instellingen</b>). Daarna moet het hoofdwachtwoord opnieuw.</p>
<h3>Goed om te weten</h3>
<ul>
<li>Er is <b>geen herstel</b> van een vergeten hoofdwachtwoord - dat is juist de
beveiliging.</li>
<li>Maak af en toe een kopie van het bestand <code>DraveVault-data/kluis.dat</code>
(blijft versleuteld) als back-up.</li>
</ul>
<p>Donatie (vrijwillig): <b>paypal.me/roger076</b> &middot; Contact:
service@dravenlock.nl</p>
"""

SNELGIDS_EN = """
<h2>DraveVault - Quick guide</h2>
<p>DraveVault stores your passwords and notes <b>encrypted</b> on your own PC. A
<b>master password</b> opens the vault and encrypts everything with AES. Nobody
can access it without that password - not even you if you forget it, so pick
something you'll remember.</p>
<h3>1. First time</h3>
<p>Choose a strong master password (at least 8 characters). The vault is stored
portably in <code>DraveVault-data</code> next to the app.</p>
<h3>2. Passwords</h3>
<p><b>Passwords</b> tab -&gt; <b>New</b>: title, username, password (or via the
<b>generator</b>), website and a note. <b>Copy username</b> / <b>Copy password</b>
put it on the clipboard, which is <b>cleared automatically</b> after a while.</p>
<h3>3. Notes</h3>
<p><b>Notes</b> tab for free, encrypted text (codes, recovery keys, etc.).</p>
<h3>4. Locking</h3>
<p>Via <b>Vault -&gt; Lock</b>, or automatically after a while of inactivity (set
in <b>Settings</b>). After that the master password is required again.</p>
<h3>Good to know</h3>
<ul>
<li>There is <b>no recovery</b> of a forgotten master password - that is exactly
the security.</li>
<li>Occasionally copy <code>DraveVault-data/kluis.dat</code> (stays encrypted) as a
backup.</li>
</ul>
<p>Donate (voluntary): <b>paypal.me/roger076</b> &middot; Contact:
service@dravenlock.nl</p>
"""


class SnelgidsDialoog(QDialog):
    def __init__(self, ouder):
        super().__init__(ouder)
        self.setWindowTitle(T("snelgids"))
        self.setWindowIcon(app_icoon())
        self.resize(680, 620)
        self.setStyleSheet(STIJL())
        from PyQt6.QtWidgets import QTextBrowser
        lay = QVBoxLayout(self)
        b = QTextBrowser()
        b.setOpenExternalLinks(True)
        b.setHtml(SNELGIDS_NL if _TAAL == "nl" else SNELGIDS_EN)
        lay.addWidget(b)
        knop = QPushButton(T("sluiten"))
        knop.clicked.connect(self.accept)
        lay.addWidget(knop)
        QTimer.singleShot(0, lambda: centreer_op_scherm(self, ouder))


class Hoofdvenster(QMainWindow):
    def __init__(self, kluis, cfg):
        super().__init__()
        self.kluis = kluis
        self.cfg = cfg
        self._klembord_inhoud = None
        self._laatste_activiteit = time.time()
        self.setWindowTitle("%s  v%s" % (APP_NAAM, APP_VERSIE))
        self.setWindowIcon(app_icoon())
        self.resize(1000, 640)
        self.setStyleSheet(STIJL())
        self._menu()
        self._bouw()
        self._ververs()

        sb = QStatusBar(); self.setStatusBar(sb)
        self.btn_donatie = QPushButton(" \u2665 " + T("donatie"))
        self.btn_donatie.setObjectName("primair")
        self.btn_donatie.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl(DONATIE_URL)))
        sb.addPermanentWidget(self.btn_donatie)

        # auto-vergrendelen: tik elke 15s en luister naar activiteit
        self._lock_timer = QTimer(self)
        self._lock_timer.timeout.connect(self._controleer_idle)
        self._lock_timer.start(15000)
        QApplication.instance().installEventFilter(self)

    # ---- menu ----
    def _menu(self):
        balk = self.menuBar()
        m = balk.addMenu(T("menu_kluis"))
        a = QAction(T("vergrendelen"), self); a.setShortcut("Ctrl+L")
        a.triggered.connect(self.vergrendel); m.addAction(a)
        a = QAction(T("wachtwoord_wijzigen"), self)
        a.triggered.connect(self._wijzig_ww); m.addAction(a)
        a = QAction(T("instellingen"), self)
        a.triggered.connect(self._instellingen); m.addAction(a)
        m.addSeparator()
        a = QAction(T("afsluiten"), self); a.setShortcut("Ctrl+Q")
        a.triggered.connect(self.close); m.addAction(a)

        h = balk.addMenu(T("menu_help"))
        a = QAction(T("snelgids"), self); a.setShortcut("F1")
        a.triggered.connect(lambda: SnelgidsDialoog(self).exec()); h.addAction(a)
        a = QAction(T("over"), self)
        a.triggered.connect(self._over); h.addAction(a)
        a = QAction(T("donatie"), self)
        a.triggered.connect(lambda: QDesktopServices.openUrl(QUrl(DONATIE_URL)))
        h.addAction(a)

    # ---- opbouw ----
    def _bouw(self):
        centraal = QWidget(); self.setCentralWidget(centraal)
        lay = QVBoxLayout(centraal)
        kop = QLabel(APP_NAAM); kop.setObjectName("titel")
        lay.addWidget(kop)
        sub = QLabel(T("ondertitel")); sub.setObjectName("sub")
        lay.addWidget(sub)

        self.zoek = QLineEdit(); self.zoek.setPlaceholderText(T("zoeken"))
        self.zoek.textChanged.connect(self._ververs)
        lay.addWidget(self.zoek)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._tab_logins(), T("tab_logins"))
        self.tabs.addTab(self._tab_notities(), T("tab_notities"))
        self.tabs.currentChanged.connect(self._ververs)
        lay.addWidget(self.tabs, 1)

    def _tab_logins(self):
        w = QWidget(); lay = QHBoxLayout(w)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.lijst_l = QListWidget()
        self.lijst_l.itemSelectionChanged.connect(self._toon_login)
        self.lijst_l.itemDoubleClicked.connect(lambda *_: self._bewerk_login())
        split.addWidget(self.lijst_l)

        rechts = QWidget(); rl = QVBoxLayout(rechts)
        self.detail_l = QLabel(""); self.detail_l.setObjectName("uitleg")
        self.detail_l.setWordWrap(True)
        self.detail_l.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        self.detail_l.setAlignment(Qt.AlignmentFlag.AlignTop)
        rl.addWidget(self.detail_l, 1)
        rij2 = QHBoxLayout()
        self.btn_kg = QPushButton(T("kopieer_gebruiker"))
        self.btn_kg.clicked.connect(self._kopieer_gebruiker)
        rij2.addWidget(self.btn_kg)
        self.btn_kw = QPushButton(T("kopieer_ww"))
        self.btn_kw.setObjectName("primair")
        self.btn_kw.clicked.connect(self._kopieer_ww)
        rij2.addWidget(self.btn_kw)
        self.btn_url = QPushButton(T("open_url"))
        self.btn_url.clicked.connect(self._open_url)
        rij2.addWidget(self.btn_url)
        rl.addLayout(rij2)
        split.addWidget(rechts)
        split.setSizes([380, 560])
        lay.addWidget(split, 1)

        knoppen = QVBoxLayout()
        for tekst, fn, obj in (
                (T("nieuw"), self._nieuw_login, "primair"),
                (T("bewerken"), self._bewerk_login, ""),
                (T("verwijderen"), self._verwijder_login, "gevaar"),
                (T("generator"), lambda: GeneratorDialoog(self).exec(), "")):
            b = QPushButton(tekst)
            if obj:
                b.setObjectName(obj)
            b.clicked.connect(fn)
            knoppen.addWidget(b)
        knoppen.addStretch(1)
        lay.addLayout(knoppen)
        return w

    def _tab_notities(self):
        w = QWidget(); lay = QHBoxLayout(w)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.lijst_n = QListWidget()
        self.lijst_n.itemSelectionChanged.connect(self._toon_notitie)
        self.lijst_n.itemDoubleClicked.connect(lambda *_: self._bewerk_notitie())
        split.addWidget(self.lijst_n)
        self.detail_n = QTextEdit(); self.detail_n.setReadOnly(True)
        split.addWidget(self.detail_n)
        split.setSizes([380, 560])
        lay.addWidget(split, 1)
        knoppen = QVBoxLayout()
        for tekst, fn, obj in (
                (T("nieuw"), self._nieuw_notitie, "primair"),
                (T("bewerken"), self._bewerk_notitie, ""),
                (T("verwijderen"), self._verwijder_notitie, "gevaar")):
            b = QPushButton(tekst)
            if obj:
                b.setObjectName(obj)
            b.clicked.connect(fn)
            knoppen.addWidget(b)
        knoppen.addStretch(1)
        lay.addLayout(knoppen)
        return w

    # ---- verversen / tonen ----
    def _filter(self, items, velden):
        q = self.zoek.text().strip().lower()
        if not q:
            return list(items)
        uit = []
        for it in items:
            if any(q in str(it.get(v, "")).lower() for v in velden):
                uit.append(it)
        return uit

    def _ververs(self):
        if self.kluis.vergrendeld():
            return
        # logins
        self.lijst_l.clear()
        for it in self._filter(self.kluis.data["logins"],
                               ("titel", "gebruiker", "url", "notitie")):
            qi = QListWidgetItem(it.get("titel", ""))
            qi.setData(Qt.ItemDataRole.UserRole, it.get("id"))
            self.lijst_l.addItem(qi)
        self.detail_l.setText("" if self.kluis.data["logins"] else T("leeg_logins"))
        # notities
        self.lijst_n.clear()
        for it in self._filter(self.kluis.data["notities"], ("titel", "tekst")):
            qi = QListWidgetItem(it.get("titel", ""))
            qi.setData(Qt.ItemDataRole.UserRole, it.get("id"))
            self.lijst_n.addItem(qi)
        if not self.kluis.data["notities"]:
            self.detail_n.setPlainText(T("leeg_notities"))

    def _huidig(self, lijst, bron):
        it = lijst.currentItem()
        if not it:
            return None
        wid = it.data(Qt.ItemDataRole.UserRole)
        for x in self.kluis.data[bron]:
            if x.get("id") == wid:
                return x
        return None

    def _toon_login(self):
        it = self._huidig(self.lijst_l, "logins")
        if not it:
            self.detail_l.setText("")
            return
        regels = ["<b>%s</b>" % _esc(it.get("titel", ""))]
        if it.get("gebruiker"):
            regels.append("%s: %s" % (T("v_gebruiker"), _esc(it["gebruiker"])))
        regels.append("%s: %s" % (T("v_ww"), "&bull;" * 10))
        if it.get("url"):
            regels.append("%s: %s" % (T("v_url"), _esc(it["url"])))
        if it.get("notitie"):
            regels.append("<br>" + _esc(it["notitie"]).replace("\n", "<br>"))
        self.detail_l.setText("<div style='font-size:15px'>"
                              + "<br>".join(regels) + "</div>")

    def _toon_notitie(self):
        it = self._huidig(self.lijst_n, "notities")
        self.detail_n.setPlainText(it.get("tekst", "") if it else "")

    # ---- login-acties ----
    def _nieuw_login(self):
        d = LoginDialoog(self)
        if d.exec():
            d.item["id"] = secrets.token_hex(8)
            self.kluis.data["logins"].append(d.item)
            self.kluis.opslaan(); self._ververs()

    def _bewerk_login(self):
        it = self._huidig(self.lijst_l, "logins")
        if not it:
            QMessageBox.information(self, APP_NAAM, T("geen_selectie")); return
        d = LoginDialoog(self, it)
        if d.exec():
            it.update(d.item); self.kluis.opslaan(); self._ververs()

    def _verwijder_login(self):
        it = self._huidig(self.lijst_l, "logins")
        if not it:
            QMessageBox.information(self, APP_NAAM, T("geen_selectie")); return
        if QMessageBox.question(
                self, APP_NAAM, T("verwijder_vraag").format(naam=it.get("titel", ""))
        ) == QMessageBox.StandardButton.Yes:
            self.kluis.data["logins"].remove(it)
            self.kluis.opslaan(); self._ververs()

    def _kopieer_gebruiker(self):
        it = self._huidig(self.lijst_l, "logins")
        if it:
            self._kopieer(it.get("gebruiker", ""))

    def _kopieer_ww(self):
        it = self._huidig(self.lijst_l, "logins")
        if it:
            self._kopieer(it.get("wachtwoord", ""))

    def _open_url(self):
        it = self._huidig(self.lijst_l, "logins")
        if it and it.get("url"):
            url = it["url"]
            if "://" not in url:
                url = "https://" + url
            QDesktopServices.openUrl(QUrl(url))

    # ---- notitie-acties ----
    def _nieuw_notitie(self):
        d = NotitieDialoog(self)
        if d.exec():
            d.item["id"] = secrets.token_hex(8)
            self.kluis.data["notities"].append(d.item)
            self.kluis.opslaan(); self._ververs()

    def _bewerk_notitie(self):
        it = self._huidig(self.lijst_n, "notities")
        if not it:
            QMessageBox.information(self, APP_NAAM, T("geen_selectie")); return
        d = NotitieDialoog(self, it)
        if d.exec():
            it.update(d.item); self.kluis.opslaan(); self._ververs()

    def _verwijder_notitie(self):
        it = self._huidig(self.lijst_n, "notities")
        if not it:
            QMessageBox.information(self, APP_NAAM, T("geen_selectie")); return
        if QMessageBox.question(
                self, APP_NAAM, T("verwijder_vraag").format(naam=it.get("titel", ""))
        ) == QMessageBox.StandardButton.Yes:
            self.kluis.data["notities"].remove(it)
            self.kluis.opslaan(); self._ververs()

    # ---- klembord ----
    def _kopieer(self, tekst):
        if tekst == "":
            return
        cb = QApplication.clipboard()
        cb.setText(tekst)
        self._klembord_inhoud = tekst
        self.statusBar().showMessage(T("gekopieerd"), 4000)
        sec = int(self.cfg.get("klembord_wis_sec", 20))
        if sec > 0:
            QTimer.singleShot(sec * 1000, self._wis_klembord)

    def _wis_klembord(self):
        cb = QApplication.clipboard()
        if self._klembord_inhoud is not None and cb.text() == self._klembord_inhoud:
            cb.clear()
        self._klembord_inhoud = None

    # ---- vergrendelen / idle ----
    def eventFilter(self, obj, ev):
        if ev.type() in (QEvent.Type.KeyPress, QEvent.Type.MouseButtonPress,
                         QEvent.Type.MouseMove, QEvent.Type.Wheel):
            self._laatste_activiteit = time.time()
        return super().eventFilter(obj, ev)

    def _controleer_idle(self):
        minuten = int(self.cfg.get("auto_lock_min", 0))
        if minuten <= 0 or self.kluis.vergrendeld():
            return
        if time.time() - self._laatste_activiteit >= minuten * 60:
            self.vergrendel()

    def vergrendel(self):
        if self.kluis.vergrendeld():
            return
        self._wis_klembord()
        self.kluis.vergrendel()
        self.hide()
        d = OntgrendelDialoog(self.kluis, nieuw=False, ouder=self)
        if d.exec():
            self._laatste_activiteit = time.time()
            self._ververs()
            self.showMaximized()
        else:
            QApplication.instance().quit()

    # ---- menu-acties ----
    def _wijzig_ww(self):
        d = WachtwoordWijzigDialoog(self, self.kluis)
        if d.exec():
            QMessageBox.information(self, APP_NAAM, T("ww_gewijzigd"))

    def _instellingen(self):
        global _TAAL
        d = InstellingenDialoog(self, self.cfg)
        if d.exec():
            bewaar_config(self.cfg)
            nieuw = self.cfg.get("taal", "auto")
            _TAAL = detecteer_taal() if nieuw == "auto" else nieuw
            QMessageBox.information(self, APP_NAAM,
                                    "Herstart de app om de taal volledig toe te passen."
                                    if _TAAL == "nl" else
                                    "Restart the app to fully apply the language.")

    def _over(self):
        QMessageBox.information(self, T("over"), T("over_tekst").format(
            versie=APP_VERSIE, contact=CONTACT, donatie=DONATIE_URL))

    def closeEvent(self, ev):
        if QMessageBox.question(self, APP_NAAM, T("afsluiten_vraag")
                                ) == QMessageBox.StandardButton.Yes:
            self._wis_klembord()
            ev.accept()
        else:
            ev.ignore()


def _esc(tekst):
    return (str(tekst).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


def main():
    global _TAAL
    zorg_voor_mappen()
    cfg = laad_config()
    taal = cfg.get("taal", "auto")
    _TAAL = detecteer_taal() if taal == "auto" else (taal if taal in ("nl", "en")
                                                     else detecteer_taal())
    if WINDOWS:
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "Dravenlock.DraveVault")
        except Exception:
            pass
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAAM)
    app.setWindowIcon(app_icoon())
    app.setStyleSheet(STIJL())

    kluis = KluisBeheer()
    ontgrendel = OntgrendelDialoog(kluis, nieuw=not kluis.bestaat())
    if not ontgrendel.exec():
        return
    venster = Hoofdvenster(kluis, cfg)
    venster.showMaximized()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
