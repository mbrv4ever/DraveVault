DraveVault - lokale, versleutelde wachtwoord- en notitiekluis
=============================================================

Dravenlock - lokaal en offline. Je gegevens blijven op je eigen pc.

STARTEN
-------
Dubbelklik run.bat. De eerste keer installeert die zichzelf (Python 3.10 t/m
3.13 nodig). Werkt iets niet, gebruik start-debug.bat: die toont de fouten.

EERSTE KEER
-----------
Je kiest een hoofdwachtwoord. Daarmee wordt je kluis versleuteld (scrypt + AES).
LET OP: vergeet je dit wachtwoord, dan is de kluis NIET te openen. Er is geen
herstel - dat is juist de beveiliging. Kies iets sterks dat je onthoudt.

WAAR STAAT MIJN KLUIS
---------------------
Versleuteld in de map DraveVault-data naast de app (bestand kluis.dat).
Portable: verplaats de hele map mee. Maak af en toe een kopie als back-up;
het bestand blijft versleuteld.

GEBRUIK
-------
- Tabblad Wachtwoorden: logins met titel, gebruiker, wachtwoord, website, notitie.
  Knoppen om gebruiker/wachtwoord naar het klembord te kopieren; het klembord
  wordt automatisch gewist.
- Tabblad Notities: vrije, versleutelde tekst.
- Wachtwoordgenerator ingebouwd.
- Vergrendelen via het menu (Ctrl+L) of automatisch na inactiviteit
  (in te stellen bij Instellingen).
- Snelgids: druk op F1.

LOSSE .EXE MAKEN (optioneel)
----------------------------
Dubbelklik bouw-exe.bat. De .exe komt in de map dist (onefile).

DONATIE (vrijwillig): https://paypal.me/roger076
CONTACT: service@dravenlock.nl
