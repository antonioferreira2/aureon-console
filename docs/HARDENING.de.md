# Hardening-Bewertung

AUREON-Bewertungen sind lokale Beobachtungen im Nur-Lese-Modus – keine Zertifizierung, kein Penetrationstest und kein Nachweis externer Erreichbarkeit. Die Anwendung setzt keine Empfehlungen um und verändert den Betriebszustand des geprüften Servers nicht. Geschrieben werden nur die lokale AUREON-Historie und ausdrücklich angeforderte Berichte.

## Derzeitige Prüfungen

Der Prüfungskatalog umfasst effektive SSH-Einstellungen und repräsentative `Match`-Kontexte; lokale Firewall-Hinweise; UID 0, sudo-Berechtigungen und Standard-Passwortalterung; Shadow-/SSH-Schlüsselmetadaten ohne Inhaltszugriff; `/tmp`-Mountoptionen; journald, `auditctl` und Logrotation; SELinux/AppArmor und ausgewählte Sysctls; Fail2ban-Jails; begrenzte Prüfung von Docker/Podman-Containern einschließlich gestoppter; Neustartmarker und Cache-Abfragen für Sicherheitsupdates mit APT, DNF und zypper; Wildcard-Sockets; Zeitsynchronisierung; sowie begrenzte Backup-Hinweise.

Jede Prüfung hat eine stabile ID, Domäne, erwarteten Zustand, Schweregrad/Gewichtung, Datenquellen, Belege, Einschränkungen, Empfehlung und Verifikationsschritte. Ergebnisse sind `PASS`, `FAIL`, `UNKNOWN`, `NOT_APPLICABLE` oder `ERROR`. Fehlende oder unzugängliche Daten gelten niemals als sicher. Verfügbarkeit von Sicherheitsupdates, tatsächliche Firewall-Wirkung, Wiederherstellbarkeit von Backups und SSH-`Match`-Blöcke bleiben ohne maßgebliche Belege unbekannt. Ein Score wird zurückgehalten, sobald eine anwendbare nicht-informative Prüfung unbekannt ist oder fehlschlägt.

Grenzwerte wie `MaxAuthTries <= 6` und Mountoptionen sind Heuristiken, keine allgemeingültigen Richtlinien. Prüfen Sie Belege und Betriebsanforderungen vor Änderungen. AUREON liest keine privaten Schlüssel, aktualisiert keine Paketindizes, installiert keine Pakete, lädt keine Dienste neu und erhöht keine Rechte. Update-Abfragen verwenden lokale Caches: APT, `dnf repoquery --cacheonly --security` und `zypper --no-refresh patch-check`; die Aktualität wird heuristisch auf 14 Tage begrenzt. `apk` simuliert allgemeine Offline-Upgrades, identifiziert jedoch keine Sicherheitsmeldungen und bleibt daher `UNKNOWN`. Komplexe nftables-Regeln, vollständige `Match`-Muster/Gruppen/Überlappungen und Backup-Wiederherstellbarkeit bleiben ohne eindeutige Belege unbekannt. Die Containerprüfung umfasst höchstens 100 aktive und gestoppte Container über erkannte Laufzeiten hinweg und validiert hexadezimale IDs.

## Befehle und Verlauf

```bash
aureon assess --json
aureon assess --output bewertung.json
aureon assess --format csv --output bewertung.csv
aureon assess-history --json
aureon assess-compare 1 2 --json
```

Jeder Aufruf von `assess` speichert einen Snapshot in der lokalen SQLite-Datenbank von AUREON. Der Verlauf listet Snapshots; der Vergleich verwendet stabile IDs und deutet fehlende Prüfungen oder nicht verfügbare Scores nicht als Verbesserung. JSON/CSV-Exporte enthalten Definitionen, Ergebnisse, Belege, Einschränkungen, Empfehlungen und Verifikation. Exportdateien erhalten nach Möglichkeit Modus `0600`.

Die Migration auf Schema-Version 2 ergänzt die Tabelle `assessments` und erhält die Ereignishistorie; die aktuelle Definitionsversion der Prüfungen ist 6. Sichern Sie die lokale Datenbank wie üblich; Betriebsdaten des geprüften Servers werden nicht verändert.

## Sprachen

Navigation und Bewertungslabels unterstützen Englisch (`en`), Portugiesisch (`pt`), Spanisch (`es`), Französisch (`fr`), Deutsch (`de`), Italienisch (`it`) und Niederländisch (`nl`). Setzen Sie `language` in `config.toml` oder `AUREON_LANGUAGE`. Nicht unterstützte Werte fallen auf Englisch zurück. Belege und Hosttexte bleiben in ihrer Ursprungssprache, um die Herkunft zu bewahren.
