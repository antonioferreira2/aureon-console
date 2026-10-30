# Hardeningbeoordeling

AUREON-beoordelingen zijn lokale waarnemingen in alleen-lezenmodus — geen certificering, penetratietest of bewijs van externe bereikbaarheid. De toepassing voert aanbevelingen niet uit en wijzigt de operationele toestand van de gecontroleerde server niet. Alleen de eigen lokale AUREON-geschiedenis en expliciet gevraagde rapporten worden geschreven.

## Huidige controles

De catalogus omvat effectieve SSH-instellingen en representatieve `Match`-contexten; lokale firewallaanwijzingen; UID 0, sudo-machtigingen en standaard wachtwoordverloop; shadow-/SSH-sleutelmetadata zonder inhoud te lezen; `/tmp`-mountopties; journald, `auditctl` en logrotatie; SELinux/AppArmor en geselecteerde sysctls; Fail2ban-jails; beperkte inspectie van Docker/Podman-containers, ook gestopte; herstartmarkeringen en cache-only updatecontroles voor APT, DNF en zypper; wildcard-sockets; tijdsynchronisatie; en beperkte back-upaanwijzingen.

Elke controle heeft een stabiele ID, domein, verwachte toestand, ernst/gewicht, gegevensbronnen, bewijs, beperkingen, aanbeveling en verificatie. Uitkomsten zijn `PASS`, `FAIL`, `UNKNOWN`, `NOT_APPLICABLE` of `ERROR`. Ontbrekende of ontoegankelijke gegevens gelden nooit als veilig. Beschikbaarheid van beveiligingsupdates, firewallwerking, herstelbaarheid van back-ups en SSH-`Match`-blokken blijven onbekend zonder gezaghebbend bewijs. De score wordt weggelaten als een toepasselijke niet-informatieve controle onbekend is of een fout geeft.

Drempels zoals `MaxAuthTries <= 6` en mountopties zijn heuristieken, geen universeel beleid. Beoordeel bewijs en operationele vereisten vóór wijzigingen. AUREON leest geen privésleutels, ververst geen pakketindexen, installeert geen pakketten, herlaadt geen diensten en verhoogt geen privileges. Updatecontroles gebruiken lokale caches: APT, `dnf repoquery --cacheonly --security` en `zypper --no-refresh patch-check`, met een versheidsheuristiek van 14 dagen. `apk` simuleert algemene offline-upgrades, maar herkent geen beveiligingsadviezen en blijft daarom `UNKNOWN`. Complexe nftables-regels, volledige `Match`-patronen/groepen/overlap en herstelbaarheid van back-ups blijven onbekend zonder sluitend bewijs. Containerinspectie omvat maximaal 100 actieve en gestopte containers samen over gevonden runtimes en valideert hexadecimale ID's.

## Opdrachten en geschiedenis

```bash
aureon assess --json
aureon assess --output beoordeling.json
aureon assess --format csv --output beoordeling.csv
aureon assess-history --json
aureon assess-compare 1 2 --json
```

Elke `assess`-uitvoering slaat een momentopname op in de lokale SQLite-database van AUREON. De geschiedenis toont momentopnamen; vergelijking gebruikt stabiele ID's en ziet ontbrekende controles of onbeschikbare scores niet als verbetering. JSON/CSV-export bevat definities, uitkomsten, bewijs, beperkingen, aanbevelingen en verificatie. Exportbestanden krijgen waar mogelijk modus `0600`.

De migratie naar schemaversie 2 voegt de tabel `assessments` toe en behoudt de gebeurtenisgeschiedenis; de huidige checkdefinitieversie is 6. Maak zoals gebruikelijk back-ups van de lokale database; operationele gegevens van de gecontroleerde server worden niet gewijzigd.

## Talen

Navigatie en beoordelingslabels ondersteunen Engels (`en`), Portugees (`pt`), Spaans (`es`), Frans (`fr`), Duits (`de`), Italiaans (`it`) en Nederlands (`nl`). Stel `language` in `config.toml` of `AUREON_LANGUAGE` in. Niet-ondersteunde waarden vallen terug op Engels. Bewijs en hostteksten behouden hun oorspronkelijke taal om herkomst te bewaren.
