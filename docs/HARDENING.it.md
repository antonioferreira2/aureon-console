# Valutazione hardening

Le valutazioni AUREON sono osservazioni locali in sola lettura: non sono certificazioni, test di penetrazione o prove di esposizione esterna. L'applicazione non applica raccomandazioni e non modifica lo stato operativo del server verificato. Scrive soltanto la propria cronologia locale e i rapporti richiesti esplicitamente.

## Controlli attuali

Il catalogo copre impostazioni SSH effettive e contesti `Match` rappresentativi; evidenze locali del firewall; UID 0, permessi sudo e scadenza password predefinita; metadati shadow/chiavi SSH senza leggerne il contenuto; opzioni `/tmp`; journald, `auditctl` e rotazione log; SELinux/AppArmor e alcuni sysctl; jail Fail2ban; ispezione limitata di container Docker/Podman, inclusi quelli arrestati; indicatori di riavvio e interrogazioni cache-only per aggiornamenti con APT, DNF e zypper; socket wildcard; sincronizzazione oraria; e indizi limitati sui backup.

Ogni controllo ha un ID stabile, dominio, stato atteso, gravità/peso, fonti, evidenze, limitazioni, raccomandazione e verifica. Gli esiti sono `PASS`, `FAIL`, `UNKNOWN`, `NOT_APPLICABLE` o `ERROR`. I dati mancanti o inaccessibili non sono mai considerati sicuri. Disponibilità degli aggiornamenti, efficacia del firewall, recuperabilità dei backup e blocchi SSH `Match` restano sconosciuti senza evidenze autorevoli. Il punteggio viene omesso se un controllo applicabile non informativo è sconosciuto o in errore.

Soglie come `MaxAuthTries <= 6` e le opzioni di mount sono euristiche, non regole universali. Valutare evidenze e requisiti operativi prima di apportare modifiche. AUREON non legge chiavi private, non aggiorna indici, non installa pacchetti, non ricarica servizi e non aumenta i privilegi. Le query usano cache locali: APT, `dnf repoquery --cacheonly --security` e `zypper --no-refresh patch-check`, con freschezza euristica di 14 giorni. `apk` simula aggiornamenti generali offline, ma non identifica avvisi di sicurezza e resta `UNKNOWN`. Regole nftables complesse, copertura completa di pattern/gruppi/precedenze `Match` e recuperabilità dei backup restano sconosciute senza prove conclusive. L'ispezione copre fino a 100 container attivi e arrestati combinati tra i runtime rilevati, con ID esadecimali convalidati.

## Comandi e cronologia

```bash
aureon assess --json
aureon assess --output valutazione.json
aureon assess --format csv --output valutazione.csv
aureon assess-history --json
aureon assess-compare 1 2 --json
```

Ogni esecuzione di `assess` salva uno snapshot nel database SQLite locale di AUREON. La cronologia elenca gli snapshot; il confronto usa ID stabili e non interpreta verifiche mancanti o punteggi non disponibili come miglioramenti. Le esportazioni JSON/CSV includono definizioni, esiti, evidenze, limitazioni, raccomandazioni e verifiche. I file esportati ricevono permessi `0600` ove possibile.

La migrazione allo schema versione 2 aggiunge la tabella `assessments` e conserva la cronologia degli eventi; la versione attuale delle definizioni è 6. Eseguire backup del database locale come di consueto; i dati operativi del server verificato non vengono modificati.

## Lingue

La navigazione e le etichette della valutazione supportano inglese (`en`), portoghese (`pt`), spagnolo (`es`), francese (`fr`), tedesco (`de`), italiano (`it`) e olandese (`nl`). Impostare `language` in `config.toml` oppure `AUREON_LANGUAGE`. I valori non supportati ricadono sull'inglese. Evidenze e testi provenienti dall'host mantengono la lingua originale per preservarne la provenienza.
