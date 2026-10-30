# Évaluation du durcissement

Les évaluations AUREON sont des observations locales en lecture seule — ni certification, ni test d’intrusion, ni preuve d’exposition externe. L’application n’applique aucune recommandation et ne modifie pas l’état opérationnel du serveur audité. Seuls sa base d’historique locale et les rapports explicitement demandés sont écrits.

## Contrôles actuels

Le catalogue couvre la configuration SSH effective et des contextes `Match` représentatifs ; les indices locaux du pare-feu ; UID 0, permissions sudo et expiration par défaut des mots de passe ; les métadonnées shadow/clés SSH sans lire leur contenu ; options `/tmp` ; journald, `auditctl` et rotation ; SELinux/AppArmor et quelques sysctl ; jails Fail2ban ; inspection limitée des conteneurs Docker/Podman, y compris arrêtés ; marqueurs de redémarrage et requêtes de mises à jour fondées sur les caches locaux APT, DNF et zypper ; sockets wildcard ; synchronisation de l’heure ; et indices limités de sauvegarde.

Chaque contrôle possède un identifiant stable, un domaine, un état attendu, une sévérité/pondération, des sources, des preuves, des limites, des recommandations et une procédure de vérification. Les résultats sont `PASS`, `FAIL`, `UNKNOWN`, `NOT_APPLICABLE` ou `ERROR`. Les données manquantes ou inaccessibles ne sont jamais considérées comme sûres. L’état des mises à jour, l’efficacité du pare-feu, la récupérabilité des sauvegardes et les blocs SSH `Match` restent inconnus sans preuve faisant autorité. Le score est masqué dès qu’un contrôle applicable non informatif est inconnu ou en erreur.

Les seuils tels que `MaxAuthTries <= 6` et les options de montage sont des heuristiques, pas des politiques universelles. Examinez les preuves et les besoins opérationnels avant toute modification. AUREON ne lit pas les clés privées, ne rafraîchit pas les index, n’installe pas de paquets, ne recharge pas de service et n’élève pas ses privilèges. Les requêtes utilisent les caches locaux : APT, `dnf repoquery --cacheonly --security` et `zypper --no-refresh patch-check`, avec une heuristique de fraîcheur de 14 jours. `apk` simule les mises à niveau générales hors ligne mais ne distingue pas les avis de sécurité et reste `UNKNOWN`. Les règles nftables complexes, la couverture complète des motifs/groupes/priorités `Match` et la récupérabilité des sauvegardes restent inconnues sans preuve concluante. L’inspection couvre jusqu’à 100 conteneurs actifs et arrêtés combinés entre runtimes, avec des identifiants hexadécimaux validés.

## Commandes et historique

```bash
aureon assess --json
aureon assess --output evaluation.json
aureon assess --format csv --output evaluation.csv
aureon assess-history --json
aureon assess-compare 1 2 --json
```

Chaque commande `assess` enregistre un instantané dans la base SQLite locale d’AUREON. L’historique liste les instantanés ; la comparaison utilise les identifiants stables et ne traite pas les contrôles absents ou les scores indisponibles comme une amélioration. Les exports JSON/CSV contiennent définitions, résultats, preuves, limites, recommandations et vérifications. Les fichiers exportés reçoivent le mode `0600` si possible.

La migration de schéma vers la version 2 ajoute la table `assessments` et conserve l’historique des événements ; la version actuelle des définitions est 6. Sauvegardez la base locale ; aucune donnée opérationnelle du serveur audité n’est modifiée.

## Langues

L’interface prend en charge l’anglais (`en`), le portugais européen (`pt_PT` ; `pt` reste accepté comme alias), l’espagnol (`es`), le français (`fr`), l’italien (`it`), le chinois simplifié (`zh_CN`) et le russe (`ru`). Définissez `language` dans `config.toml` ou `AUREON_LANGUAGE`. Toute valeur non prise en charge utilise l’anglais. Les preuves et textes provenant de l’hôte conservent leur langue d’origine pour préserver leur provenance.
