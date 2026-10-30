# Avaliação de hardening

As avaliações AUREON são observações locais e somente de leitura — não são certificação, teste de intrusão nem prova de exposição externa. A aplicação não aplica recomendações nem altera o estado operacional do servidor auditado. Apenas a base de histórico própria do AUREON e os relatórios pedidos são escritos.

## Verificações atuais

O catálogo cobre definições SSH efetivas e amostras de contextos `Match`; evidência local de firewall; UID 0, permissões sudo e política padrão de expiração de passwords; metadados de shadow/chaves SSH sem ler conteúdos; opções de `/tmp`; journald, `auditctl` e rotação de logs; SELinux/AppArmor e sysctls selecionados; jails Fail2ban; inspeção limitada de contentores Docker/Podman, incluindo parados; marcadores de reinício e consultas de atualizações com cache local em APT, DNF e zypper; sockets wildcard; sincronização horária; e evidência limitada de backups.

Cada verificação tem ID estável, domínio, estado esperado, severidade/peso, fontes, evidência, limitações, recomendação e procedimento de verificação. Os resultados são `PASS`, `FAIL`, `UNKNOWN`, `NOT_APPLICABLE` ou `ERROR`. Dados ausentes ou inacessíveis nunca contam como seguros. Disponibilidade de atualizações, eficácia do firewall, recuperação de backups e blocos SSH `Match` permanecem desconhecidos sem evidência autoritativa. A pontuação é omitida quando qualquer verificação aplicável não informativa é desconhecida ou tem erro.

Limites como `MaxAuthTries <= 6` e opções de montagem são heurísticas, não políticas universais. Revise evidências e requisitos operacionais antes de qualquer alteração independente. A aplicação não lê conteúdos de chaves privadas, não atualiza índices, não instala pacotes, não recarrega serviços e não eleva privilégios. Atualizações usam consultas à cache existente: APT, `dnf repoquery --cacheonly --security` e `zypper --no-refresh patch-check`; a idade de índices usa uma heurística de 14 dias. O `apk` simula atualizações gerais offline, mas não distingue avisos de segurança, pelo que permanece `UNKNOWN`. Firewall nftables complexo, cobertura de `Match` com padrões/grupos/precedências e recuperabilidade de backups continuam desconhecidos quando não demonstráveis. A inspeção cobre até 100 contentores ativos e parados combinados entre runtimes, usando IDs hexadecimais validados.

## Comandos e histórico

```bash
aureon assess --json
aureon assess --output avaliacao.json
aureon assess --format csv --output avaliacao.csv
aureon assess-history --json
aureon assess-compare 1 2 --json
```

Cada execução CLI de `aureon assess` guarda um snapshot na base SQLite local do AUREON; abrir ou atualizar o painel TUI não grava histórico. O histórico lista snapshots; a comparação usa IDs estáveis e não interpreta verificações ausentes ou pontuações indisponíveis como melhoria. JSON/CSV incluem definições, resultados, evidências, limitações, recomendações e verificações. Os ficheiros exportados recebem permissões `0600` quando suportado.

A migração de schema para versão 2 acrescenta a tabela `assessments` e preserva o histórico de eventos; a versão atual das definições de checks é 6. Faça cópias de segurança da base local como habitualmente; dados operacionais do servidor auditado não são alterados.

## Idiomas

A interface suporta inglês (`en`), português europeu (`pt_PT`; `pt` é aceite como alias), espanhol (`es`), francês (`fr`), italiano (`it`), chinês simplificado (`zh_CN`) e russo (`ru`). Configure `language` em `config.toml` ou `AUREON_LANGUAGE`. Valores não suportados usam inglês. Evidências e texto obtido do servidor mantêm o idioma original para preservar a proveniência.
