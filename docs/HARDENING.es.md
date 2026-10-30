# Evaluación de hardening

Las evaluaciones de AUREON son observaciones locales de solo lectura: no son una certificación, una prueba de intrusión ni una demostración de exposición externa. La aplicación no aplica recomendaciones ni modifica el estado operativo del servidor auditado. Solo escribe en su propia base de historial y en los informes solicitados.

## Comprobaciones actuales

El catálogo cubre configuración SSH efectiva y contextos `Match` representativos; evidencia local del firewall; UID 0, permisos sudo y caducidad predeterminada de contraseñas; metadatos de shadow/claves SSH sin leer contenido; opciones de `/tmp`; journald, `auditctl` y rotación; SELinux/AppArmor y sysctls seleccionados; jails Fail2ban; inspección limitada de contenedores Docker/Podman, incluidos los detenidos; marcadores de reinicio y consultas de actualizaciones con caché local para APT, DNF y zypper; sockets wildcard; sincronización horaria; y evidencia limitada de copias.

Cada comprobación tiene un ID estable, dominio, estado esperado, severidad/peso, fuentes, evidencias, limitaciones, recomendación y procedimiento de verificación. Los resultados son `PASS`, `FAIL`, `UNKNOWN`, `NOT_APPLICABLE` o `ERROR`. Los datos ausentes o inaccesibles nunca se consideran seguros. La disponibilidad de actualizaciones, la eficacia del firewall, la recuperabilidad de copias y los bloques SSH `Match` siguen siendo desconocidos sin evidencia autoritativa. La puntuación se omite cuando cualquier comprobación aplicable no informativa es desconocida o termina en error.

Umbrales como `MaxAuthTries <= 6` y las opciones de montaje son heurísticas, no políticas universales. Revise las evidencias y los requisitos operativos antes de realizar cambios. AUREON no lee claves privadas, no actualiza índices, no instala paquetes, no recarga servicios ni eleva privilegios. Las consultas usan índices locales: APT, `dnf repoquery --cacheonly --security` y `zypper --no-refresh patch-check`, con una heurística de antigüedad de 14 días. `apk` simula actualizaciones generales sin conexión, pero no identifica avisos de seguridad y permanece `UNKNOWN`. Las reglas nftables complejas, la cobertura completa de patrones/grupos/precedencia `Match` y la recuperabilidad de copias siguen sin confirmarse si no hay evidencia concluyente. La inspección abarca hasta 100 contenedores activos y detenidos combinados entre runtimes, con IDs hexadecimales validados.

## Comandos e historial

```bash
aureon assess --json
aureon assess --output evaluacion.json
aureon assess --format csv --output evaluacion.csv
aureon assess-history --json
aureon assess-compare 1 2 --json
```

Cada ejecución de `assess` guarda una instantánea en la base SQLite local de AUREON. El historial lista instantáneas; la comparación usa IDs estables y no interpreta comprobaciones ausentes ni puntuaciones no disponibles como mejoras. Las exportaciones JSON/CSV incluyen definiciones, resultados, evidencias, limitaciones, recomendaciones y verificación. Los archivos exportados usan permisos `0600` cuando es posible.

La migración al esquema versión 2 añade la tabla `assessments` y conserva el historial de eventos; la versión actual de definiciones de checks es 6. Mantenga copias de seguridad de la base local; no se modifica información operativa del servidor auditado.

## Idiomas

La navegación y las etiquetas de evaluación admiten inglés (`en`), portugués (`pt`), español (`es`), francés (`fr`), alemán (`de`), italiano (`it`) y neerlandés (`nl`). Configure `language` en `config.toml` o `AUREON_LANGUAGE`. Los valores no admitidos usan inglés. Las evidencias y el texto del servidor conservan su idioma original para mantener la procedencia.
