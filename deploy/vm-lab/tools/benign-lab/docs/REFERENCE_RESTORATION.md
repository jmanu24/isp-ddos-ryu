# Restauración de la referencia — 7 octubre 2026

Referencia histórica: `4ec77ba`, restaurada mediante `0eeb0e9`. Perfil `persistent`, BENIGN_V1 original, sin alargar bursts ni redistribuir sus horarios.

El motor de envío actual conserva la lógica de esa revisión. Se conserva el diagnóstico v2 que clasifica las cuotas incompletas como fallidas: restaurar la clasificación antigua aumentaría los finalizados sin mejorar bytes entregados. Por eso no se sustituyen agentes ni se reutiliza el execution_hash histórico.

Se retiran los controles de preparación/inicio del piloto de mínimos 1 s / 2 s. La biblioteca selecciona por defecto el plan original de semilla 1; un botón prepara modo laboratorio B0, pipeline baseline y persistent, sin iniciar tráfico. Los planes experimentales y sus resultados siguen disponibles para análisis.

Se preservan los dos peers con sus AS, la distribución por fuente lógica, la migración Workstation, namespaces Fixed, mapeos dinámicos, preflight de las cinco UE, monitorización, analítica y programación. No se modifican vCPU, servicios de radio, umbrales, capacidades ni archivos de planes.

La referencia histórica alcanzó payload cliente/previsto Mobile 91.54%, Fixed 86.16%, Enterprise 99.95%, Peering 97.85%. La topología física de entonces era diferente; restaurar esta configuración no demuestra recuperar esos porcentajes. Se requiere repetir las pruebas completas en el laboratorio actual.
