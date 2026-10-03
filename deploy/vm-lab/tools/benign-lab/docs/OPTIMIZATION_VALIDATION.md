# Optimizaciones aplicadas a DDOS PUCP LAB

Fecha: 2 de octubre de 2026 (America/Lima). Plataforma desplegada en http://192.168.18.154:8780, repositorio isp-ddos-ryu, rama integrate/vm-lab-distributed-detection.

## Cambios instalados

- Un supervisor por VM comparte la conexión SSH de generación y conserva procesos independientes por abonado/UE. Verificación real: 9 sesiones, 9 supervisores Python y 21 trabajadores; Fixed mantuvo 10 namespaces distintos. La reducción de 21 a 9 corresponde al transporte de generación (57,1 %), no a todos los recolectores de monitoreo.
- Preparación de rutas, receptor y conexiones antes del comienzo común, con comprobación individual de reloj. No se amplían las fechas límite ni se relajan los controles del baseline.
- Métricas activas agrupadas cada 2 s; inicio y fin de eventos enviados inmediatamente.
- Checkpoints, captura de históricos, serialización de históricos y exportación ZIP fuera del bucle de coordinación. Escrituras ordenadas y protegidas ante cancelación.
- Pool TCP/HTTP y receptor v2 con keep-alive, cuotas explícitas y descarte de transferencias incompletas. Las conexiones se separan por origen lógico, dirección, aplicación y destino; UDP/ICMP conservan el mecanismo anterior.
- Dashboard con selector classic/coordinated/persistent, evidencia de transportes y trabajadores, contadores de reutilización y execution_hash. La configuración conectada usa persistent, identificado como experimental; classic y coordinated siguen disponibles.

## Verificación

Suite completa: 64 pruebas aprobadas en Python 3.8. Después del ajuste de lectura/serialización de históricos, las 15 pruebas de API, recursos y baseline afectadas también pasaron. Sintaxis JavaScript y Python verificada. Los generadores reales usan Python 3.10.12; no se actualizó su intérprete.

La prueba corta procesó 252 eventos en todos los dominios: 240 completados y 12 sin carga dentro de su límite inicial de 1,5 s. La segunda tanda completó sus 126 eventos. Se conservó esa evidencia y no se presentó como una aceptación sin fallos.

Una primera prueba completa se detuvo a los 195,13 s para corregir la clasificación de descargas parciales al llegar al límite. El pipeline se restauró y esa prueba se excluyó de la comparación. La versión corregida conserva el criterio anterior y descarta siempre el socket incompleto.

La validación final ejecutó el plan original de 600 s, sin modificar capacidades, población ni archivo de entrada.

- Ejecución: `20261003T002223-6d0ce1fa`; estado `completed_with_errors`.
- Eventos: 7904, con 7113 completados y 791 fallidos. Los completados pueden tener carga incompleta: se conserva su aviso y déficit.
- Ground truth: 120 ventanas de exactamente 5 s.
- Pipeline restaurado al finalizar; ninguna conexión del pool quedó abierta. Verificación posterior: cero supervisores, trabajadores o sesiones SSH de generación residuales.
- Reutilizaciones TCP/HTTP: 742, sobre 6904 eventos TCP/HTTP (10.75 %).
- Métricas: 19995 muestras en 4595 lotes (4.35 muestras/lote).
- Consultas concurrentes de estado, ground truth y recursos: cero errores; máximo observado para el conjunto de tres consultas 5.46 s.
- Exportación durante la ejecución: ZIP válido, 4.93 s; consultas de estado concurrentes entre 0.11 y 2.65 s.

## Resultados por dominio

| Dominio | Referencia clásica: carga observada/plan | Persistente: carga observada/plan | Fallidos clásico / persistente | Desfase p95 clásico / persistente (ms) |
|---|---:|---:|---:|---:|
| mobile | 85.36 % | 83.69 % | 40 / 41 | 6.16 / 4.27 |
| fixed | 81.04 % | 81.29 % | 369 / 414 | 7.56 / 7.09 |
| enterprise | 76.35 % | 86.46 % | 64 / 49 | 2.40 / 2.67 |
| peering | 93.75 % | 93.45 % | 309 / 287 | 46.66 / 59.74 |

La referencia clásica es 20261002T223041-0273f3ea. Usa el mismo plan y diez abonados Fixed. Esta comparación es indicativa: cambia el perfil de ejecución y la hora de la prueba, y la validación nueva añade consultas concurrentes y una exportación. No demuestra causalidad ni una mejora uniforme de todos los dominios.

La carga observada suma TX/RX de los agentes. Para UDP UL no constituye una certificación de recepción extremo a extremo. Enterprise aumentó 10,11 puntos porcentuales frente a la referencia; Mobile bajó 1,67, Fixed subió 0,24 y Peering bajó 0,31. Persisten límites de carga y eventos muy breves; las optimizaciones no eliminan esos déficits.

## CPU de las VMs

| VM | CPU media clásica | CPU media persistente | CPU p95 persistente |
|---|---:|---:|---:|
| control | 33.32 % | 41.24 % | 66.09 % |
| suscriptor | 37.10 % | 39.62 % | 62.15 % |
| ue | 43.55 % | 41.05 % | 45.64 % |
| ue2 | 29.57 % | 31.82 % | 36.16 % |
| peer-router | 58.28 % | 60.01 % | 68.58 % |
| victim | 38.48 % | 42.35 % | 59.93 % |

CPU normalizada por VM, ponderada por intervalo de muestreo. No se midió una reducción de CPU en todos los nodos. El JSON adjunto conserva las estadísticas de las 26 VMs; el dashboard mantiene monitoreo de VMs, interfaces y ambos hosts físicos.

## Reproducibilidad y operación

plan_hash: `2c3580be4272c69a94c0ee39a990b0d33b9aa8654f60ab35d120283d2e118245`.

SHA-256 de benign_plan.json: `3a2b8445f025bd6e1625baf6901f024b10d07567beac12d633e09e665b1fa9dc`. Coincide byte por byte con el plan materializado previo.

execution_hash del perfil persistente: `d9049fdb3ef74c1502601180cced14174d5141da00d53338f5f3405301e9a268`.

BENIGN_V1, semilla 1, cuotas, calendario y ventanas de ground truth no cambian. El modo persistente modifica el patrón de conexiones y debe tratarse como una variante experimental. Para pares B0/B0+ataque usar el mismo archivo de plan, capacidades, mapeo y execution_hash. Para comparar con la generación anterior seleccionar classic; coordinated comparte SSH y agrupa métricas sin reutilizar conexiones TCP/HTTP.

Despliegue y reversión funcional: docs/OPTIMIZED_EXECUTION.md. Instalador: scripts/install_execution_agents.py; usa el inventario privado del repositorio, comprueba ausencia de pruebas activas, conserva copias y reinicia receptores. Para revertir la modalidad basta seleccionar classic; no se modifica el plan ni el aprovisionamiento del laboratorio.

Los parámetros de red, namespaces, IPoE, usuarios y destinos activos están en config/lab.connected.yaml. config/lab.real.yaml conserva el formulario de mapeo para otro laboratorio. Las credenciales siguen fuera del proyecto distribuido.
