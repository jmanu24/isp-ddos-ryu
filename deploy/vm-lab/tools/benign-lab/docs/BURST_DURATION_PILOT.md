# Piloto de bursts con mínimo TCP/HTTP de 1 s y 2 s

Se materializan seis variantes BENIGN_BURST_MIN_V1 a partir de los tres planes BENIGN_V1 existentes. Cada variante tiene plan_hash, profile_hash, parent_plan_hash, variant_parameters y un ledger variant_changes con horario/duración/tasa originales. Los originales, semillas y archivo de referencia no se reescriben. La cuota planned_bytes por evento y el volumen total se conservan; UDP/ICMP permanecen intactos.

El algoritmo amplía TCP/HTTP por debajo del mínimo y reduce tasa a bytes*8/duración. Se retiene aproximadamente 10% (ceil por dominio) de los eventos TCP/HTTP originalmente menores de 2 s, seleccionado por SHA256(parent_hash:event_id); la selección es común para ambas variantes. Los eventos retenidos mantienen todos sus campos originales. No se modifica el timeout del agente ni su tolerancia de cierre.

La extensión directa violó picos benignos en los seis casos. No se elevaron los límites: el algoritmo ordena eventos modificados por tasa descendente, inicio original e ID; conserva los demás eventos y ubica cada nuevo intervalo en la posición válida más cercana al inicio original. Verifica capacidad instantánea y límites de 0 a 600 s, con desempate temporal determinista. Si no encuentra una posición válida, falla en lugar de aumentar carga, recortar cuota o extender la prueba.

La recolocación cambia la distribución temporal y los solapamientos. El ledger y el análisis de carga por 5 s lo explicitan. No debe describirse este experimento como cambio exclusivo de timeout; evalúa suavizado temporal con un mínimo y restricciones de pico. Tampoco demuestra que todos los eventos puedan cumplir cuota: el RTT/setup y el receptor siguen consumiendo presupuesto de ejecución.

## Planes preparados

| Semilla | Mínimo | Eventos modificados | Eventos desplazados | Máximo desplazamiento absoluto |
|---|---:|---:|---:|---:|
| 1 | 1 s | 2876 | 284 | 3,131 s |
| 1 | 2 s | 3359 | 177 | 9,935 s |
| 2 | 1 s | 2480 | 173 | 7,269 s |
| 2 | 2 s | 3052 | 242 | 8,371 s |
| 3 | 1 s | 2310 | 256 | 4,237 s |
| 3 | 2 s | 2807 | 237 | 5,961 s |

La suma de bytes de cada par de variantes coincide exactamente con la de su original. Los hashes y la comparación nominal por ventana están en piloto-bursts-carga.json. Ground truth sigue en ventanas de 5 s; los ensayos son B0, con detección/mitigación suspendidas y restauradas al finalizar.

## Ejecución en plataforma

En Pruebas y programación aparecen Preparar variantes 1 s / 2 s y Ejecutar piloto de 9 pruebas. La biblioteca muestra mínimo y hash propios. El piloto usa persistent, duración 600 s, una repetición por condición/semilla, pausa 60 s y este orden:

| Bloque/semilla | Orden |
|---|---|
| S1 | Original → mínimo 1 s → mínimo 2 s |
| S2 | Mínimo 1 s → mínimo 2 s → Original |
| S3 | Mínimo 2 s → Original → mínimo 1 s |

Duración mínima 1 h 38 min más preparación/limpieza. La cola persiste en control y puede cancelarse después de la prueba actual; errores globales o restauración no confirmada detienen el avance. No se permite otro piloto/serie pendiente simultáneo al inicio. Los runs incorporan burst_condition y series_kind. Una repetición por condición solo sirve como piloto; no permite conclusiones estadísticas definitivas.

## Validación

146 pruebas existentes aprobadas y dos nuevas de variantes/API; pruebas focales de cola también pasaron. Se verifican reproducibilidad, conservación por evento, ausencia de cambios UDP/ICMP/retención, límites de carga y duración, orden alternado y protección de originales.

Smoke técnico 20261007T145650-0d7b769b: variante mínima 2 s con retención 0 únicamente para prueba funcional, 20 s, 18 eventos de 1024 bytes en las cinco UE, Fixed, Enterprise y dos fuentes Peering. 18/18 cuotas completas y recepciones confirmadas; pipeline restaurado. Este smoke no estima la mejora de los planes completos ni usa la política de retención del piloto científico.

Usar resultados de cuota, recepción, payload por ventana y recursos para elegir una variante. No mezclar con BENIGN_V1 ni seleccionar solamente la condición favorable. Mantener capacidades, topología y umbrales durante toda la serie. Después de este piloto, repetir condiciones seleccionadas con orden alternado antes de ataques/calibración definitiva.
