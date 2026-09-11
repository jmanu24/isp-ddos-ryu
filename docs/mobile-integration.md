# Integración móvil real — primera etapa

Se retiró el simulador móvil/O-RAN, su CSV KPM, el mapa estático IMSI/IP,
el decodificador de identidad específico de ns-3 y los lanzadores asociados.
Broadband/BNGBlaster se conserva. La webtool ya no crea gNBs ni ataques móviles
simulados. La telemetría móvil real puede ejecutarse sin iniciar Mininet.

## Activación

Definir `MOBILE_OBSERVATIONS_PATH=/ruta/mobile.json` en el entorno del controlador.
Sin esta variable el adaptador permanece desconectado y no genera tráfico.
El productor debe escribir un archivo temporal y reemplazar el snapshot de forma
atómica. El contrato es `tesis.mobile.observations/v1`:

```json
{
  "schema_version": "tesis.mobile.observations/v1",
  "generated_at": 1788890000,
  "flows": [],
  "bindings": [],
  "kpms": []
}
```

Las listas contienen las estructuras definidas en `core/mobile_models.py`.
Timestamps: Unix UTC en segundos; generated_at debe actualizarse con cada snapshot.

- **FlowObservation**: observation_id único por source/network_id, IPs reales,
  puertos, protocolo, bytes_count y packets_count del intervalo [start,end].
  Exportar del UPF/plano de usuario antes de NAT. No enviar contadores acumulados
  ni el mismo intervalo con identificadores diferentes. El productor debe evitar
  solapamientos y observaciones duplicadas de distintos puntos de captura.
- **UeSessionBinding**: SUPI como texto, sesión PDU, IP y ámbito network_id,
  procedencia y validez. La asociación debe cubrir todo el intervalo del flujo.
  ran_source/node_id/ue_id_type/ue_id/cell_id solo se incluyen si fueron resueltos.
  node_id debe distinguir CU/DU y nodo; no representa automáticamente una celda.
  Exportar también cierres/reasignaciones, nunca conservar asociaciones indefinidas
  después de perder conectividad con el core.
- **KpmObservation**: source, node_id, métrica, valor, unidad, timestamp original,
  scope=node/cell/ue, status y reliable. Mantener NO_VALUE como null. No convertir
  PRB de nodo en PRB por UE. No interpretar un contador de volumen como throughput.

Los KPM frescos se conservan en flags.kpm_context del TelemetryEvent. Su volumen
NO se suma: las tasas se calculan solo a partir de contadores reales de flujo.
`bps` mantiene el convenio existente del repositorio: **bytes por segundo**.
La identidad resuelta se conserva en flags.ue_session; una asociación ambigua
queda unresolved. El flujo IP sigue disponible sin inventar UE o celda.
El consumidor de alertas puede leer estos metadatos; todavía no se trasladan
como campos dedicados a todos los resultados de detección/dashboard.

## Control y alcance pendiente

apply_mitigation devuelve False: no existe backend RAN confirmado. No escribe
la antigua cola RC ni anuncia una mitigación aplicada. Falta integrar una política
completa de alertas móviles en la capa de orquestación y confirmaciones de control.

Esta etapa implementa el contrato y su consumo, no instala colectores en Open5GS,
srsRAN o UPF. Quedan pendientes los exportadores reales de flujos/sesiones, la
correlación NGAP/F1AP/E1AP, lectura HTTP del Gateway y la validación por UE.
No se modificó el testbed remoto. Format 4 presentó rechazo al decodificar; la
causa exacta entre encoder/decoder no está demostrada. Format 5 no está validado.

La entrada OpenFlow ya no excluye el prefijo simulado 10.60.0.0/16. Si el tráfico
real del UPF también cruza los switches observados, configurar un único propietario
para su contabilización antes de habilitar ambas fuentes: esta etapa no deduplica
mediciones entre dominios.

## Verificación

`python3 -m unittest discover -s tests -v`

Pruebas de tasas sin doble conteo KPM, asociaciones ambiguas/vencidas, identidad
UE exacta, snapshots repetidos/obsoletos y flujos inválidos. La conexión real aún
requiere pruebas en Ubuntu con el core y la RAN.
