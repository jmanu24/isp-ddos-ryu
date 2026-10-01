# Modelo ejecutado y trazabilidad

## Materialización

`G(perfiles, semilla, capacidades, duración) → benign_plan.json`.

La semilla por dominio es el entero de los primeros 8 bytes de SHA-256 de `"{master_seed}:{domain}:BENIGN_V1"`. Los generadores consumen RNG locales, no `random.seed()` global. Cada evento contiene inicio/duración en segundos relativos, dirección vista desde el cliente (UL envía; DL recibe), tasa, presupuesto de bytes, tamaño de chunk/datagrama, destino, protocolo lógico y protocolo realmente emitido.

Mismo archivo implica mismos eventos; semilla sola no garantiza lo mismo si cambian perfiles, capacidades o versión. Usar el JSON materializado como unidad experimental. La implementación utiliza `random.Random` y flotantes: al regenerar, fijar la versión de Python y de este proyecto; para comparación definitiva reutilizar el archivo.

## Perfiles conservados y extensiones

Los cinco YAML provienen de la especificación de la conversación referenciada. `common.yaml` incorpora una única extensión de calibración que se registra en el perfil efectivo. No se ha realizado una validación independiente del origen bibliográfico de los porcentajes MAWI.

Para Mobile/Fixed/Enterprise:

- Muestreo ponderado de estados o sesiones por usuario/sitio y jitter inicial.
- Objetos HTTP Pareto truncados con pausas exponenciales. Descargas, archivos y streaming se traducen a presupuesto de payload.
- Tráfico intersite sigue la matriz de Enterprise y sus filtros por servicio.
- Picos especiales se insertan con el RNG del dominio; su etiqueta permanece BENIGN.
- Se calcula el conjunto de eventos activos en cada intervalo delimitado por un inicio/fin exacto. Se mantienen sin escalar web, DNS/UDP interactivo, ICMP, SSH sintético y picos especiales. Sólo las clases bulk/streaming son escalables.
- Se busca un factor global para alcanzar la media objetivo sujeto a capacidad disponible. Donde cambia el factor debido a solapamientos, se divide el evento en segmentos; `parent_event` permite identificarlos. Cada segmento se ejecuta como una nueva sesión. Por eso las conexiones observadas pueden superar el número de sesiones originales.
- El tamaño de un bulk normalizado es su presupuesto final `rate_bps × duration / 8`; las distribuciones de tamaño originales son propuestas previas a normalización y pueden cambiar. No afirmar conservación exacta de esas distribuciones en el plan final.
- Si ni la máxima tasa permitida alcanza el 80 % de la media objetivo, la opción `supplement_bulk_when_sparse` agrega transferencias `calibration_bulk`, repartidas entre fuentes y direcciones, antes de normalizar de nuevo. Queda explícito en eventos/advertencias. Desactivarla permite estudiar el modelo sin suplemento.
- Las proporciones DL/UL son objetivos de muestreo, no igualdades volumétricas garantizadas. Los perfiles de streaming conservan sus relaciones propuestas al escalarse; las ráfagas pueden alterar la relación global.

Para Peering:

- Envolvente de random walk acotada y pico legítimo independiente. Se centra la parte normal para aproximar la media manteniendo mínimos/máximos.
- Cada tramo crea 20–60 slots concurrentes. Se asigna al menos un slot a cada categoría y se reparte entre sus slots la fracción de bytes objetivo del protocolo.
- Cada slot encadena flujos con duraciones de su clase. `payload_kb` limita los flujos TCP cortos. El pool de 100 fuentes es lógico; para direcciones distintas se debe ampliar el mapeo.
- La composición se cumple para **payload planificado**, con pequeñas diferencias por redondeo entero. Tiempos reales, cabeceras, ICMP y pérdida modifican la mezcla observada.

## Medición y calidad

`rate_bps` y `planned_bytes` son solicitudes al generador. `bytes_tx/rx` son contadores observados del payload por aplicación. `chunks_tx/rx` no equivalen a paquetes TCP. `src_port` y `dst_port` corresponden a sockets TCP/UDP; quedan nulos cuando no aplican. `start_timestamp`/`stop_timestamp` son epoch del agente; `actual_start_s`, `actual_end_s` y `lateness_s` usan el reloj monotónico relativo.

En simulación, todos los contadores son sintéticos y están etiquetados `simulated_payload`. En ejecución real son `application_payload`. La curva del panel siempre dice **carga planificada**; el indicador de Mbps usa deltas de contadores del agente por segundo y se guarda en `metrics.jsonl`.

Al vencer el presupuesto temporal de un evento con payload ya observado, el agente puede reportar `completed` con nota de deadline. Esto significa que su ventana de ejecución terminó, **no** que entregó todos los bytes. Comparar siempre el presupuesto y los contadores. Sin payload, o ante error de conexión, el evento falla. Una ejecución con eventos fallidos termina `completed_with_errors` y no debe aceptarse sin revisar.

El ping nativo sólo informa payload de respuestas recibidas en esta versión; las solicitudes transmitidas no se estiman a partir de respuestas, evitando aparentar entrega donde pudo existir pérdida. ICMP es simétrico en el cable y no obedece estrictamente la dirección lógica del evento.

## Límites prácticos

No se incluyen TLS/HTTPS, DNS real, autenticación SSH como carga, SMTP, códecs ni reproducción de PCAP. El protocolo lógico `other` se emite como UDP. El receptor TCP es específico de esta herramienta: no apunta a servidores arbitrarios de producción. No se incluyen controladores de ataques, creación de namespaces, aprovisionamiento de VMs, agentes de Ryu/OVS ni inferencia del detector.

El proyecto permite ejecutar y registrar la campaña. La calibración en la infraestructura real y la validación científica de sus distribuciones siguen siendo pasos experimentales necesarios. Para métricas L3/L4 utilizar PCAP/contadores y correlacionar timestamps con los artefactos de ejecución.
