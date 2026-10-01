# Validación de la entrega

Entorno: macOS ARM64, Python 3.14.3. Dependencias fijadas en `requirements.lock`. Instalación editable y comando `benign-lab` verificados.

**13 pruebas aprobadas** en la suite final. La única advertencia procede de la transición de Starlette TestClient de httpx a httpx2; no es un fallo de ejecución.

Cobertura:

- Determinismo byte por byte e independencia del RNG entre dominios.
- Integridad SHA-256, rechazo de alteraciones y de sobrescritura de planes distintos.
- Límites exactos de carga, medias objetivo y mezcla de bytes de Peering.
- Picos legítimos e intersite presentes en el plan de 600 s.
- Ventanas semiabiertas de 5 s, warmup, observaciones incompletas y ataques previstos sin confirmar.
- B0 y B0+attack de **600 s completos**, simulados a 100×, con el mismo archivo y hashes de archivo idénticos.
- Exportación de todos los campos de eventos heterogéneos y recuperación de resultados.
- Autenticación, rechazo de peticiones de otro origen y validación de entradas.
- Parada y rechazo de experimentos simultáneos.
- Construcción de comandos SSH/namespace con argumentos escapados.
- **Tráfico real** TCP, UDP y HTTP en ambos sentidos sobre localhost.
- Ejecución real completa del orquestador de 5 s con seis eventos: 3.600 bytes TX y 3.600 bytes RX; puertos y desfase de inicio registrados.
- Cancelación de agentes locales y recuperación explícita tras interrupción.

Ejemplo incluido: `examples/benign_plan.json`, BENIGN_V1 seed 1, 600 s, capacidad 100 Mbps en cada dominio, 7.222 eventos.

```text
plan_hash = 56768742fedb51db39a55b8f440ec8504190eb1be3eb845a2973a96aaef33994
```

Carga media planificada: Mobile 15 %, Fixed 18 %, Enterprise 15 %, Peering 20 %. Los picos no superan, respectivamente, 35 %, 40 %, 35 % y 40 %, salvo redondeo numérico inferior a 1e-6. El ejemplo declara el suplemento de calibración Enterprise y el transporte UDP de la categoría `other`.

No se han probado conexiones a las VMs del usuario, namespaces Linux reales, provisionamiento IPoE/5G, sincronización NTP remota ni precisión ICMP a las tasas de la tesis. Esas comprobaciones se hacen con la guía de mapeo y un piloto antes de la campaña experimental. El plan es reproducible; la fidelidad de carga física requiere calibración.
