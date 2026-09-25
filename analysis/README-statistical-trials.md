# Recolección estadística en el laboratorio distribuido

`analysis/run_vm_lab_trials.py` ejecuta las pruebas de forma secuencial y
genera la tabla `Td`, `Tm` y `Tr` para Enterprise, Broadband, Mobile y
Peering.

- **Td:** inicio real del generador → detección.
- **Tm:** detección → aplicación de mitigación.
- **Tr:** aplicación de mitigación → desbloqueo o recuperación.

Las pruebas TCP, UDP e ICMP usan exactamente un origen. La prueba
`MULTIDOMAIN_FLOOD` necesita por definición más de un dominio; utiliza
exactamente un origen por dominio y el mismo destino, protocolo y puerto.
Broadband siempre utiliza una sola sesión atacante; las otras siete sesiones
permanecen en baseline.

## Tamaño de muestra

El valor predeterminado es **30 corridas independientes por combinación**.
Esto permite estimar media, mediana, dispersión, percentiles e intervalos de
confianza sin tratar las acciones de bloqueo de una misma corrida como
observaciones independientes. Si una combinación muestra mucha variabilidad,
se recomienda ampliar a 50 corridas con `--resume --iterations 50`.

## Ejecución

Ejecutar desde la raíz del repositorio en el jump host:

```bash
python3 analysis/run_vm_lab_trials.py --iterations 30 \
  --output-dir analysis/results/vm-lab-30
```

Desde un worktree, el script usa automáticamente el inventario generado en el
checkout principal (`~/isp-ddos-ryu`). También puede indicarse explícitamente
con `--inventory /ruta/absoluta/inventory.ini`.

La ejecución completa puede tardar varias horas porque cada corrida espera el
desbloqueo real y un periodo de enfriamiento. No deben lanzarse ataques
manuales mientras esté activa.

Para una validación corta del procedimiento:

```bash
python3 analysis/run_vm_lab_trials.py --iterations 2 \
  --domains enterprise broadband \
  --vectors TCP_SYN_FLOOD UDP_FLOOD \
  --output-dir /tmp/vm-lab-smoke
```

Si una corrida queda incompleta, el programa termina sin continuar con la
siguiente. Después de resolver la causa:

```bash
python3 analysis/run_vm_lab_trials.py --iterations 30 \
  --output-dir analysis/results/vm-lab-30 --resume
```

Archivos generados:

- `trials.jsonl`: checkpoint append-only con trazabilidad completa.
- `trials_long.csv`: una fila por dominio, vector y corrida.
- `trials_table.csv`: tabla ancha lista para el análisis estadístico.

El orden de las combinaciones se aleatoriza de forma reproducible para reducir
el sesgo por deriva temporal. Antes de cada prueba se comprueban los servicios,
se detienen generadores residuales y se exigen ocho sesiones IPoE activas. Una
prueba no se considera válida hasta observar detección, mitigación y
recuperación.
