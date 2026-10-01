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

## Modo de campaña: `--mode {isolated,multidomain,both}`

Antes de arrancar la campaña hay que decidir explícitamente qué se va a medir:

- **`isolated`** (recomendado para la matriz básica de 4 dominios × 3 vectores):
  solo TCP/UDP/ICMP_FLOOD, un dominio por corrida. Si `MULTIDOMAIN_FLOOD` queda
  en `--vectors`, se descarta.
- **`multidomain`** (recomendado para el escenario de ataque coordinado):
  solo `MULTIDOMAIN_FLOOD`, exige `--domains` con al menos 2 dominios.
- **`both`** (default, comportamiento previo sin cambios): corre exactamente
  los `--vectors` indicados, mezclando ambos tipos en la misma campaña.

La validación es inmediata (antes de tocar cualquier VM): una combinación
imposible (p. ej. `--mode multidomain` con un solo dominio) termina con error
en el arranque, no a mitad de la campaña con un "Skipping..." silencioso.

```bash
# Matriz básica, aislada, los 4 dominios
python3 analysis/run_vm_lab_trials.py --mode isolated --iterations 30 \
  --output-dir analysis/results/vm-lab-isolated-30

# Escenario multidominio, los 4 dominios atacando a la vez
python3 analysis/run_vm_lab_trials.py --mode multidomain --iterations 30 \
  --output-dir analysis/results/vm-lab-multidomain-30
```

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
se detienen generadores residuales y se exigen ocho sesiones IPoE activas
(Broadband) y la cadena cu1→du1→ue1 saludable (Mobile, señales de
E2/F1/RRC/ping real, igual que `deploy/vm-lab/webtool/status_checks.py`). Una
prueba no se considera válida hasta observar detección, mitigación y
recuperación.

**Mobile es el único dominio cuya recuperación automática no es un gate
duro**: el RACH ZMQ de srsRAN es conocido por su no-determinismo (ver memoria
`mobile-bringup-order`), y a veces la única recuperación real es un
power-cycle completo que este script no ejecuta por sí solo. Si cu1/du1/ue1
no se recuperan tras 3 intentos (`reconnect_mobile_domain.yml --tags
cu1,du1,ue1`), el script imprime una advertencia y continúa con los otros tres
dominios en vez de abortar toda la campaña; las corridas de Mobile en esa
ventana quedarán `INCOMPLETE` en `trials_long.csv` y deben repetirse después
de un bring-up manual (`ansible-playbook playbooks/reconnect_mobile_domain.yml`
desde `deploy/vm-lab/ansible/`).
