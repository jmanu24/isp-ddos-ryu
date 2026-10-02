# Ampliacion de CPU y reparto ESXi

Aplicado: Victim 1 -> 4 vCPU, cuatro procesos receptores SO_REUSEPORT supervisados; Fixed/suscriptor 1 -> 2 vCPU con los diez namespaces. Reinicios limpios de ambas VMs y servicios persistentes verificados. CPU shares de las siete DU/UE cambiadas de high a normal. LatencySensitivity DU/UE se probo normal en una segunda prueba y se restauro high al obtener menor payload. Se conservan reservas MHz, vCPU de radio, memoria y limites ilimitados.

Host: dos sockets, 28 cores fisicos, 56 hilos logicos. 24 VMs encendidas, 90 vCPU tras la ampliacion (antes 86). Sin afinidad manual; todas las VMs en el mismo resource pool. CPU Ready sigue siendo la medida de espera efectiva; tener hilos libres/CPU agregada moderada no garantiza disponibilidad de cada vCPU.

## Misma carga, tres mediciones

| Etapa | Payload logrado | Fallidos | Run |
|---|---:|---:|---|
| Anterior | 71.35 % | 1914 | 20261002T043840-e19cc0ac |
| CPU y paralelo | 75.47 % | 1292 | 20261002T051023-529367f8 |
| Latencia normal | 70.39 % | 1692 | 20261002T052313-79b71c31 |

| Dominio | Anterior % | CPU/paralelo % | Latencia normal % |
|---|---:|---:|---:|
| mobile | 55.56 | 64.91 | 64.10 |
| fixed | 49.66 | 59.74 | 55.50 |
| enterprise | 79.76 | 81.23 | 73.79 |
| peering | 90.17 | 89.97 | 89.41 |

Decision aplicada: conservar CPU/paralelo (75,47 % frente a 71,35 % previo; fallos 1.292 frente a 1.914). Se descarta por ahora la politica de latencia normal: 70,39 % y 1.692 fallos, aunque Ready BR mejora 59,1 -> 35,6 % y CU ~48 -> 27 %. Se restauro high en las siete VMs radio sin cambiar shares normal ni reservas. No se afirma que una sola repeticion pruebe causalidad; se elige conservadoramente la configuracion con mayor payload observado.

## Recursos

| Nodo | CPU media antes / CPU-paralelo / normal % | Ready antes / CPU-paralelo / normal % |
|---|---|---|
| victim | 96.8 / 69.3 / 72.5 | 2.5 / 33.7 / 31.7 |
| suscriptor | 83.3 / 46.1 / 49.6 | 22.7 / 27.6 / 31.0 |
| br | 42.3 / 42.4 / 27.0 | 58.1 / 59.1 / 35.6 |
| ran | 21.7 / 23.0 / 12.2 | 45.7 / 48.3 / 27.3 |
| cu2 | 21.5 / 22.4 / 12.7 | 45.1 / 47.7 / 26.9 |
| ue | 39.3 / 37.9 / 36.7 | 17.0 / 17.1 / 22.8 |
| ue2 | 24.9 / 24.3 / 28.4 | 14.7 / 16.4 / 14.9 |
| pe | 82.9 / 82.4 / 83.9 | 29.6 / 31.3 / 19.5 |
| peer-router | 84.8 / 88.3 / 89.4 | 10.6 / 21.2 / 16.8 |

CPU guest promediada sobre las muestras reales cada ~5 s; el porcentaje de CPU se normaliza por el numero de vCPU, por lo que no comparar porcentajes como si expresaran el mismo tiempo CPU tras ampliar. CPU Ready agregado ESXi dividido por vCPU e intervalo real, deduplicado y ponderado por la superposicion con los 600 s.

Solo una ejecucion por configuracion: variabilidad temporal y cambios combinados CPU/receptor impiden atribuir por separado su beneficio o probar significacion estadistica. La segunda prueba conserva CPU/receiver/shares y cambia latencySensitivity. No se ajustaron duraciones demasiado cortas ni capacidades del perfil para mejorar artificialmente la comparacion.

## Reproducibilidad y operacion

BENIGN_V1, semilla y plan intactos. benign_plan.json es byte a byte identico en las tres ejecuciones; SHA-256 archivo 3a2b8445f025bd6e1625baf6901f024b10d07567beac12d633e09e665b1fa9dc. plan_hash 2c3580be4272c69a94c0ee39a990b0d33b9aa8654f60ab35d120283d2e118245. Ground truth en ventanas de 5 s. Pipeline restaurado en las tres ejecuciones. Las graficas web conservan los contadores reales de interfaces en el historial.

37 pruebas existentes pasaron; nueva prueba Linux paso: cuatro procesos, 40 transferencias TCP, HTTP, UDP y salida/limpieza al fallar un hijo. Receptor real en Victim verificado con cuatro listeners por puerto TCP 9001, HTTP 8088 y UDP 9002 tras reiniciar. Fixed conserva diez namespaces y servicios bng-subscriber-agent/bng-macvlans activos.

Persistencia en repositorio: topology.yaml (Victim 4, Fixed 2, radio shares normal y latency high), deploy_govc.sh respeta la politica al crear nuevas VMs; install_parallel_receiver.py reinstala el receptor desde el control node usando credenciales privadas y SSH conocido; apply_esxi_cpu_policy.py aplica la politica solamente sin experimentos activos. Ver docs/CPU_PARALLEL_RECEIVER.md.

Backups privados en control: .runtime/benign-lab/cpu-upgrade/before.json, after.json, policy-normal.json (prueba) y policy-high.json (estado final). Backups en Victim: /opt/benign-lab/agent.py.before-parallel y /etc/init.d/benign-lab-receiver.before-parallel. Reducir vCPU requiere apagar limpiamente las VMs. Las reservas de radio se conservan para proteger capacidad base.

La sensibilidad alta puede conceder CPU fisica exclusiva, dependiendo de las condiciones del host y reserva; esta captura no demuestra cuantas CPUs quedaron exclusivas. [Broadcom: ajuste de latencia](https://www.vmware.com/docs/perf-latency-tuning-vsphere8).

Para dimensionar definitivamente: repetir ambas configuraciones varias veces; si persiste Ready alto, repartir radio y generadores/routers entre dos hosts fisicos. No crear una VM por UE/suscriptor ni bajar CPU de DU sin una prueba dedicada de radio.
