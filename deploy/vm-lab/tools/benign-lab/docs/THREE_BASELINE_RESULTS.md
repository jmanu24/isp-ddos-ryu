# Recomendaciones implementadas y tres pruebas baseline

Las tres pruebas duraron 600 segundos y utilizaron el mismo archivo BENIGN_V1, semilla 1, escenario B0 y pipeline baseline. Durante cada prueba se suspendieron la detección y mitigación de ataques; la restauración terminó antes de iniciar la siguiente. Las tres acabaron con errores de transferencia, sin abortar el experimento.

## Cambios desplegados

- Dos procesos Peering en la misma VM, con reparto determinista por fuente lógica y volumen planificado. Cada proceso conserva 50 fuentes; no se duplican eventos ni se cambia el plan.
- Nueve sesiones SSH de generación y 22 trabajadores: cinco UE, diez namespaces Fixed, cinco Enterprise y dos Peering.
- ESXi en High Performance; sensibilidad de latencia normal en UE, UE2 y DU1–DU5. Se conservan sus vCPU, RAM y reservas de CPU. No se reiniciaron esas VMs por el cambio.
- Validación de peering_workers entre 1 y 16 y registro de partición en execution_hash. Ocho pruebas nuevas; suite completa de 72 pruebas aprobada.
- Documentación de despliegue, política aplicada y reversión. La plataforma continúa mostrando estado, logs, tráfico, recursos y reutilización de conexiones.

## Resultados

Porcentaje = bytes TX + RX observados por los generadores / bytes planificados. No equivale a recepción confirmada de cada envío UDP ni al caudal total de una interfaz.

| Prueba | Perfil | Mobile | Fixed | Enterprise | Peering | Eventos fallidos |
|---|---|---:|---:|---:|---:|---:|
| 1 | coordinated | 84.72 % | 77.95 % | 72.71 % | 93.94 % | 775 |
| 2 | persistent | 77.78 % | 80.21 % | 95.38 % | 93.95 % | 748 |
| 3 | persistent | 83.78 % | 80.23 % | 76.26 % | 92.78 % | 782 |
| Referencia anterior | persistent, 1 Peering | 91.54 % | 86.16 % | 99.95 % | 97.85 % | 368 |

Se repitió **persistent**: obtuvo el mayor cumplimiento del dominio más rezagado entre las primeras dos pruebas. Es una comparación exploratoria; una repetición no establece una mejora estadística ni aísla el efecto de la política física.

| Prueba | Completados | Fallidos | Payload observado total | Reutilizaciones |
|---|---:|---:|---:|---:|
| 1 | 7129 | 775 | 78.40 % | 0 |
| 2 | 7156 | 748 | 89.91 % | 799 |
| 3 | 7122 | 782 | 80.65 % | 838 |

## Espera por CPU

CPU Ready es tiempo de espera por CPU normalizado por vCPU. Se muestran medias aritméticas de las muestras archivadas durante cada ejecución. No se suma este porcentaje entre VMs.

| VM ESXi | Prueba 1 | Prueba 2 | Prueba 3 |
|---|---:|---:|---:|
| lab-wifi-relay | 38.61 % | 36.73 % | 32.36 % |
| br | 33.91 % | 32.44 % | 31.11 % |
| peer-router | 22.89 % | 24.05 % | 25.42 % |
| ue | 19.71 % | 20.43 % | 18.55 % |
| ue2 | 16.12 % | 15.47 % | 16.84 % |

La comprobación directa con esxtop confirmó espera por CPU, sin tiempo de limitación de CPU en la muestra. También mostró Co-Stop en las VMs UE. Esa muestra puntual no representa todo el ensayo. High Performance y sensibilidad normal no eliminaron la contención; no se aumentaron vCPU ni se alteró la configuración física entre las tres pruebas.

## CPU de los trabajadores Peering

CPU de proceso: 100 % significa un núcleo lógico ocupado, no toda la VM.

| Prueba | PID | Fuentes | CPU media | CPU p95 |
|---|---:|---:|---:|---:|
| 1 | 4366 | 50 | 59.80 % | 79.84 % |
| 1 | 4368 | 50 | 60.77 % | 83.11 % |
| 2 | 4635 | 50 | 59.92 % | 78.15 % |
| 2 | 4637 | 50 | 61.08 % | 78.31 % |
| 3 | 4902 | 50 | 62.29 % | 81.73 % |
| 3 | 4900 | 50 | 61.30 % | 77.29 % |

## Integridad y restauración

- plan_hash: `2c3580be4272c69a94c0ee39a990b0d33b9aa8654f60ab35d120283d2e118245`.
- SHA-256 del archivo: `3a2b8445f025bd6e1625baf6901f024b10d07567beac12d633e09e665b1fa9dc`.
- 7.904 eventos y 120 ventanas BENIGN de cinco segundos por prueba. Todas las ventanas quedaron cerradas; esto describe el escenario y no garantiza cumplimiento de cuotas.
- baseline_restored=true en los tres ensayos. La verificación final confirmó cero experimentos activos, baseline del controlador desactivado, cero supervisores/trabajadores de generación y cero sesiones SSH de generación residuales.
- Configuración conectada sin parámetros de mapeo pendientes. Se mantiene persistent como perfil predeterminado y peering_workers=2; config/lab.real.yaml continúa siendo una plantilla, mientras el servicio usa lab.connected.yaml.
- No se ampliaron deadlines, tasas ni capacidades.
- execution_hash cambia entre perfiles porque sus conexiones y opciones de ejecución difieren, aunque plan_hash sea idéntico.

| Prueba | Run ID | execution_hash | lab_hash |
|---|---|---|---|
| 1 | `20261003T011409-b7f7c843` | `cec5d75201b9c4e7df10a6bec0993c76750e89bfd94fa36f8d18305c1bda67b2` | `a7190ead3c2708c8e334b6a8935f39a1db94399834e7ec84f23e2eea51a0972e` |
| 2 | `20261003T012522-65a88e80` | `c8b3428fa8363807eadd2e841e6af50a13e669267a0c504e8af93788f617ae4f` | `f7204cc90492e1db002ea41945b248a71937b7b9076fd3312cfd4d0ffabd2464` |
| 3 | `20261003T013636-30fe808f` | `c8b3428fa8363807eadd2e841e6af50a13e669267a0c504e8af93788f617ae4f` | `f7204cc90492e1db002ea41945b248a71937b7b9076fd3312cfd4d0ffabd2464` |

## Cambios de mapeo entre ensayos

Fixed usa direcciones IPoE obtenidas por DHCP. Entre las pruebas 1 y 2, fixed4 cambió de 10.20.0.29 a 10.20.0.31. Las pruebas 2 y 3 mantuvieron 10.20.0.31 y el mismo lab_hash. El guard obtuvo y validó la dirección vigente en cada preflight. Por ello lab_hash no debe considerarse idéntico, y la comparación no aísla únicamente el perfil. Los ZIP contienen el mapeo efectivo completo de cada ejecución.

## Fallos registrados

Prueba 1: 711 × Deadline reached; compare actual and planned bytes; 58 × Missed event deadline; 6 × [Errno 104] Connection reset by peer.

Prueba 2: 679 × Deadline reached; compare actual and planned bytes; 67 × Missed event deadline; 2 × [Errno 104] Connection reset by peer.

Prueba 3: 702 × Deadline reached; compare actual and planned bytes; 78 × Missed event deadline; 2 × [Errno 104] Connection reset by peer.

## Límite operativo y siguientes pasos

El baseline sigue sin alcanzar todas las cuotas. La referencia anterior entregó 94,85 % del volumen total; los tres ensayos nuevos entregaron 78,40 %, 89,91 % y 80,65 %. No se demuestra una mejora global ni sostenida. La paralelización reduce la concentración en un único proceso, pero no demuestra una mejora global frente al ensayo anterior: cambian el perfil, la política física y las condiciones del host. Para una comparación causal deben alternarse configuraciones y repetirse suficientes veces.

Fijar o conservar las concesiones DHCP/IPoE durante cada par experimental para evitar cambios de origen entre B0 y B0+ataque. Priorizar el enlace Ethernet entre hosts para sacar el transporte del laboratorio de WiFi; después medir relay/BR y CPU Ready con el mismo plan. Las VMs de radio grandes muestran espera y Co-Stop: cualquier reducción de vCPU debe ensayarse con una DU/UE, medir estabilidad de radio y restaurar si empeora. No se recomienda aumentar indiscriminadamente vCPU.

La opción peering_workers permite volver a un solo proceso sin cambiar BENIGN_V1. Para decidir si conservar dos, comparar 1 frente a 2 con el mismo perfil persistente, política física y concesiones, alternando ejecuciones. La comparación de esta entrega no separa ese efecto del cambio físico y de las condiciones del host.

Los eventos más breves que el costo de planificación o establecimiento siguen siendo problemáticos. Un perfil con duración mínima tendría que versionarse como BENIGN_V2, con plan_hash nuevo; no se modificó BENIGN_V1 para ocultar fallos.

La evidencia completa incluye los ZIP originales exportados, baseline-tres-resultados.json y la política de CPU pública. No se distribuyen credenciales ni auditorías privadas del hipervisor.
