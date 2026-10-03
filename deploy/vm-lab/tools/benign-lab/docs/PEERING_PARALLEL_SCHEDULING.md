# Peering paralelo y planificación compartida

La ejecución conectada usa dos procesos Peering en la misma VM y una única sesión SSH de generación para esa VM. En total: 9 transportes y 22 trabajadores (5 Mobile, 10 Fixed, 5 Enterprise y 2 Peering).

```yaml
execution:
  default_profile: persistent
  metrics_interval_s: 2
  peering_workers: 2
```

El número de trabajadores se valida entre 1 y 16. BENIGN_V1 y benign_plan.json permanecen intactos. `logical_source_bytes_v1` calcula el volumen planificado por fuente lógica, ordena por volumen descendente y nombre, y asigna cada fuente completa al trabajador con menor volumen acumulado; los empates usan el índice del trabajador. Ninguna fuente se reparte entre procesos y no se duplican eventos. La asignación es independiente del orden de los eventos del archivo. Cada trabajador conserva su pool y sus fuentes.

peering_workers y partition_algorithm forman parte de execution_options y execution_hash. Una comparación experimental debe conservar esos parámetros además de plan_hash y el mapeo real. Para el comportamiento anterior de un proceso, configurar peering_workers: 1.

## Política física aplicada

Host ESXi: dos Xeon E5-2680 v4, 28 núcleos físicos y 56 hilos. La auditoría no encontró afinidades manuales ni límites de CPU en las VMs encendidas. Había siete VMs de radio con sensibilidad de latencia high: ue, ue2 y du..du5. Se configuraron con sensibilidad normal para compartir el host, conservando las reservas de CPU, sus 8 vCPU y RAM. No hubo apagados de VMs ni reinicios de servicios de radio por este cambio.

Las reservas permanecen en 6250 MHz para cada VM UE y 9300 MHz para cada DU. ESXi pasó de Balanced a High Performance. La topología del repositorio conserva latency_sensitivity: normal, y el instalador de política usa normal por defecto.

Desde el nodo control:

```text
python3 scripts/apply_esxi_cpu_policy.py --latency normal --power-policy high-performance
```

Reversión de la política anterior (con experimentos detenidos):

```text
python3 scripts/apply_esxi_cpu_policy.py --latency high --power-policy balanced
```

El script rechaza cambios cuando detecta una ejecución activa. La reversión conserva también las reservas. Para versiones originales del repositorio, aplicar primero el parche acumulado entregado.

## Comparación final solicitada

Tres ejecuciones baseline de 600 s: coordinated, persistent y repetición del perfil que obtuvo mejor resultado entre las primeras dos. El criterio de selección prioriza el menor porcentaje de carga observada entre los cuatro dominios; después usa la media por dominio y, ante empate, menos eventos fallidos. Los tres ensayos usan el mismo archivo, semilla, cuotas, duraciones y dos trabajadores Peering.

Cada prueba suspende detección y mitigación mediante el guard existente. Se comprueba la restauración antes de iniciar la siguiente, la integridad del archivo, 120 ventanas BENIGN de 5 s y nueve transportes con 22 trabajadores. No se amplían deadlines ni se cambian capacidades para disimular déficits.

Es una comparación exploratoria: dos perfiles y una repetición no proporcionan una estimación estadística robusta. Los resultados reales y las esperas de CPU deben determinar el perfil predeterminado. Los cambios físicos se mantienen constantes durante los tres ensayos.
