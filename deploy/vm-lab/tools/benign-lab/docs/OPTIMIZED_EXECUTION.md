# Ejecución optimizada del laboratorio

La plataforma mantiene BENIGN_V1 y copia exactamente benign_plan.json en cada ejecución. El perfil de ejecución se registra por separado en execution_profile.json, con execution_hash y plan_hash. Para comparar B0 y B0+ataque deben coincidir ambos hashes, además de la topología y las capacidades.

## Perfiles en el dashboard

- classic: un transporte por trabajador; conexiones TCP/HTTP por evento.
- coordinated: un supervisor por VM, trabajadores independientes, métricas agrupadas; conexiones por evento.
- persistent: añade preparación y reutilización de conexiones TCP/HTTP. Es una variante experimental porque modifica el número de conexiones y el patrón de paquetes, aunque mantiene eventos, cuotas y calendario del plan.

La configuración conectada usa persistent por defecto. El selector permite volver a classic o coordinated sin reinstalar. La API acepta execution_profile en POST /api/runs. Configuración:

```yaml
execution:
  default_profile: persistent
  metrics_interval_s: 2
  peering_workers: 2
```

## Transporte y aislamiento

En la topología actual hay 9 transportes de generación: dos VMs UE, una Fixed, cinco Enterprise y un peer-router. Mantienen 22 trabajadores: cinco UE, diez namespaces Fixed, cinco Enterprise y dos generadores Peering. El reparto por fuente lógica está documentado en PEERING_PARALLEL_SCHEDULING.md. Los flujos lógicos de Peering conservan su identidad. Los recolectores de monitoreo usan sus propias conexiones y no están incluidos en estos nueve transportes.

Cada supervisor lanza los trabajadores en sus namespaces originales y transmite controles, estados y métricas por una sesión SSH. Antes del comienzo común verifica receptor, rutas, identidad de origen y reloj. La parada, fin de SSH o señales terminan los procesos descendientes. No se modifica el límite de reloj ni se amplían las fechas límite de los eventos.

La reutilización separa conexiones por IP de origen, abonado lógico, destino, protocolo, dirección y aplicación. Una transferencia incompleta invalida la conexión; no se reenvía su carga automáticamente. El protocolo receptor v2 confirma cuotas TCP y permite HTTP keep-alive. Los receptores antiguos se detectan antes del inicio. UDP e ICMP mantienen su ejecución anterior.

## Monitoreo y archivos

Las muestras activas se agrupan cada dos segundos, con marcas temporales. Los comienzos y finales de evento se transmiten inmediatamente. El dashboard muestra perfil, transportes, trabajadores y conexiones reutilizadas. Los eventos exportados incluyen conexiones abiertas/reutilizadas y bytes confirmados por el receptor cuando corresponde. Las gráficas de interfaces, VMs y ambos hosts siguen disponibles; el ground truth permanece en ventanas de cinco segundos.

La lectura y serialización de históricos para gráficas, la escritura de checkpoints y la compresión de exportaciones se realizan fuera del bucle de coordinación, a partir de copias consistentes y escrituras ordenadas. Una cancelación espera la escritura iniciada antes de liberar su bloqueo.

## Despliegue

El controlador requiere Python 3.8 o superior y conserva su entorno virtual. Instalar agent.py, connection_pool.py y supervisor.py juntos en /opt/benign-lab de cada VM generadora; instalar agent.py y connection_pool.py en Victim. Los módulos usan únicamente la biblioteca estándar. supervisor_path es opcional: por defecto se busca supervisor.py junto a agent_path. Mantener usuarios, claves, known_hosts y permisos sudo existentes.

Desde el nodo control, ejecutar `python3 scripts/install_execution_agents.py` dentro de la herramienta integrada en isp-ddos-ryu. El instalador usa el inventario privado, conserva una copia previa por módulo, comprueba su compilación y reinicia los receptores; rechaza la instalación si encuentra un experimento activo.

Actualizar el receptor de Victim y reiniciar su servicio con cuatro trabajadores cuando no haya experimentos activos; actualizar también los receptores de los cinco sitios Enterprise y después reiniciar benign-lab-web.service. Validar primero un plan corto en todos los dominios y después el plan materializado de 600 segundos. El perfil classic sirve de reversión funcional. Las copias previas de los módulos quedan como *.pre-optimized.py en las VMs durante este despliegue.

Estas mejoras reducen la sobrecarga de control y conexiones. No eliminan límites físicos de CPU, radio, WiFi ni capacidad de enlace; los resultados completos deben evaluarse por dominio.
