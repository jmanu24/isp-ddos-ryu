# Plan de revisión de la tesis conforme al nuevo diseño

Fecha: 2026-09-09. Documento revisado: `Tesis_PUCP (7).pdf` (147 páginas).
Referencia arquitectónica: [Diseño de implementación](implementation-design.md) y [flujos de plataforma](platform-flows.md).

Las páginas indicadas son las **impresas en la tesis**. Para las páginas arábigas, sumar 16 para ubicarlas en el visor PDF; por ejemplo, p.112 corresponde a la página PDF128. Resumen: iii–iv (PDF4–5); Abstract: v–vi (PDF6–7).

Este informe propone modificaciones; no altera el PDF ni certifica nuevamente los resultados históricos. El diseño objetivo no equivale a una implementación terminada.

## 1. Dictamen

La motivación y los cuatro dominios siguen siendo pertinentes. Deben revisarse sustancialmente la arquitectura experimental, la operacionalización, la campaña de validación y la interpretación de resultados. El nuevo aporte es un **orquestador centralizado de análisis y decisión, con adquisición y ejecución distribuidas por dominio**, para DoS/DDoS TCP SYN, UDP e ICMP floods y ataques multidominio.

Conviene distinguir en todo el documento:

- **Prototipo anterior:** campaña de 14 subcasos y simulador móvil, con sus límites y evidencia conservada.
- **Estado actual de migración:** simulador móvil retirado; contrato de observaciones y correlación móvil incorporados al repositorio; integración y control completos pendientes.
- **Diseño objetivo:** cuatro dominios instrumentados y acciones verificadas mediante sus respectivos elementos de control.

Los experimentos históricos pueden conservarse como validación preliminar o anexo. No deben renombrarse como pruebas del nuevo testbed ni completarse con resultados previstos.

## 2. Correcciones críticas antes de ampliar el texto

| Ubicación | Hallazgo | Modificación necesaria |
|---|---|---|
| Tabla 3.8, p.75; §4.1.1, pp.80–81; Tabla 4.8, p.93; Tabla 5.2, p.112 | La tabla de alcance declara RC no implementado, pero infraestructura/resultados describen aislamiento RC. La tabla de mecanismos mezcla simulador y xApp. | Identificar el actuador efectivamente usado en cada ejecución. Donde fue el generador, escribir «actuación sobre generador del prototipo»; reservar «E2SM-RC» para una orden que llegó al agente RAN y cuyo efecto se comprobó. |
| Tabla 3.2, p.67 frente a Tablas 3.7, p.74; 4.16, p.105; 5.3, p.116 | HE1 trata del análisis de limitaciones, pero se contrasta con cobertura de telemetría; HE2 trata de mejora de detección, pero se evalúa agrupación por destino; HE3 trata de correlación y decisión, pero se contrasta clasificación de protocolos. | Rehacer una única matriz problema–objetivo–hipótesis–indicador–experimento–evidencia, y reutilizar los mismos enunciados e identificadores. |
| HG, p.66; §5.2.5 y Tabla 5.3, pp.115–116 | Se plantea mejora significativa respecto de mecanismos independientes; los resultados presentados no aportan esa comparación ni series estadísticas suficientes. | Incorporar una campaña comparativa o reformular la hipótesis como factibilidad medible. No declarar superioridad significativa a partir de funcionalidad observada. |
| §5.2.2, p.113 | La cadencia de 0.5 s se usa para acotar el tiempo de mitigación. | Separar decisión, despacho, instalación y efecto. El período del bucle no limita por sí solo el tiempo del backend ni la mitigación efectiva. |
| §5.2.4, p.115 | Se considera suficiente el registro del controlador para reconstruir mitigación/liberación y se generaliza observabilidad a cuatro tableros. | El log acredita lo que registró el controlador; exigir respuestas, lectura de estado y medición independiente. Un tablero de peering existente no prueba telemetría de ese dominio. |
| §5.2.5, Tabla 5.3, p.116 | HE4 afirma mitigación en los catorce subcasos, aunque uno es línea base sin ataque. | Distinguir casos positivos y negativos; en línea base el éxito es no emitir una mitigación indebida. |

## 3. Modificaciones por capítulo

### Portada, Resumen y Abstract

**Título sugerido:** «Diseño e implementación de un orquestador centralizado para la detección de ataques DoS/DDoS y su mitigación distribuida en cuatro dominios de una red de Service Provider».

El título actual puede mantenerse si se explicita centralización lógica en el objetivo y se demuestra experimentalmente qué significa «temprana». No confundir mitigación distribuida con decisión descentralizada.

Reescribir Resumen/Abstract al terminar la nueva campaña: finalidad, cuatro dominios, flujos de datos, normalización/correlación, actuación específica y resultados realmente medidos. Mientras tanto, describir el nuevo sistema como diseño en implementación. Actualizar las menciones al generador móvil y los catorce subcasos. Homogeneizar IPoE frente a PPPoE/IPoE según las sesiones efectivamente evaluadas. No añadir precisión, latencias o porcentajes de eficacia aún no medidos.

### Capítulo I: problema, objetivos y viabilidad

| Sección/páginas | Conservar | Cambiar o incorporar |
|---|---|---|
| §1.1–1.2, pp.1–10 | Motivación de visibilidad fragmentada y heterogeneidad del SP. | Delimitar tres vectores; distinguir DoS, DDoS y multidominio; explicar que observar el mismo tráfico en acceso y borde no implica dos dominios de origen. |
| §1.3 y Tabla 1.3, pp.11–13 | Propósito de integración y evaluación. | Incluir implementación del orquestador y verificación de control. OE4 incluye ataques de aplicación: retirarlos del alcance obligatorio, pues no forman parte del diseño solicitado. |
| §1.4, pp.14–20; Tablas 1.4–1.6 | Justificación técnica y práctica. | Precisar contribución: contratos, correlación temporal e identidad, deduplicación, decisión y traducción de acciones, verificación de eficacia. Evitar presentar una interfaz vacía como demostración de extensibilidad operacional. |
| §1.5, pp.20–27; Tablas 1.7–1.9 y Figura 1.2 | Viabilidad y planificación. | Actualizar infraestructura real, dependencias de exportadores y capacidades RIC/router. Incorporar hitos de control móvil y peering y esfuerzo de repetición experimental. |

**Objetivo general propuesto:**

> Diseñar, implementar y evaluar un orquestador centralizado que integre telemetría e información de flujos de los dominios móvil O-RAN, fijo con BNGBlaster, enterprise OpenFlow y peering BGP, para detectar y correlacionar ataques DoS/DDoS TCP SYN, UDP e ICMP floods, incluidos escenarios multidominio, y coordinar acciones de mitigación específicas por dominio cuya aplicación y eficacia sean verificadas experimentalmente.

**Objetivos específicos propuestos:**

1. Caracterizar fuentes de observación, identidades y capacidades efectivas de control de los cuatro dominios.
2. Diseñar e implementar contratos normalizados y correlación temporal y de identidad, con calidad y deduplicación de observaciones.
3. Implementar y evaluar detección por vector, distribución de fuentes y dominio de origen, incluyendo ataques simultáneos.
4. Implementar traducción y ejecución de mitigaciones por dominio, con confirmación, expiración, retirada y tratamiento de fallos parciales.
5. Evaluar detección, eficacia, impacto sobre tráfico legítimo y recuperación mediante una campaña reproducible y comparativa.

### Capítulo II: marco teórico

Conservar los antecedentes (pp.28–46), actualizando su síntesis de brechas para conectar con las contribuciones anteriores. Ampliar §2.3.4–2.3.6 (pp.51–55) y definiciones §2.4 (pp.56–64):

- Diferenciar flujos IP del plano de usuario, métricas KPM de radio y eventos de sesión. No afirmar que KPM identifica por sí solo TCP SYN/UDP/ICMP.
- Explicar relaciones temporales IP–sesión PDU–SUPI y UEID RAN tipado; no equiparar IDs NGAP/F1AP por igualdad numérica ni gNB con celda.
- Tratar los formatos KPM como capacidades a comprobar del stack. La clasificación por IP no depende de que Format 5 esté operativo.
- Distinguir controlador RIC, xApp, modelo de servicio RC y actuador RAN. Describir capacidades generales separadamente de las comprobadas en el build.
- Diferenciar observación NetFlow/IPFIX de contexto de rutas BGP/BMP; distinguir distribución de FlowSpec e instalación efectiva por el router.
- Precisar BNGBlaster como instrumento de laboratorio y alcance del corte de sesión respecto de filtrado selectivo en un BNG.
- Añadir tiempo de evento, ventanas, retraso admisible, deduplicación, calidad de identidad y estados de control.

Revisar §2.4.1, p.57: la distribución geográfica no debe ser requisito operacional para identificar DDoS en el laboratorio. Separar cantidad de fuentes observadas de cantidad de atacantes físicos demostrados.

Para nuevas afirmaciones técnicas, incorporar fuentes primarias y versiones efectivamente utilizadas. Este informe es una revisión de coherencia documental, no una auditoría completa de la bibliografía.

### Capítulo III: hipótesis y variables

Rehacer §§3.1–3.2 (pp.65–75), Tablas 3.1–3.8. Mantener las dimensiones conceptuales de §3.3 (pp.75–78), añadiendo calidad de observación y verificación de control.

**Hipótesis general propuesta, si se conserva la comparación:**

> Bajo condiciones experimentales equivalentes, la coordinación centralizada entre dominios reduce el tiempo hasta la mitigación efectiva y la degradación del servicio frente a mecanismos de detección y respuesta independientes por dominio, en los escenarios multidominio definidos.

Definir antes de experimentar el tamaño de mejora relevante, criterio estadístico y condiciones en que se espera observarla. No exigir superioridad en cada caso monodominio como consecuencia automática del diseño.

| Hipótesis operacional propuesta | Evidencia requerida |
|---|---|
| H1: la normalización conserva magnitudes e identidades disponibles sin duplicar tráfico | Comparación con contadores/capturas de referencia, pruebas de reentrega y doble observador. |
| H2: la correlación identifica contribuciones coincidentes de dominios de origen distintos | Verdad de referencia temporal, casos de tránsito y reasignación de IP. |
| H3: el detector discrimina los tres vectores y su distribución con los criterios de calidad prefijados | Matriz de confusión, negativos benignos y tasas por clase. |
| H4: el orquestador aplica y retira controles soportados sobre el selector correcto | Respuestas del backend, lectura de estado y medición; fallos nunca etiquetados como éxito. |
| H5: la coordinación mejora las métricas de servicio y respuesta frente al control independiente | Ensayos pareados/repetidos, dispersión, tamaño del efecto y comparación definida. |

Estas hipótesis son una propuesta para sustituir la correspondencia inconsistente actual; deben alinearse con los problemas específicos y objetivos finales.

Actualizar Tabla 3.8 como matriz de **requerido / implementado / validado / evidencia**. Peering y actuación vía RIC son requisitos pendientes, no trabajo futuro opcional si se mantiene el alcance de cuatro dominios. La retirada del simulador no prueba por sí misma integración móvil completa.

### Capítulo IV: arquitectura y metodología — revisión principal

**§4.1.1–4.1.2, pp.80–85; Figura 4.1, p.82; Tablas 4.1–4.2.** Sustituir la estrella con hosts `gnb_i` como representación de la solución final por una topología con límites de VM, interfaces y puntos de medición reales. Mantener Mininet/OVS solo donde se utilice. Mostrar estos caminos objetivo:

| Dominio | Información hacia el orquestador | Orden y comprobación |
|---|---|---|
| Móvil | Flujos antes de NAT en UPF + sesiones Open5GS + asociaciones CU-CP/RAN + KPM desde Gateway/RIC | Bridge/xApp → Near-RT RIC → acción RC soportada → RAN; respuesta y efecto por UE. |
| Fijo | Flujos medidos + estadísticas y asociación IP/sesión/VLAN de BNGBlaster | Control de sesión experimental; estado posterior y tráfico. Precisar cualquier participación adicional de DHCP/nftables. |
| Enterprise | Estadísticas OpenFlow y evidencia de flags, con ubicación host/puerto | Ryu → switch: regla/meter soportado; lectura y contadores. |
| Peering | Flujos de entrada al borde + interfaz y contexto de rutas | Router: FlowSpec con instalación real o mecanismo de gestión declarado; retirada y contadores. |

Los caminos son requisitos del diseño; su presencia en el diagrama no acredita despliegue.

**§4.4.1, pp.89–93; Tabla 4.6, Figura 4.3 y Tablas 4.7–4.8.** Ampliar con subsecciones:

1. Contratos versionados para flujo, identidad, KPM, detección y acción; unidades y datos ausentes.
2. Correlación por red/VRF, destino, servicio y tiempo; fuentes de origen y puntos autoritativos de medición.
3. Asociación móvil temporal: IP → sesión → identidad RAN; uso contextual de KPM agregado y enriquecimiento por UE solo con evidencia.
4. Detección: vector independiente de distribución; contadores SYN reales; baseline, persistencia y confianza.
5. Política basada en capacidades y granularidad: flujo, UE, sesión o prefijo; daño colateral.
6. Ejecución asíncrona, idempotencia, persistencia y estados propuesto/aceptado/aplicado/verificado/fallido/desconocido.
7. TTL, reconciliación tras reinicio y retirada comprobada; fallo parcial de un plan multidominio.

Reemplazar la idea de que sumar eventos de un ciclo equivale a correlación temporal robusta. Los valores de ventanas del diseño son propuestas de arranque, pendientes de calibración. No equiparar ausencia de telemetría con recuperación ni un ACK con eficacia.

**§4.3–4.4.3, pp.86–97; Tabla 4.5, p.88; Figuras 4.2, 4.4, 4.5.** Conservar los 14 casos como catálogo histórico y crear una matriz nueva:

- 24 combinaciones básicas: cuatro dominios × tres vectores × DoS/DDoS.
- 18 combinaciones por parejas: seis parejas de dominios × tres vectores.
- Tres escenarios con los cuatro dominios y un escenario mixto adicional.
- Baselines benignos y pruebas de fallo/ambigüedad/retirada adicionales.

Son 46 configuraciones positivas propuestas antes de repeticiones y casos negativos; no representan todas las combinaciones posibles. Las ternas pueden añadirse si se exige cobertura exhaustiva. Preparar suficientes fuentes para evaluar DDoS enterprise; cuatro fuentes frente a un umbral de cinco caracteriza el umbral anterior, pero no valida esa capacidad.

**Comparación necesaria:** ejecutar el mismo escenario con (A) observación sin mitigación, (B) detección/respuesta local independiente y (C) coordinación central. Mantener tráfico, recursos y capacidades de actuación comparables. Separar calibración y evaluación; el escenario conocido por el generador no debe entrar al detector como etiqueta de ataque.

**§4.5–4.6, pp.99–105; Tablas 4.11–4.16.** Incorporar `run_id`, versiones y configuración, tiempos sincronizados, registros de entrada, decisiones, órdenes, respuestas y mediciones del punto protegido. Medir:

| Magnitud | Definición operacional propuesta |
|---|---|
| Tiempo de detección | Marca de detección menos inicio conocido del ataque. |
| Tiempo de despacho | Envío de orden menos decisión. |
| Tiempo de aplicación | Instalación comprobada menos envío; indicar incertidumbre de sondeo. |
| Tiempo hasta efecto | Primera reducción que cumple criterio persistente menos inicio del ataque. |
| Eficacia | Reducción de tráfico malicioso en el punto protegido frente a referencia comparable. |
| Daño colateral | Pérdida, latencia y rendimiento benignos antes/durante/después de actuar. |
| Recuperación | Retirada comprobada y restauración del servicio conforme al criterio definido. |
| Calidad de detección | Precisión, recall, F1 y falsos positivos por vector/distribución con unidad de evaluación explícita. |

Predefinir cómo emparejar detecciones con incidentes y cómo contabilizar alertas repetidas. No contar ventanas solapadas como ensayos independientes. La disponibilidad requiere sondas de servicio y denominador temporal definido, no solo disponibilidad del exportador Prometheus.

Reportar repeticiones, dispersión e incertidumbre. Diez repeticiones, las ventanas y los umbrales de eficacia del diseño son propuestas para el piloto; no resultados ni justificación estadística definitiva. Conservar fallos y datos incompletos con indicadores de calidad en vez de excluirlos sin registrar su causa (Tabla 4.14).

**§4.7, pp.105–108:** actualizar límites de aislamiento al testbed conectado y documentar tratamiento de IP/SUPI/identidades. Mantener integridad y reproducibilidad.

### Capítulo V: desarrollo y resultados

| Porción | Tratamiento propuesto |
|---|---|
| §5.1, pp.109–111 | Separar desarrollo del prototipo y migración. Registrar commit/configuración de cada campaña; la rama por sí sola es mutable. |
| Tabla 5.1, p.110 | Conservar parámetros como históricos. Crear tabla independiente con parámetros calibrados de la nueva campaña. |
| Tabla 5.2, p.112 | Corregir denominación RC; añadir versión, tipo de entorno, despacho, instalación, efecto y liberación. Si falta evidencia, marcar no comprobado. |
| §5.2.2, p.113 | Sustituir deducciones de latencia por mediciones; distinguir indisponibilidad observada de ausencia de medición. |
| §5.2.3, pp.113–115 | Mantener hallazgos históricos de umbral/entropía. Validar ahora ventanas, doble observación, nuevas identidades y distribución por origen. |
| §5.2.4, p.115 | Separar paneles disponibles, fuentes frescas y capacidad de mitigación verificada. |
| §5.2.5–5.3, pp.115–119 | Contrastar las hipótesis finales con evidencia correspondiente. No trasladar el «sustentada» histórico a la nueva implementación. |

**Texto de transición sugerido:**

> La campaña preliminar corresponde al prototipo previo a la integración del testbed móvil. Sus resultados se conservan como evidencia de las funciones evaluadas en esa versión. La actuación sobre el generador móvil no constituye una validación de control E2SM-RC sobre la RAN. La arquitectura revisada exige comprobar por separado la adquisición real, la atribución temporal de identidades y la aplicación y eficacia de las acciones en los cuatro dominios.

### Conclusiones, recomendaciones y anexos

**Conclusiones, pp.120–122:** reescribir tras la campaña nueva. Limitar las afirmaciones de cobertura, ausencia de errores, resiliencia y mejoras a los ensayos medidos. Una clase `DomainAdapter` demuestra una abstracción de software; no demuestra interoperabilidad ni desempeño con un router real.

**Recomendaciones, pp.123–125:** trasladar integración peering y control móvil RC desde «futuro» a implementación requerida. Conservar como extensiones futuras ataques de aplicación, despliegue productivo y mayor escala. Un RIC desplegado no implica una acción de mitigación operativa.

**Anexos, p.131:** incorporar catálogo histórico, nueva matriz, inventario de versiones, contratos, diagramas, runbooks, muestras de evidencia anonimizadas y resultados por repetición. Documentar fallos de integración como hallazgos técnicos con evidencia: no convertir hipótesis sobre decodificación KPM en causas definitivas.

## 4. Figuras y tablas que conviene sustituir o añadir

Prioridad de sustitución: Figura 4.1 (topología), Figura 4.3 (adquisición/normalización), Figura 4.4 (cuatro dominios y origen), Figura 4.5 (experimento con comprobación). Actualizar Figuras 3.1–3.3 si cambian variables e hipótesis.

Añadir:

- Diagrama de secuencia observación → incidente → orden → respuesta → efecto → retirada.
- Diagrama de identidad móvil IP/sesión/SUPI/UEID/celda con validez temporal.
- Máquina de estados de mitigación y ejemplo de éxito parcial multidominio.
- Tabla por dominio: fuente, granularidad, frecuencia, capacidad y evidencia de validación.
- Tabla por ejecución: `run_id`, verdad de referencia, clasificación, tiempos, efecto, impacto benigno y retirada.

## 5. Orden recomendado de edición

1. Corregir contradicciones de RC, hipótesis y tiempo de mitigación.
2. Fijar alcance, objetivo y matriz de trazabilidad única.
3. Reescribir capítulo IV usando el diseño objetivo y distinguiendo capacidades pendientes.
4. Etiquetar capítulo V actual como campaña preliminar; preservar evidencia histórica.
5. Ejecutar la nueva campaña y completar resultados, contraste, conclusiones y resumen.

El documento puede actualizarse ya en su diseño y metodología. Los apartados de resultados definitivos requieren nueva evidencia experimental, especialmente control vía RIC, peering y comparación con respuestas independientes.
