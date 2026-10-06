# Analítica experimental para la tesis

El dashboard integra el historial del servidor y archivos ZIP exportados. Las importaciones son solo datos: no crean procesos ni ejecutan instrucciones de los archivos. Un identificador ya existente con iguales eventos/plan no se cuenta dos veces; contenidos conflictivos se rechazan. Los ZIP requieren archivos planos, estado terminal e integridad del plan, con límites de tamaño.

## Unidad y elegibilidad

La repetición es una ejecución real completa. Se excluyen de las medias las simulaciones, diagnósticos, pruebas abortadas o sin inicio, observaciones parciales, planes sin integridad y evidencia incompleta de eventos. completed_with_errors permanece como resultado completo: sus errores son parte del resultado, no motivo para borrar una medición desfavorable.

El dashboard distingue grupos por perfil, capacidad, duración, warmup, ejecución, topología, instrumentación, contexto físico registrado, hardware observado y política del detector. Las IP dinámicas de abonados y session_id no se usan para separar condiciones; las identidades lógicas y sus hosts/interfaces sí. La falta de metadatos históricos se advierte y no se presenta como paridad verificada.

## Métricas

Entrega = 100 × bytes de aplicación reportados / cuota del plan. Payload medio = bytes reportados ×8 / duración nominal. No son pérdida de paquetes físicos ni capacidad máxima del enlace. Errores y retraso p95 se calculan por evento; no se usan esos eventos como repeticiones para los IC.

FPR utiliza la evaluación estructurada y sus ventanas benignas elegibles. Sin evidencia la tasa permanece vacía, no cero. La vista global combina dominio × ventana; la vista por dominio conserva su denominador. Las restricciones reportadas y los cambios de IP se consultan en el detalle.

CPU se resume por nodo y origen, ponderada por solapamiento temporal de las muestras con la ejecución; Ready es la espera normalizada por vCPU que registró ESXi. No se suman CPUs/Ready de nodos distintos. Las series de payload se derivan de diferencias de contadores y se comparan con la carga nominal del plan. El muestreo limita su resolución.

## Repeticiones, semillas y confianza

Se reportan número de ejecuciones y semillas distintas, distribución de repeticiones por semilla, media ponderada por ejecución y media principal equilibrada por semilla. Primero se promedia dentro de cada semilla; después cada semilla tiene igual peso. Esto evita que una semilla con muchas repeticiones domine el estimador.

SD e IC 95 % se calculan sobre las medias de semillas. IC = media ± t(0,975, n−1) × SD/√n, con n semillas independientes. Se usa la tabla NIST hasta df=30; para mayores df ese valor se conserva como límite conservador. Una semilla no permite estimar el intervalo. Si no hay variación observada se reporta SD=0 e IC no estimable: no se afirma certeza perfecta. Los IC no se recortan a los límites físicos del porcentaje.

El modelo requiere independencia, condiciones comparables y normalidad aproximada de las medias; no se ejecuta una validación automática de normalidad ni se afirma causalidad. Con pocas semillas los intervalos pueden ser muy amplios. El número adicional de semillas para una precisión deseada es una orientación piloto basada en (1,96 × SD / semiancho)², no un análisis de potencia definitivo ni garantía de precisión.

Las diferencias pareadas se construyen con el mismo plan materializado, semilla y ejecución. Dentro de cada condición se promedian las repeticiones del plan y después se calcula comparación − referencia. La estadística de diferencias vuelve a agruparse por semilla. Las diferencias descriptivas con contexto desconocido se etiquetan; no se cuentan todas las combinaciones de eventos o pares como muestras independientes.

## Procedencia y operación

Las ejecuciones nuevas capturan transporte público de Workstation, Python del control, almacenamiento de probes y hashes de las copias de código de tráfico del control. Esos hashes describen las copias esperadas; no constituyen atestación independiente del código instalado en cada worker. Los hashes del detector instalado y sus umbrales se toman de la evidencia de auditoría.

El historial básico utiliza caché. El análisis detallado y las importaciones se pausan mientras haya experimentos activos para reducir interferencia con adquisición. La analítica no cambia planes, umbrales ni servicios de VMs. Sus exportaciones incluyen CSV por ejecución, CSV de cohortes, reporte JSON y este método.

Fuentes del método: [NIST, intervalo para la media](https://www.itl.nist.gov/div898/handbook/eda/section3/eda352.htm), [tabla t](https://www.itl.nist.gov/div898/handbook/eda/section3/eda3672.htm), [diferencias pareadas](https://www.itl.nist.gov/div898/handbook/prc/section3/prc312.htm).
