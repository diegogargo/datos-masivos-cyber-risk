# Alcance del proyecto

## Contexto del problema

Los equipos de seguridad reciben más avisos de vulnerabilidades de los que pueden atender al mismo tiempo. La puntuación CVSS resume severidad técnica, mientras que el catálogo Known Exploited Vulnerabilities (KEV) de CISA identifica vulnerabilidades para las que existe evidencia de explotación en condiciones reales. Integrar ambas fuentes permite estudiar qué características aparecen con mayor frecuencia entre las CVE presentes en KEV y construir evidencia útil para priorizar revisiones.

## Relevancia

Priorizar únicamente por severidad puede omitir vulnerabilidades con explotación conocida o concentrar recursos en casos que no son los más urgentes para una organización. El proyecto busca complementar, no reemplazar, el juicio de especialistas, el contexto de activos ni los requisitos operativos.

## Pregunta principal

¿Qué características técnicas y temporales de las vulnerabilidades registradas en la National Vulnerability Database (NVD) entre 2021 y 2025 están asociadas con su inclusión en el catálogo Known Exploited Vulnerabilities (KEV) de CISA, y qué patrones pueden aportar información para su priorización de riesgo?

## Preguntas secundarias

1. ¿Cómo varía la proporción de CVE presentes en KEV según el vector de ataque?
2. ¿Cómo se distribuyen severidad, puntuación base, complejidad de ataque e interacción del usuario según `in_kev`?
3. ¿Qué familias CWE aparecen con mayor frecuencia en cada grupo?
4. Entre las CVE incluidas en KEV, ¿cuánto tiempo transcurre entre publicación en NVD e incorporación al catálogo cuando ambas fechas permiten calcularlo?
5. ¿Qué limitaciones de cobertura, temporalidad y valores faltantes afectan la interpretación?

## Objetivo general

Construir un sistema reproducible de adquisición, integración, validación y análisis de datos de vulnerabilidades provenientes de NVD y CISA KEV para identificar características técnicas y temporales asociadas con la inclusión en KEV y evaluar su utilidad potencial para priorizar riesgo.

## Objetivos específicos

- Automatizar la descarga desde NVD CVE API 2.0 y el feed JSON oficial de CISA KEV.
- Preservar datos crudos y registrar la fecha y hora de extracción.
- Normalizar las principales métricas CVSS y documentar su criterio de selección.
- Integrar las fuentes por `cve_id` y construir `in_kev` sin interpretarlo como ausencia de explotación.
- Diagnosticar estructura, nulos, duplicados, cobertura temporal e inconsistencias.
- Producir una primera evidencia descriptiva, sin inferencias causales.

## Unidad de análisis

Una vulnerabilidad identificada por una CVE.

## ¿Qué representa una fila?

Cada fila del dataset analítico representa una `cve_id` única publicada por NVD dentro del periodo analizado, enriquecida con los atributos de CISA KEV cuando esa misma CVE estaba presente en el catálogo en la fecha de extracción.

## Alcance

- Fuentes: NVD CVE API 2.0 y catálogo CISA KEV.
- Ventana del proyecto completo: 2021-01-01 a 2025-12-31.
- Ventana inicial para probar el flujo: 2025-01-01 a 2025-03-31.
- Enfoque inicial: análisis descriptivo y asociaciones observadas.

## Periodo y temporalidad

La pertenencia a KEV es una observación del catálogo en el momento de extracción. `in_kev = 0` significa solamente que la CVE no fue encontrada en el feed descargado entonces; no significa que nunca haya sido explotada ni que no pueda añadirse posteriormente.

## Limitaciones

- KEV es dinámico y no constituye un registro exhaustivo de toda explotación existente.
- NVD puede revisar registros, estados y métricas después de su publicación.
- Las versiones CVSS no son idénticas y su disponibilidad varía entre CVE.
- Ausencia de una CVE en KEV no equivale a evidencia de no explotación.
- Las asociaciones descriptivas no prueban causalidad ni sustituyen contexto de activos, exposición o controles.

## Usuarios potenciales

- Equipos de gestión de vulnerabilidades y respuesta a incidentes.
- Responsables de riesgo tecnológico.
- Analistas de seguridad y estudiantes de ingeniería de datos.

## Decisiones que podría apoyar

- Qué grupos de vulnerabilidades revisar primero junto con exposición y criticidad del activo.
- Qué variables necesitan mejor calidad antes de construir modelos posteriores.
- Qué fuentes y frecuencia de actualización conviene mantener en un pipeline operativo.

## Valor esperado

Un proceso auditable que conecte severidad técnica, características CVSS, debilidades CWE y presencia observada en KEV, con resultados reproducibles y limitaciones explícitas.

