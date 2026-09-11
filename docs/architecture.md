# Arquitectura inicial

## Flujo propuesto

```text
NVD CVE API 2.0 -------------------+
                                   |
CISA KEV JSON oficial -------------+--> adquisición con requests
                                           |
                                           v
                                     data/raw/ (JSON)
                                           |
                                           v
                               normalización y selección CVSS
                                           |
                                           v
                                   data/interim/ (CSV)
                                           |
                                           v
                          integración por cve_id + validaciones
                                           |
                                           v
                                  data/processed/ (CSV)
                                           |
                                           v
                              notebooks y análisis descriptivo
                                           |
                                           v
                              reports/figures y reports/tables
```

## Almacenamiento

- `data/raw/`: respuestas sin transformar y metadatos de extracción. Se regeneran y no se versionan por tamaño.
- `data/interim/`: tablas normalizadas por fuente. Se regeneran y no se versionan.
- `data/processed/`: integración analítica completa. Se regenera y no se versiona.
- `data/sample/`: muestras pequeñas reales para revisión, pruebas y ejecución sin descargar el conjunto completo.
- `reports/`: tablas y figuras reproducibles obtenidas por código.

## Adquisición

Los módulos de `src/ingestion/` usan `requests`, tiempos de espera, reintentos, manejo de límites de tasa, validación de JSON y paginación de NVD. La API key de NVD es opcional y se lee únicamente desde `NVD_API_KEY`.

## Transformaciones

1. Validación básica de la respuesta y trazabilidad de extracción.
2. Aplanamiento de registros NVD y selección documentada de una métrica CVSS.
3. Normalización de nombres KEV y conversión de fechas.
4. Revisión del formato de `cve_id` y deduplicación controlada.
5. Integración izquierda desde NVD hacia KEV mediante `cve_id`.
6. Creación de `in_kev` y de `days_to_kev` solo cuando la diferencia temporal es válida y no negativa.

## Herramientas

Python, requests, pandas, matplotlib, Jupyter, nbconvert, pytest y Git.

## Criterio de selección CVSS

Una CVE puede contener varias métricas. El pipeline utiliza el siguiente orden de versión: CVSS 4.0, 3.1, 3.0 y 2.0. Dentro de una misma versión prioriza una métrica marcada como `Primary`, después una producida por `nvd@nist.gov` y finalmente la primera disponible. Se conservan `cvss_version` y `cvss_source` para auditar la elección. Los análisis deberán considerar que las versiones no son directamente equivalentes en todos sus componentes.

## Crecimiento de volumen

El prototipo combina respuestas paginadas en memoria y genera CSV. Al ampliar el periodo, los JSON y DataFrames consumirán más memoria, las descargas serán más sensibles a límites de tasa y los CSV serán lentos para lectura selectiva.

Una evolución razonable es descargar por intervalos y lotes, escribir JSON por página, normalizar incrementalmente y migrar `interim` y `processed` a Parquet particionado por año o fecha de publicación. En una escala mayor podrían evaluarse Polars, DuckDB o procesamiento distribuido. Estas mejoras corresponden a etapas posteriores del proyecto.

