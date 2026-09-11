# De la severidad a la explotacion

**Titulo corto:** Cybersecurity Vulnerability Risk Analysis

Proyecto universitario de Datos Masivos para estudiar caracteristicas tecnicas y temporales asociadas con la presencia de vulnerabilidades NVD en el catalogo CISA KEV.

## Integrantes

- Diego Garcia Gomez
- Maria José Barreda
- Emiliano Martínez 
- Sofia Villegas

Los nombres temporales se reemplazaran cuando se integre formalmente el equipo.

## Problema

La cantidad de vulnerabilidades publicadas supera la capacidad de revision inmediata de muchos equipos. El proyecto integra severidad y caracteristicas de NVD con presencia observada en CISA KEV para producir evidencia descriptiva que complemente la priorizacion.

## Pregunta principal

¿Que caracteristicas tecnicas y temporales de las vulnerabilidades registradas en NVD entre 2021 y 2025 estan asociadas con su inclusion en CISA KEV, y que patrones pueden aportar informacion para su priorizacion de riesgo?

## Objetivo

Construir un sistema reproducible de adquisicion, integracion, validacion y analisis. La primera ejecucion usa el periodo 2025-01-01 a 2025-03-31; el alcance final sera 2021-01-01 a 2025-12-31.

## Fuentes de datos

- NVD CVE API 2.0 de NIST: fechas, estado, metricas CVSS y debilidades CWE.
- Catalogo CISA KEV: vulnerabilidades con evidencia de explotacion conocida y acciones asociadas.

Los detalles se encuentran en `docs/sources.md`.

## Unidad de analisis

Cada fila representa una CVE unica publicada por NVD en el periodo. `in_kev = 1` indica presencia en el feed KEV descargado. `in_kev = 0` solo indica que no se encontro en esa version del catalogo; no significa que la vulnerabilidad no haya sido explotada.

## Estructura

- `data/`: capas raw, interim, processed y sample.
- `docs/`: alcance, fuentes, diccionario, arquitectura y validacion.
- `notebooks/`: exploracion inicial y primera evidencia.
- `src/`: adquisicion, procesamiento, validacion y analisis.
- `reports/`: figuras y tablas generadas.
- `tests/`: pruebas automaticas.

## Requisitos e instalacion

Se requiere Python 3.10 o superior y acceso a internet para descargar los datos.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

La API key de NVD es opcional. Si se utiliza, se define en `NVD_API_KEY` y nunca se guarda en el repositorio.

## Obtencion y procesamiento

Ejecutar desde la raiz:

```bash
python -m src.ingestion.nvd_ingestion
python -m src.ingestion.kev_ingestion
python -m src.processing.build_sample_dataset
```

Los scripts conservan datos crudos en `data/raw/`, generan tablas en `data/interim/` y producen el dataset integrado en `data/processed/`. Los archivos grandes no se versionan. Para reemplazar una descarga existente se usa `--force`.

## Notebooks

```bash
jupyter nbconvert --to notebook --execute notebooks/01_exploration.ipynb --output 01_exploration.ipynb --output-dir notebooks --ExecutePreprocessor.timeout=600
jupyter nbconvert --to notebook --execute notebooks/02_first_evidence.ipynb --output 02_first_evidence.ipynb --output-dir notebooks --ExecutePreprocessor.timeout=600
```

Los notebooks usan el dataset completo si existe y, en una clonacion sin datos grandes, recurren a la muestra incluida en `data/sample/`.

## Primera evidencia

La pregunta inicial es: **¿Como varia la proporcion de CVE incluidas en CISA KEV segun su vector de ataque?** La tabla se guarda en `reports/tables/` y la grafica en `reports/figures/`. Es una comparacion descriptiva y no demuestra causalidad.

## Limitaciones

- KEV es dinamico y no representa toda explotacion existente.
- NVD puede modificar registros despues de la extraccion.
- Las versiones CVSS tienen diferencias metodologicas.
- La ventana inicial no sustituye el analisis final 2021-2025.

## Estado actual

Primera entrega: estructura, adquisicion, muestra real, integracion, EDA, diccionario, arquitectura y primera evidencia reproducible.
