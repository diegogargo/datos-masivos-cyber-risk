# Registro de decisiones

## Usar NVD CVE API 2.0 y el feed JSON oficial de CISA KEV

### Razón

Son fuentes oficiales, estructuradas y automatizables.

### Alternativas consideradas

Repositorios secundarios, archivos preparados por terceros y extracción manual.

### Consecuencias

El pipeline debe manejar paginación, límites de tasa, cambios de esquema y la naturaleza dinámica de ambas fuentes.

## Definir `in_kev` como presencia observada

### Razón

La ausencia en KEV no demuestra ausencia histórica o futura de explotación.

### Consecuencias

Los textos, tablas y gráficas usarán expresiones como "presente en KEV" y nunca "no explotada" para `in_kev = 0`.

## Mantener CSV durante el primer parcial

### Razón

Facilita inspección y evaluación de la muestra inicial.

### Alternativas consideradas

Parquet y una base analítica local.

### Consecuencias

Al crecer el periodo completo se evaluará migrar las capas intermedia y procesada a Parquet particionado.

