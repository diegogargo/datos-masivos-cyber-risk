# Validación inicial

Las validaciones ejecutadas por el pipeline incluyen:

- presencia de las columnas requeridas;
- formato de `cve_id`;
- unicidad de `cve_id` en el dataset analítico;
- conversión de fechas;
- valores permitidos de `in_kev`;
- cálculo no negativo de `days_to_kev`;
- consistencia de conteos antes y después de la integración;
- registro de filas, duplicados y valores faltantes en un resumen generado.

Los resultados concretos se actualizan en `data/sample/build_summary.json` al ejecutar:

```bash
python -m src.processing.build_sample_dataset
```

En la extraccion inicial se obtuvieron 12,412 filas unicas y 58 coincidencias con KEV. En 16 de esas coincidencias `date_added` era anterior a `published`; por ello `days_to_kev` se dejo vacio y solo se conservo para 42 casos con diferencia no negativa. Esto evita presentar una duracion que no representa el intervalo definido.

Las pruebas automatizadas más amplias y comparaciones de desempeño se desarrollarán en el segundo parcial, conforme al documento semestral.
