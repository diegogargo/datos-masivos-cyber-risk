# Revisión del análisis exploratorio inicial

## Conjunto analizado

La muestra inicial corresponde a las CVE publicadas por NVD entre el 1 de enero y el 31 de marzo de 2025. El dataset procesado contiene 12,412 filas únicas y no presenta identificadores `cve_id` duplicados.

## Valores faltantes

Los campos asociados con CWE presentan aproximadamente 8.08% de valores faltantes. Los principales campos CVSS tienen aproximadamente 3.75% de valores faltantes. Los campos provenientes de CISA KEV tienen un porcentaje elevado de faltantes porque solamente se completan para las CVE presentes en ese catálogo.

## Presencia en CISA KEV

Se identificaron 58 CVE presentes en el catálogo KEV descargado, equivalentes aproximadamente al 0.47% de las CVE del periodo. La ausencia de una CVE en esta versión de KEV no constituye evidencia de que nunca haya sido explotada.

## Interpretación

Los resultados son descriptivos. Las diferencias observadas entre categorías de severidad o vector de ataque no prueban causalidad y deben interpretarse considerando las limitaciones y los cambios temporales de ambas fuentes.
