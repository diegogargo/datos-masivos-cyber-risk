# Diccionario de datos

Porcentajes calculados sobre las 12,412 filas reales del dataset procesado 2025-01-01 a 2025-03-31. La columna de faltantes se regenera y verifica mediante `data/sample/build_summary.json`.

| Variable | Tipo | Fuente | Descripcion | Unidad | Faltantes | Observaciones |
|---|---|---|---|---|---:|---|
| `cve_id` | string | NVD | Identificador de vulnerabilidad | - | 0.00% | Llave unica de integracion |
| `published` | datetime | NVD | Fecha y hora de publicacion | UTC | 0.00% | Convertida a fecha |
| `last_modified` | datetime | NVD | Ultima modificacion registrada | UTC | 0.00% | Puede cambiar despues |
| `vuln_status` | string | NVD | Estado del registro | - | 0.00% | Categoria NVD |
| `cwe_id` | string | NVD | Primera debilidad CWE priorizada | - | 8.08% | Puede faltar o ser generica |
| `nvd_extracted_at_utc` | datetime | Pipeline | Momento de extraccion NVD | UTC | 0.00% | Trazabilidad |
| `cvss_version` | string | NVD | Version CVSS elegida | - | 3.75% | Criterio en arquitectura |
| `cvss_source` | string | NVD | Fuente de la metrica elegida | - | 3.75% | Audita la seleccion |
| `base_score` | float | NVD | Puntuacion base CVSS | puntos | 3.75% | Comparar versiones con cautela |
| `severity` | string | NVD | Severidad CVSS | - | 3.75% | Categoria de la metrica |
| `attack_vector` | string | NVD | Vector de ataque | - | 3.75% | Campo CVSS |
| `attack_complexity` | string | NVD | Complejidad del ataque | - | 3.75% | Campo CVSS |
| `privileges_required` | string | NVD | Privilegios requeridos | - | 3.75% | No existe igual en toda version |
| `user_interaction` | string | NVD | Interaccion requerida | - | 3.75% | No existe igual en toda version |
| `confidentiality_impact` | string | NVD | Impacto en confidencialidad | - | 18.58% | Nombre armonizado |
| `integrity_impact` | string | NVD | Impacto en integridad | - | 18.58% | Nombre armonizado |
| `availability_impact` | string | NVD | Impacto en disponibilidad | - | 18.58% | Nombre armonizado |
| `vendor_project` | string | CISA KEV | Proveedor o proyecto afectado | - | 99.53% | Solo para CVE en KEV |
| `product` | string | CISA KEV | Producto afectado | - | 99.53% | Solo para CVE en KEV |
| `vulnerability_name` | string | CISA KEV | Nombre de la vulnerabilidad | - | 99.53% | Solo para CVE en KEV |
| `date_added` | datetime | CISA KEV | Fecha de incorporacion al catalogo | UTC | 99.53% | Catalogo dinamico |
| `short_description` | string | CISA KEV | Descripcion breve | - | 99.53% | Solo para CVE en KEV |
| `required_action` | string | CISA KEV | Accion requerida por CISA | - | 99.53% | Contexto federal |
| `due_date` | datetime | CISA KEV | Fecha limite de remediacion | UTC | 99.53% | Contexto BOD 22-01 |
| `known_ransomware_campaign_use` | string | CISA KEV | Uso conocido en ransomware | - | 99.53% | Declarado por CISA |
| `notes` | string | CISA KEV | Notas y referencias | - | 99.53% | Puede estar vacio |
| `kev_extracted_at_utc` | datetime | Pipeline | Momento de extraccion KEV | UTC | 99.53% | Trazabilidad |
| `in_kev` | integer | Derivada | Presencia en KEV: 1 si, 0 no encontrada | binaria | 0.00% | 0 no significa no explotada |
| `days_to_kev` | float | Derivada | Dias de publicacion a alta en KEV | dias | 99.66% | Solo diferencias validas no negativas |
