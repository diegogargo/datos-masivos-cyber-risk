# Fuentes de datos

## National Vulnerability Database (NVD)

- **Origen:** NVD CVE API 2.0: <https://services.nvd.nist.gov/rest/json/cves/2.0>
- **Institucion:** National Institute of Standards and Technology (NIST), Estados Unidos.
- **Documentacion oficial:** <https://nvd.nist.gov/developers/vulnerabilities>
- **Metodo de acceso:** solicitudes HTTPS automatizadas con `requests`, filtros `pubStartDate` y `pubEndDate`, y paginacion mediante `startIndex`.
- **Formato:** JSON, version de respuesta `2.0` en la extraccion inicial.
- **Volumen verificado:** 12,412 registros para 2025-01-01 a 2025-03-31, segun `totalResults` devuelto el 2026-09-10.
- **Frecuencia:** la base cambia conforme NVD publica o revisa registros; el pipeline conserva la hora de extraccion para evitar tratar una descarga como historicamente inmutable.
- **Restricciones de uso:** consultar los avisos y politicas de NVD/NIST; no se redistribuyen masivamente los archivos crudos dentro de Git.
- **Variables utilizadas:** identificador, publicacion, ultima modificacion, estado, metricas CVSS y debilidades CWE.
- **Problemas conocidos:** campos faltantes, varias metricas CVSS por CVE, distintas versiones CVSS, fuentes de metrica diferentes, estados revisables y limites de tasa.

### Seleccion de CVSS

El JSON real puede incluir `cvssMetricV40`, `cvssMetricV31`, `cvssMetricV30` y `cvssMetricV2`. Se elige la version disponible mas reciente en ese orden. Dentro de la version se prioriza una metrica `Primary`, despues una de `nvd@nist.gov` y luego la primera disponible. La version y fuente elegidas se conservan en el dataset.

### Operacion de la API

La API key es opcional y se lee desde `NVD_API_KEY`. Sin key, el script espera entre paginas para respetar el limite publico. Se manejan paginacion, timeout, errores HTTP, `Timeout`, `ConnectionError`, limites 429, reintentos y JSON invalido.

## CISA Known Exploited Vulnerabilities (KEV)

- **Origen:** feed JSON oficial: <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>
- **Institucion:** Cybersecurity and Infrastructure Security Agency (CISA), Estados Unidos.
- **Catalogo y contexto oficial:** <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- **Metodo de acceso:** descarga HTTPS automatizada con `requests`.
- **Formato:** JSON.
- **Volumen verificado:** 1,705 entradas en la version de catalogo `2026.09.10`, extraida el 2026-09-10.
- **Frecuencia:** catalogo dinamico, actualizado cuando CISA agrega o modifica entradas; no se presupone un intervalo fijo.
- **Restricciones de uso:** el portal oficial publica el feed y su licencia; las acciones y fechas limite se interpretan dentro del contexto definido por CISA.
- **Variables utilizadas:** CVE, proveedor/proyecto, producto, nombre, fecha de alta, descripcion breve, accion requerida, fecha limite, uso conocido en ransomware y notas.
- **Problemas conocidos:** el catalogo no representa toda explotacion posible, cambia con el tiempo y contiene campos textuales o notas que requieren limpieza.

## Interpretacion de la integracion

La union usa `cve_id` y parte de las CVE publicadas por NVD en el periodo. `in_kev = 1` indica presencia en el feed KEV descargado. `in_kev = 0` indica solamente que no se encontro en esa version del feed; no significa que la CVE nunca haya sido explotada.
