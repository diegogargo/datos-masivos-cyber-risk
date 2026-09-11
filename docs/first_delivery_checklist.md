# Checklist de la primera entrega

Estado verificado el 2026-09-10.

La simulacion de clonacion sin `raw`, `interim` ni `processed` ejecuto correctamente las tres pruebas y ambos notebooks usando `data/sample/`.

| Requisito | Estado | Evidencia |
|---|---|---|
| Problema, relevancia y pregunta concreta | COMPLETO | `README.md` y `docs/project_scope.md` |
| Usuarios, decisiones y valor esperado | COMPLETO | `docs/project_scope.md` |
| Dos fuentes oficiales documentadas | COMPLETO | `docs/sources.md` |
| Origen, variables, periodo, formato, volumen y limitaciones | COMPLETO | `docs/sources.md` |
| Adquisicion automatizada por codigo | COMPLETO | Modulos de `src/ingestion/` ejecutados |
| Muestra pequena disponible | COMPLETO | `data/sample/` |
| Datos grandes excluidos de Git | COMPLETO | `.gitignore` verificado |
| Filas, dimensiones y tipos | COMPLETO | `notebooks/01_exploration.ipynb` ejecutado |
| Nulos, porcentajes y duplicados | COMPLETO | Notebook y `build_summary.json` |
| Estadisticas y distribuciones | COMPLETO | Notebook ejecutado |
| Problemas de calidad y preguntas abiertas | COMPLETO | Notebook ejecutado |
| Diccionario con faltantes reales | COMPLETO | `docs/data_dictionary.md` |
| Arquitectura inicial y escalabilidad | COMPLETO | `docs/architecture.md` |
| Primera evidencia con tabla, grafica e interpretacion | COMPLETO | Segundo notebook y `reports/` |
| Rutas relativas y dependencias declaradas | COMPLETO | Revision automatizada y archivos de entorno |
| Pruebas automatizadas | COMPLETO | 3 pruebas aprobadas |
| Repositorio local en rama `main` | PARCIAL | Git inicializado; commits bloqueados por permisos de esta sesion |
| Repositorio remoto privado | PENDIENTE | GitHub solicita inicio de sesion |
| Issues 1 a 8 | PENDIENTE | Plan preparado en `docs/collaboration_plan.md` |
| Dos commits por integrante | PENDIENTE | Deben ser contribuciones reales |
| Un pull request por integrante | PENDIENTE | Debe crearlo cada integrante |
| Una revision ajena por integrante | PENDIENTE | Debe realizarla cada integrante |
| Participacion en un issue por integrante | PENDIENTE | Debe realizarla cada integrante |

## Nota de alcance

El pipeline, validaciones y pruebas adelantan trabajo de etapas posteriores, pero no se presentan como sustituto de la colaboracion exigida en el primer parcial.
