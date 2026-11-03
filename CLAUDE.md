# Objetivo de la aplicación

Aplicación para mantenerse al tanto de nuevas vulnerabilidades de seguridad
con el mayor nivel de detalle posible. Permite:
- Ver vulnerabilidades filtrando por fecha, tecnología (ej. Java, Node),
  criticidad (CVSS), si está explotada activamente (KEV), probabilidad de
  explotación (EPSS) y otros criterios.
- Buscar por CVE específica o por texto libre.

Alcance v1: [definir]. Fuera de alcance por ahora: [ej. alertas, usuarios, login].

# Stack tecnológico

* Backend: Python con uv (gestión de dependencias y entorno), API con FastAPI.
* Base de datos: [SQLite en v1 / Postgres]
* Frontend: web que consume la API. React + Vite + TypeScript
* Calidad: ruff (lint y format), pytest (tests), mypy o pyright (tipos).

# Comandos

* Instalar: `uv sync`
* Correr API: [comando]
* Tests: `uv run pytest`
* Lint y formato: `uv run ruff check . && uv run ruff format .`

# Fuentes de información

* NVD (NIST): detalle oficial de CVE (descripción, CVSS, CPE, referencias).
* CISA KEV: vulnerabilidades explotadas activamente.
* EPSS (FIRST): probabilidad de explotación.
* OSV.dev y GitHub Security Advisories: vulnerabilidades en paquetes y dependencias.

Reglas sobre las fuentes:
* Normalizar todo a un modelo de datos propio; el resto de la app no
  depende del formato de cada fuente.
* Respetar rate limits, usar cache y reintentos con backoff.
* Los datos externos son entrada no confiable: validar y sanitizar siempre
  (también al mostrarlos en el front, por riesgo de XSS).
* Nunca inventar ni completar datos técnicos de una CVE; si falta un dato, se muestra como no disponible.

# Reglas del código

* Todo el código y la documentación en inglés (excepto este CLAUDE.md).
* Todo código nuevo lleva unit tests. Los tests no hacen llamadas reales a
  APIs externas (usar mocks o fixtures).
* Antes de dar una tarea por terminada deben pasar lint, formato, tipos y tests.
* Type hints en todo el código Python.

# Seguridad

* Secretos y API keys solo en variables de entorno; `.env` fuera de git
  y un `.env.example` sin valores reales.
* Nunca imprimir secretos en logs ni escribirlos en el código.
* No agregar dependencias nuevas sin explicar por qué.

# Forma de trabajar

* Para cambios grandes: primero proponer un plan y esperar aprobación.
* Cambios pequeños y enfocados; un commit por cambio lógico.
* Si algo no está claro, preguntar antes de asumir.

# Documentación

* Toda documentación en inglés. Se actualiza en el mismo cambio que modifica
  el comportamiento: una tarea no está terminada sin su documentación.
* Funcional (`docs/functional/`) y técnica (`docs/technical/`, `README.md`).
* Al terminar, indicar qué documentación se actualizó o por qué no hizo falta.
* Guía detallada de qué y cómo documentar: @docs/documentation-guidelines.md