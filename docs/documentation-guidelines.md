# Objetivo de la aplicación

Aplicación para mantenerse al tanto de nuevas vulnerabilidades de seguridad
con el mayor nivel de detalle posible. Permite:
- Ver vulnerabilidades filtrando por fecha, tecnología (ej. Java, Node),
  criticidad (CVSS), si está explotada activamente (KEV), probabilidad de
  explotación (EPSS) y otros criterios.
- Buscar por CVE específica o por texto libre.

Alcance v1: [definir]
Fuera de alcance por ahora: [ej. alertas, usuarios, login]

# Stack tecnológico

* Backend: Python con uv (dependencias y entorno), API con FastAPI.
* Base de datos: [SQLite en v1 / Postgres]
* Frontend: React + TypeScript + Vite, en `frontend/`. Consume la API
  mediante un cliente generado desde el esquema OpenAPI de FastAPI
  (no escribir `fetch` a mano). TanStack Query para datos, Tailwind + shadcn/ui
  para componentes.
* Calidad backend: ruff (lint y format), pytest (tests), mypy o pyright (tipos).
* Calidad frontend: ESLint, Prettier, Vitest, TypeScript en modo estricto.

# Comandos

* Instalar backend: `uv sync`
* Correr API: [comando]
* Tests backend: `uv run pytest`
* Lint y formato backend: `uv run ruff check . && uv run ruff format .`
* Instalar frontend: `cd frontend && npm install`
* Correr frontend: `cd frontend && npm run dev`
* Tests frontend: `cd frontend && npm test`

# Fuentes de información

* NVD (NIST): detalle oficial de CVE (descripción, CVSS, CPE, referencias).
* CISA KEV: vulnerabilidades explotadas activamente.
* EPSS (FIRST): probabilidad de explotación.
* OSV.dev y GitHub Security Advisories: vulnerabilidades en paquetes y dependencias.

Reglas sobre las fuentes:
* Normalizar todo a un modelo de datos propio; el resto de la app no
  depende del formato de cada fuente.
* Respetar rate limits, usar cache y reintentos con backoff.
* Los datos externos son entrada no confiable: validar y sanitizar siempre,
  también al mostrarlos en el front (riesgo de XSS).
* Nunca inventar ni completar datos técnicos de una CVE; si falta un dato,
  se muestra como no disponible.

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
* No agregar dependencias nuevas (Python o npm) sin explicar por qué.

# Forma de trabajar

* Para cambios grandes: primero proponer un plan y esperar aprobación.
* Cambios pequeños y enfocados; un commit por cambio lógico.
* Si algo no está claro, preguntar antes de asumir.
* Al trabajar en el frontend, explicar brevemente las decisiones tomadas
  (el usuario tiene experiencia en backend, no en frontend).

# Documentación

* Toda documentación en inglés. Se actualiza en el mismo cambio que modifica
  el comportamiento: una tarea no está terminada sin su documentación.
* Funcional en `docs/functional/`; técnica en `docs/technical/` y `README.md`.
* Al terminar, indicar qué documentación se actualizó o por qué no hizo falta.
* Guía detallada de qué y cómo documentar: @docs/documentation-guidelines.md

# Worklog (memoria de trabajo) y changelog

* El worklog es diario: un archivo por día en `docs/worklog/AAAA-MM-DD.md`.
  Si ya existe el del día, agregar la nueva entrada al final de ese archivo.
* Al terminar cada tarea, agregar una entrada en el worklog del día y,
  si el cambio es visible para el usuario, una línea en `CHANGELOG.md`
  (formato Keep a Changelog: Added, Changed, Fixed, Security).
* Al iniciar una sesión o una tarea grande, leer `docs/worklog/README.md`
  y el archivo de worklog más reciente antes de planificar. No leer todo
  el historial salvo que haga falta.
* Cada entrada incluye: qué se hizo, por qué, módulos principales afectados,
  decisiones tomadas (y alternativas descartadas), y pendientes o riesgos.
* Las entradas son breves (máximo ~10 líneas), en inglés, sin secretos ni datos sensibles.
* Mantener `docs/worklog/README.md` como resumen del estado actual (qué
  funciona, qué está en curso, próximos pasos). Actualizarlo al cerrar cada tarea.

# Decisiones de arquitectura (ADR)

* Toda decisión técnica importante (base de datos, framework, estrategia de
  cache, modelo de datos, cambio de fuente) se registra como ADR en
  `docs/technical/adr/NNNN-titulo-corto.md`, numerado en secuencia.
* Antes de proponer una decisión de arquitectura, revisar los ADR existentes
  para no contradecirlos.
* Los ADR no se reescriben: si una decisión cambia, crear un ADR nuevo que
  reemplaza al anterior y marcar el anterior como "Superseded".
* Formato: @docs/technical/adr/TEMPLATE.md