Toda documentación se escribe en inglés y se actualiza en el mismo cambio que
modifica el comportamiento. Una tarea no está terminada si su documentación
no está al día.

## Documentación funcional (qué hace el sistema)
- Ubicación: `docs/functional/`
- Audiencia: usuarios y personas sin conocimiento técnico.
- Debe describir cada funcionalidad desde el punto de vista del usuario:
  qué problema resuelve, cómo se usa (filtros, búsquedas) y ejemplos
  concretos de entrada y resultado esperado.
- Mantener un glosario (CVE, CVSS, EPSS, KEV, severidad) y explicar el
  significado de cada campo que se muestra en pantalla.
- Evitar jerga de implementación.

## Documentación técnica (cómo funciona)
- Ubicación: `docs/technical/` y `README.md`
- Audiencia: desarrolladores.
- Debe incluir:
  - Arquitectura y flujo de datos (de la fuente externa a la API y al front).
  - Modelo de datos y cómo se normalizan los datos de cada fuente.
  - Cómo funciona la ingesta: frecuencia, rate limits, reintentos, cache.
  - Cómo instalar, configurar (variables de entorno), ejecutar y testear.
  - Decisiones de diseño importantes como ADRs cortos en `docs/technical/adr/`
    (contexto, decisión, alternativas descartadas).
- Los endpoints se documentan vía OpenAPI (autogenerado); cada endpoint
  debe tener summary, descripción y ejemplos de respuesta.
- Todo módulo y función pública lleva docstring que explique el propósito,
  parámetros, retorno y errores posibles. Los comentarios explican el
  "por qué", no el "qué".