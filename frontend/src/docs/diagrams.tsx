import type { ComponentType } from "react";

/**
 * Diagrams that topics can embed with a fenced block:
 *
 *     ```diagram
 *     name
 *     ```
 *
 * They are React components (SVG/HTML), so they follow the light and dark theme.
 */
export const DIAGRAMS: Record<string, ComponentType> = {};
