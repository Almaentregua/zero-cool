import type { ComponentType } from "react";

import { CvssVectorBreakdown, CveCweCpe, SeverityScale } from "./diagrams";

/**
 * Diagrams that topics can embed with a fenced block:
 *
 *     ```diagram
 *     name
 *     ```
 *
 * They are React components (SVG/HTML), so they follow the light and dark theme.
 */
export const DIAGRAMS: Record<string, ComponentType> = {
  "severity-scale": SeverityScale,
  "cvss-vector": CvssVectorBreakdown,
  "cve-cwe-cpe": CveCweCpe,
};
