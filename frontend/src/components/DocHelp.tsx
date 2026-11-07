import { Link } from "react-router-dom";

import { docPath } from "../docs";
import type { DocGroup } from "../docs/parse";

/**
 * A small "?" link next to a term that opens its topic in the Docs section.
 *
 * @param group Docs group of the topic (`sources` or `concepts`).
 * @param slug Topic slug, e.g. `cvss`.
 * @param label Name of the term, used for the accessible name ("About CVSS").
 */
export function DocHelp({ group = "concepts", slug, label }: { group?: DocGroup; slug: string; label: string }) {
  return (
    <Link className="doc-help" to={docPath(group, slug)} aria-label={`About ${label}`} title={`About ${label}`}>
      ?
    </Link>
  );
}
