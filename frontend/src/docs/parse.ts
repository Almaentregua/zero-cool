/** Parsing of the Markdown topics that make up the Docs section. */

export type DocGroup = "sources" | "concepts";

export interface Heading {
  id: string;
  text: string;
}

export interface Doc {
  group: DocGroup;
  slug: string;
  title: string;
  summary: string;
  keywords: string[];
  order: number;
  body: string;
  headings: Heading[];
  /** Body without Markdown syntax, used for searching and snippets. */
  plain: string;
}

/** Turns a heading text into a stable anchor id, e.g. "How this app uses it" -> "how-this-app-uses-it". */
export function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/** Removes Markdown syntax so the text can be searched and quoted in snippets. */
export function toPlainText(markdown: string): string {
  return markdown
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/[`*_>#|]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/** Second-level headings (outside code fences), used for the "On this page" list. */
export function extractHeadings(body: string): Heading[] {
  const headings: Heading[] = [];
  let inFence = false;
  for (const line of body.split("\n")) {
    if (line.startsWith("```")) inFence = !inFence;
    const match = !inFence && /^## (.+)$/.exec(line);
    if (match) headings.push({ id: slugify(match[1]), text: match[1].trim() });
  }
  return headings;
}

/**
 * Parses one topic file. The file starts with a `---` block of `key: value` lines
 * (`title`, `summary`, `order`, comma-separated `keywords`) followed by the Markdown body.
 * The group and slug come from the path (`content/<group>/<slug>.md`).
 *
 * @throws Error when the path, the front matter or a required key is invalid, so a broken
 *   topic fails loudly in tests instead of silently disappearing.
 */
export function parseDoc(path: string, raw: string): Doc {
  const location = /content\/(sources|concepts)\/([a-z0-9-]+)\.md$/.exec(path);
  if (!location) throw new Error(`Unexpected docs path: ${path}`);
  const parts = /^---\n([\s\S]*?)\n---\n([\s\S]*)$/.exec(raw);
  if (!parts) throw new Error(`Missing front matter in ${path}`);

  const meta: Record<string, string> = {};
  for (const line of parts[1].split("\n")) {
    const separator = line.indexOf(":");
    if (separator > 0) meta[line.slice(0, separator).trim()] = line.slice(separator + 1).trim();
  }
  for (const key of ["title", "summary", "order"]) {
    if (!meta[key]) throw new Error(`Missing "${key}" in ${path}`);
  }
  const order = Number(meta.order);
  if (!Number.isFinite(order)) throw new Error(`Invalid "order" in ${path}`);

  const body = parts[2].trim();
  return {
    group: location[1] as DocGroup,
    slug: location[2],
    title: meta.title,
    summary: meta.summary,
    keywords: (meta.keywords ?? "")
      .split(",")
      .map((k) => k.trim())
      .filter(Boolean),
    order,
    body,
    headings: extractHeadings(body),
    plain: toPlainText(body),
  };
}
