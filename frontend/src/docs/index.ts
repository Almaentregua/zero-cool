import { type Doc, type DocGroup, parseDoc } from "./parse";

export const GROUPS: { id: DocGroup; label: string; intro: string }[] = [
  { id: "sources", label: "Sources", intro: "Where the data comes from: who runs each source and what it tells you." },
  { id: "concepts", label: "Concepts", intro: "The terms and scores you will meet, explained with examples." },
];

// The topics are Markdown files bundled at build time; nothing is fetched at run time.
const files = import.meta.glob("./content/*/*.md", { query: "?raw", import: "default", eager: true }) as Record<
  string,
  string
>;

/** Every topic, ordered by group and then by the `order` of its front matter. */
export const DOCS: Doc[] = Object.entries(files)
  .map(([path, raw]) => parseDoc(path, raw))
  .sort(
    (a, b) =>
      GROUPS.findIndex((g) => g.id === a.group) - GROUPS.findIndex((g) => g.id === b.group) ||
      a.order - b.order ||
      a.title.localeCompare(b.title),
  );

/** Topics of one group, in display order. */
export function docsInGroup(group: DocGroup): Doc[] {
  return DOCS.filter((d) => d.group === group);
}

/** The topic with that group and slug, or undefined when there is none. */
export function getDoc(group: string, slug: string): Doc | undefined {
  return DOCS.find((d) => d.group === group && d.slug === slug);
}

/** Path of a topic page, optionally to one of its sections. */
export function docPath(group: DocGroup, slug: string, anchor?: string): string {
  return `/docs/${group}/${slug}${anchor ? `#${anchor}` : ""}`;
}
