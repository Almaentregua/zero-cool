import type { Doc } from "./parse";

export interface SearchResult {
  doc: Doc;
  score: number;
  snippet: string;
}

/** Lower-case words of a query; empty for a blank query. */
export function queryTerms(query: string): string[] {
  return query.toLowerCase().split(/\s+/).filter(Boolean);
}

/**
 * Searches title, keywords, summary and text of every topic. A topic matches when
 * every word of the query appears somewhere in it; matches in the title weigh the most,
 * then keywords, summary and body.
 *
 * @param docs Topics to search.
 * @param query Free text typed by the user.
 * @returns Matching topics, best first, each with a short snippet of the text around the match.
 */
export function searchDocs(docs: Doc[], query: string): SearchResult[] {
  const terms = queryTerms(query);
  if (terms.length === 0) return [];

  const results: SearchResult[] = [];
  for (const doc of docs) {
    const title = doc.title.toLowerCase();
    const keywords = doc.keywords.join(" ").toLowerCase();
    const summary = doc.summary.toLowerCase();
    const body = doc.plain.toLowerCase();

    let score = 0;
    let matchesAll = true;
    for (const term of terms) {
      const termScore =
        (title.includes(term) ? 10 : 0) +
        (keywords.includes(term) ? 5 : 0) +
        (summary.includes(term) ? 3 : 0) +
        (body.includes(term) ? 1 : 0);
      if (termScore === 0) {
        matchesAll = false;
        break;
      }
      score += termScore;
    }
    if (matchesAll) results.push({ doc, score, snippet: makeSnippet(doc, terms) });
  }
  return results.sort((a, b) => b.score - a.score || a.doc.title.localeCompare(b.doc.title));
}

/** About 160 characters of body text around the first query word found in it (the summary if none). */
function makeSnippet(doc: Doc, terms: string[]): string {
  const lower = doc.plain.toLowerCase();
  const positions = terms.map((t) => lower.indexOf(t)).filter((i) => i >= 0);
  if (positions.length === 0) return doc.summary;
  const at = Math.min(...positions);
  const start = Math.max(0, at - 60);
  const end = Math.min(doc.plain.length, at + 100);
  return `${start > 0 ? "…" : ""}${doc.plain.slice(start, end).trim()}${end < doc.plain.length ? "…" : ""}`;
}

/** Splits text into pieces, flagging the ones that match a query word, so they can be highlighted. */
export function highlightParts(text: string, query: string): { text: string; match: boolean }[] {
  const terms = queryTerms(query).map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  if (terms.length === 0) return [{ text, match: false }];
  // With a capture group, split() puts the matches at the odd positions.
  return text
    .split(new RegExp(`(${terms.join("|")})`, "gi"))
    .map((piece, index) => ({ text: piece, match: index % 2 === 1 }))
    .filter((part) => part.text !== "");
}
