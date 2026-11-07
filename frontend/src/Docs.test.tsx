import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import App from "./App";
import { DocBody } from "./components/DocBody";
import { DOCS, docsInGroup, getDoc } from "./docs";
import { extractHeadings, parseDoc, slugify, toPlainText } from "./docs/parse";
import { describeVectorPart } from "./docs/cvssMetrics";
import { DIAGRAMS } from "./docs/diagramRegistry";
import { CvssVectorBreakdown } from "./docs/diagrams";
import { highlightParts, searchDocs } from "./docs/search";

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}

const RAW = `---
title: Sample
summary: A sample topic.
order: 3
keywords: alpha, beta gamma
---
Intro text about deserialization.

## First section

Some \`code\` and a [link](https://example.test/x).

\`\`\`
## not a heading
\`\`\`

## Second section
`;

describe("parseDoc", () => {
  test("reads front matter, group, slug and headings", () => {
    const doc = parseDoc("./content/concepts/sample.md", RAW);
    expect(doc).toMatchObject({ group: "concepts", slug: "sample", title: "Sample", order: 3 });
    expect(doc.keywords).toEqual(["alpha", "beta gamma"]);
    expect(doc.headings.map((h) => h.text)).toEqual(["First section", "Second section"]);
    expect(doc.plain).toContain("Some code and a link");
  });

  test("fails loudly on a broken topic", () => {
    expect(() => parseDoc("./content/concepts/x.md", "no front matter")).toThrow("front matter");
    expect(() => parseDoc("./content/concepts/x.md", "---\ntitle: T\n---\nbody")).toThrow('"summary"');
    expect(() => parseDoc("./content/other/x.md", RAW)).toThrow("path");
    expect(() => parseDoc("./content/concepts/x.md", RAW.replace("order: 3", "order: soon"))).toThrow("order");
  });

  test("helpers", () => {
    expect(slugify("How this app uses it")).toBe("how-this-app-uses-it");
    expect(extractHeadings("## A\n```\n## B\n```\n### C")).toEqual([{ id: "a", text: "A" }]);
    expect(toPlainText("**bold** [t](http://x) `c`")).toBe("bold t c");
  });
});

describe("searchDocs", () => {
  const docs = [
    parseDoc("./content/concepts/a.md", RAW),
    parseDoc("./content/sources/b.md", RAW.replace("Sample", "Other").replace("deserialization", "scoring")),
  ];

  test("matches title, keywords and text; every word must match", () => {
    expect(searchDocs(docs, "sample").map((r) => r.doc.slug)).toEqual(["a", "b"]); // title beats summary
    expect(searchDocs(docs, "gamma").length).toBe(2);
    expect(searchDocs(docs, "deserialization").map((r) => r.doc.slug)).toEqual(["a"]);
    expect(searchDocs(docs, "deserialization zzz")).toEqual([]);
    expect(searchDocs(docs, "   ")).toEqual([]);
  });

  test("title matches rank first and the snippet quotes the text", () => {
    const [first] = searchDocs(docs, "other");
    expect(first.doc.slug).toBe("b");
    expect(searchDocs(docs, "deserialization")[0].snippet).toContain("deserialization");
  });

  test("highlightParts flags matches and escapes regex characters", () => {
    expect(highlightParts("Hello World", "world")).toEqual([
      { text: "Hello ", match: false },
      { text: "World", match: true },
    ]);
    expect(() => highlightParts("a (b", "(")).not.toThrow();
  });
});

describe("DocBody", () => {
  test("is safe: no raw HTML, no javascript: links, no remote images", () => {
    const { container } = render(
      <MemoryRouter>
        <DocBody markdown={'<script>alert(1)</script>\n\n[bad](javascript:alert(1)) ![pic](https://x.test/a.png)'} />
      </MemoryRouter>,
    );
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("a")).toBeNull();
    expect(screen.getByText("[image: pic]")).toBeInTheDocument();
  });

  test("links to topics stay inside the app and external links open safely", () => {
    render(
      <MemoryRouter>
        <DocBody markdown={"[inner](/docs/concepts/cvss#score) [outer](https://example.test)"} />
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "inner" })).toHaveAttribute("href", "/docs/concepts/cvss#score");
    expect(screen.getByRole("link", { name: "outer" })).toHaveAttribute("rel", "noopener noreferrer");
  });

  test("gives sections an id and reports unknown diagrams", () => {
    render(
      <MemoryRouter>
        <DocBody markdown={"## My section\n\n```diagram\nnope\n```"} />
      </MemoryRouter>,
    );
    expect(screen.getByRole("heading", { name: "My section" })).toHaveAttribute("id", "my-section");
    expect(screen.getByText("Unknown diagram: nope")).toBeInTheDocument();
  });
});

describe("Docs pages", () => {
  test("topics are unique per group and every topic has content", () => {
    const keys = DOCS.map((d) => `${d.group}/${d.slug}`);
    expect(new Set(keys).size).toBe(keys.length);
    for (const doc of DOCS) expect(doc.body.length).toBeGreaterThan(100);
  });

  test("every source follows the same card and links to its official website", () => {
    const sections = ["At a glance", "What it tells you", "Example", "How this app uses it", "Pitfalls", "Keep investigating"];
    const sources = docsInGroup("sources");
    expect(sources.map((d) => d.slug)).toEqual([
      "cisa-kev",
      "nvd",
      "epss",
      "osv",
      "github-advisories",
      "cve-org",
      "cisa-vulnrichment",
      "mitre-cwe",
    ]);
    for (const doc of sources) {
      const texts = doc.headings.map((h) => h.text);
      for (const section of sections) expect(texts, `${doc.slug} lacks "${section}"`).toContain(section);
      expect(doc.body, `${doc.slug} lacks a Website row`).toMatch(/\| Website \| .*\]\(https:\/\//);
    }
  });

  test("sources do not talk about API access", () => {
    for (const doc of docsInGroup("sources")) expect(doc.plain).not.toMatch(/api key|rate limit/i);
  });

  test("the index lists topics and the menu has a Docs link", () => {
    renderAt("/docs");
    expect(screen.getByRole("link", { name: "Docs", current: "page" })).toBeInTheDocument();
    expect(screen.getAllByRole("heading", { name: "Sources" }).length).toBe(2); // sidebar and index
    const first = docsInGroup("sources")[0];
    expect(screen.getAllByRole("link", { name: first.title }).length).toBeGreaterThan(0);
  });

  test("a topic page shows title, sections, and pagination", () => {
    const doc = getDoc("sources", "cisa-kev")!;
    renderAt(`/docs/sources/${doc.slug}`);
    expect(screen.getByRole("heading", { level: 1, name: doc.title })).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "On this page" })).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Topic pagination" })).toBeInTheDocument();
  });

  test("unknown topic shows a message with a way back", () => {
    renderAt("/docs/concepts/does-not-exist");
    expect(screen.getByText(/does not exist/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Go to the docs index" })).toHaveAttribute("href", "/docs");
  });

  test("searching replaces the topic list with results and says when nothing matches", async () => {
    renderAt("/docs");
    const box = screen.getByRole("searchbox", { name: "Search the docs" });
    await userEvent.type(box, "ransomware");
    expect(screen.getByText(/topics? found/)).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: /CISA KEV/ }).length).toBeGreaterThan(0);
    await userEvent.clear(box);
    await userEvent.type(box, "zzzzqqq");
    expect(screen.getByText("No topics match “zzzzqqq”.")).toBeInTheDocument();
  });
});

describe("Docs content", () => {
  const exists = (path: string) => {
    const match = /^\/docs\/(sources|concepts)\/([a-z0-9-]+)(?:#([a-z0-9-]+))?$/.exec(path);
    if (!match) return false;
    const doc = getDoc(match[1], match[2]);
    return !!doc && (!match[3] || doc.headings.some((h) => h.id === match[3]));
  };

  test("every internal link points to an existing topic and section", () => {
    for (const doc of DOCS) {
      for (const [, path] of doc.body.matchAll(/\]\((\/docs[^)]*)\)/g)) {
        expect(exists(path), `${doc.group}/${doc.slug} links to ${path}`).toBe(true);
      }
    }
  });

  test("every diagram used by a topic exists", () => {
    for (const doc of DOCS) {
      for (const [, name] of doc.body.matchAll(/```diagram\n([a-z-]+)\n```/g)) {
        expect(Object.keys(DIAGRAMS), `${doc.slug} uses diagram ${name}`).toContain(name);
      }
    }
  });

  test("concepts have an example and further reading", () => {
    const concepts = docsInGroup("concepts");
    expect(concepts.length).toBe(13);
    for (const doc of concepts) {
      const texts = doc.headings.map((h) => h.text);
      expect(texts, doc.slug).toContain("Keep investigating");
      expect(texts.some((t) => t.startsWith("Example")), doc.slug).toBe(true);
    }
  });

  test("every topic has a short summary and is not too long", () => {
    for (const doc of DOCS) {
      expect(doc.summary.length, doc.slug).toBeLessThan(160);
      expect(doc.plain.split(" ").length, `${doc.slug} is too long`).toBeLessThan(1100);
    }
  });
});

describe("Diagrams", () => {
  test("vector parts are explained", () => {
    expect(describeVectorPart("AV:N")).toEqual({ name: "Attack Vector", meaning: expect.stringContaining("remotely") });
    expect(describeVectorPart("ZZ:N")).toBeNull();
    expect(describeVectorPart("AV:Q")).toBeNull();
  });

  test("selecting a part shows its meaning", async () => {
    render(<CvssVectorBreakdown />);
    expect(screen.getByText("Select or hover a part of the vector.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "PR:N" }));
    expect(screen.getByText(/no login needed/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "PR:N" })).toHaveAttribute("aria-pressed", "true");
  });
});

describe("Help links", () => {
  const sources = import.meta.glob(["./pages/*.tsx", "./components/*.tsx"], { query: "?raw", import: "default", eager: true }) as Record<
    string,
    string
  >;

  test("every <DocHelp> in the app points to an existing topic", () => {
    let found = 0;
    for (const [file, code] of Object.entries(sources)) {
      for (const [, attrs] of code.matchAll(/<DocHelp ([^>]*?)\/>/g)) {
        const slug = /slug="([a-z0-9-]+)"/.exec(attrs)?.[1];
        if (!slug) continue; // dynamic slug, covered by the test below
        const group = /group="(sources|concepts)"/.exec(attrs)?.[1] ?? "concepts";
        expect(getDoc(group, slug), `${file}: ${attrs}`).toBeDefined();
        found++;
      }
    }
    expect(found).toBeGreaterThan(20);
  });

  test("every research source has a topic", () => {
    const code = sources["./components/SourceBlock.tsx"];
    const block = /SOURCE_TOPIC[^{]*\{([^}]*)\}/.exec(code)?.[1] ?? "";
    const slugs = [...block.matchAll(/:\s*"([a-z-]+)"/g)].map((m) => m[1]);
    expect(slugs.length).toBe(7);
    for (const slug of slugs) expect(getDoc("sources", slug), slug).toBeDefined();
  });
});
