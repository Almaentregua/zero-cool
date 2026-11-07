import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import App from "./App";
import { DocBody } from "./components/DocBody";
import { DOCS, docsInGroup, getDoc } from "./docs";
import { extractHeadings, parseDoc, slugify, toPlainText } from "./docs/parse";
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
