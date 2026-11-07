import { useEffect, useMemo, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useParams } from "react-router-dom";

import { DocBody } from "../components/DocBody";
import { DOCS, GROUPS, docPath, docsInGroup, getDoc } from "../docs";
import { highlightParts, searchDocs } from "../docs/search";

function Highlighted({ text, query }: { text: string; query: string }) {
  return (
    <>
      {highlightParts(text, query).map((part, i) =>
        part.match ? <mark key={i}>{part.text}</mark> : <span key={i}>{part.text}</span>,
      )}
    </>
  );
}

/** Frame of every Docs page: search box and topic list on the side, the page on the right. */
export function DocsLayout() {
  const [query, setQuery] = useState("");
  const results = useMemo(() => searchDocs(DOCS, query), [query]);
  const searching = query.trim() !== "";
  // On narrow screens the list starts collapsed so the topic is visible without scrolling.
  const [open] = useState(() => !window.matchMedia?.("(max-width: 48rem)").matches);

  return (
    <div className="docs-layout">
      <aside className="docs-sidebar">
        <div role="search">
          <label htmlFor="docs-search" className="sr-only">
            Search the docs
          </label>
          <input
            id="docs-search"
            type="search"
            placeholder="Search the docs…"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </div>
        <details open={open || searching}>
          <summary>{searching ? "Search results" : "Topics"}</summary>
          {searching ? (
            <div aria-live="polite">
              <p className="muted">
                {results.length === 0
                  ? `No topics match “${query.trim()}”.`
                  : `${results.length} ${results.length === 1 ? "topic" : "topics"} found`}
              </p>
              <ul className="docs-results">
                {results.map(({ doc, snippet }) => (
                  <li key={`${doc.group}/${doc.slug}`}>
                    <Link to={docPath(doc.group, doc.slug)}>
                      <strong>
                        <Highlighted text={doc.title} query={query} />
                      </strong>{" "}
                      <span className="tag">{doc.group === "sources" ? "Source" : "Concept"}</span>
                      <span className="snippet">
                        <Highlighted text={snippet} query={query} />
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <nav aria-label="Docs topics">
              {GROUPS.map((group) => (
                <section key={group.id}>
                  <h2>{group.label}</h2>
                  <ul>
                    {docsInGroup(group.id).map((doc) => (
                      <li key={doc.slug}>
                        <NavLink to={docPath(doc.group, doc.slug)}>{doc.title}</NavLink>
                      </li>
                    ))}
                  </ul>
                </section>
              ))}
            </nav>
          )}
        </details>
      </aside>
      <div className="docs-content">
        <Outlet />
      </div>
    </div>
  );
}

/** `/docs`: what the section is for and the list of topics by group. */
export function DocsIndexPage() {
  return (
    <article>
      <h1>Docs</h1>
      <p className="subtitle">
        A short guide to the security data shown in this app: where it comes from and how to read it. Each topic is
        meant to give you the idea and the right links to keep learning.
      </p>
      {GROUPS.map((group) => (
        <section key={group.id}>
          <h2>{group.label}</h2>
          <p className="muted">{group.intro}</p>
          <ul className="docs-cards">
            {docsInGroup(group.id).map((doc) => (
              <li key={doc.slug}>
                <Link to={docPath(doc.group, doc.slug)}>{doc.title}</Link>
                <span className="muted">{doc.summary}</span>
              </li>
            ))}
          </ul>
        </section>
      ))}
    </article>
  );
}

/** `/docs/:group/:slug`: one topic with its table of sections and links to the previous and next one. */
export function DocPage() {
  const { group = "", slug = "" } = useParams();
  const { hash } = useLocation();
  const doc = getDoc(group, slug);

  // The router does not scroll to anchors by itself.
  useEffect(() => {
    if (hash) document.getElementById(decodeURIComponent(hash.slice(1)))?.scrollIntoView?.();
    else window.scrollTo?.(0, 0);
  }, [hash, group, slug]);

  if (!doc) {
    return (
      <p>
        That topic does not exist. <Link to="/docs">Go to the docs index</Link>
      </p>
    );
  }

  const siblings = docsInGroup(doc.group);
  const index = siblings.indexOf(doc);
  const previous = siblings[index - 1];
  const next = siblings[index + 1];

  return (
    <article>
      <p className="muted docs-crumbs">
        <Link to="/docs">Docs</Link> / {doc.group === "sources" ? "Sources" : "Concepts"}
      </p>
      <h1>{doc.title}</h1>
      <p className="subtitle">{doc.summary}</p>
      {doc.headings.length >= 3 && (
        <nav aria-label="On this page" className="docs-toc">
          <strong>On this page</strong>
          <ul>
            {doc.headings.map((heading) => (
              <li key={heading.id}>
                <a href={`#${heading.id}`}>{heading.text}</a>
              </li>
            ))}
          </ul>
        </nav>
      )}
      <DocBody markdown={doc.body} />
      <nav aria-label="Topic pagination" className="docs-pager">
        {previous ? <Link to={docPath(previous.group, previous.slug)}>← {previous.title}</Link> : <span />}
        {next ? <Link to={docPath(next.group, next.slug)}>{next.title} →</Link> : <span />}
      </nav>
    </article>
  );
}
