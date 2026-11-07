import { Children, type ReactNode, isValidElement } from "react";
import Markdown from "react-markdown";
import { Link } from "react-router-dom";
import remarkGfm from "remark-gfm";

import { DIAGRAMS } from "../docs/diagramRegistry";
import { slugify } from "../docs/parse";
import { safeUrl } from "../format";

const INTERNAL_LINK = /^\/docs\/(sources|concepts)\/[a-z0-9-]+(#[a-z0-9-]+)?$/;

/** Allows links to other topics and http(s) links; anything else (javascript:, data:, ...) is dropped. */
function docUrl(url: string): string {
  return INTERNAL_LINK.test(url) ? url : (safeUrl(url) ?? "");
}

function textOf(children: ReactNode): string {
  return Children.toArray(children)
    .map((child) => (typeof child === "string" || typeof child === "number" ? String(child) : ""))
    .join("");
}

/** Name of the diagram in a ```diagram block, or null for any other code block. */
function diagramName(children: ReactNode): string | null {
  const child = Children.toArray(children)[0];
  if (!isValidElement(child)) return null;
  const props = child.props as { className?: string; children?: ReactNode };
  return props.className === "language-diagram" ? textOf(props.children).trim() : null;
}

/**
 * Renders the Markdown of a topic. Topics are bundled with the app, but they are still rendered
 * safely: raw HTML is dropped, tables use GitHub-flavored Markdown (`remark-gfm`), images become their alt text and only topic or http(s) links work.
 */
export function DocBody({ markdown }: { markdown: string }) {
  return (
    <div className="doc-body">
      <Markdown
        skipHtml
        remarkPlugins={[remarkGfm]}
        urlTransform={docUrl}
        components={{
          h2: ({ children }) => <h2 id={slugify(textOf(children))}>{children}</h2>,
          h3: ({ children }) => <h3 id={slugify(textOf(children))}>{children}</h3>,
          a: ({ href, children }) => {
            if (!href) return <span>{children}</span>;
            if (INTERNAL_LINK.test(href)) return <Link to={href}>{children}</Link>;
            return (
              <a href={href} target="_blank" rel="noopener noreferrer">
                {children}
              </a>
            );
          },
          img: ({ alt }) => <span className="muted">[image: {alt || "no description"}]</span>,
          table: ({ children }) => (
            <div className="table-wrap">
              <table>{children}</table>
            </div>
          ),
          pre: ({ children }) => {
            const name = diagramName(children);
            if (name === null) return <pre>{children}</pre>;
            const Diagram = DIAGRAMS[name];
            return Diagram ? <Diagram /> : <p className="error">Unknown diagram: {name}</p>;
          },
        }}
      >
        {markdown}
      </Markdown>
    </div>
  );
}
