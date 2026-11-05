import Markdown from "react-markdown";

import { safeUrl } from "../format";
import type { NotesMode } from "../notesMode";

/**
 * Shows notes as Markdown or as plain text. Notes are untrusted: raw HTML is dropped
 * (`skipHtml`), only http(s) links survive, and images are shown as their alt text so
 * that nothing is loaded from a third-party site.
 */
export function NotesView({ text, mode }: { text: string; mode: NotesMode }) {
  if (text.trim() === "") return <p className="muted">No notes yet.</p>;
  if (mode === "plain") return <pre className="notes-plain">{text}</pre>;
  return (
    <div className="notes-markdown">
      <Markdown
        skipHtml
        urlTransform={(url) => safeUrl(url) ?? ""}
        components={{
          a: ({ href, children }) =>
            href ? (
              <a href={href} target="_blank" rel="noopener noreferrer">
                {children}
              </a>
            ) : (
              <span>{children}</span>
            ),
          img: ({ alt }) => <span className="muted">[image: {alt || "no description"}]</span>,
        }}
      >
        {text}
      </Markdown>
    </div>
  );
}

/** Radio switch between the two ways of showing notes. */
export function ModeSwitch({ mode, onChange }: { mode: NotesMode; onChange: (m: NotesMode) => void }) {
  return (
    <fieldset className="mode-switch">
      <legend>Show notes as</legend>
      <label className="inline">
        <input type="radio" name="notes-mode" checked={mode === "markdown"} onChange={() => onChange("markdown")} />
        Markdown
      </label>
      <label className="inline">
        <input type="radio" name="notes-mode" checked={mode === "plain"} onChange={() => onChange("plain")} />
        Plain text
      </label>
    </fieldset>
  );
}
