import type { FormEvent } from "react";

import { SEVERITIES, type Technology } from "../api";

interface Props {
  params: URLSearchParams;
  technologies: Technology[];
  onApply: (next: URLSearchParams) => void;
}

/** Search and filters. Applied on submit so each keystroke does not hit the API. */
export default function FilterBar({ params, technologies, onApply }: Props) {
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const next = new URLSearchParams();
    for (const key of ["q", "technology", "added_from", "added_to", "min_cvss", "min_epss"]) {
      const value = String(form.get(key) ?? "").trim();
      if (value) next.set(key, value);
    }
    for (const value of form.getAll("severity")) next.append("severity", String(value));
    if (form.get("ransomware")) next.set("ransomware", "true");
    // Keep the sort, restart at the first page.
    for (const key of ["sort", "order"]) {
      const value = params.get(key);
      if (value) next.set(key, value);
    }
    onApply(next);
  }

  // Changing the URL remounts the form so inputs always reflect it.
  return (
    <form className="filters" onSubmit={submit} key={params.toString()} aria-label="Filters">
      <label className="wide">
        Search
        <input type="search" name="q" defaultValue={params.get("q") ?? ""} placeholder="CVE id or text, e.g. log4j" maxLength={200} />
      </label>
      <label>
        Technology
        <select name="technology" defaultValue={params.get("technology") ?? ""}>
          <option value="">All</option>
          {technologies.map((t) => (
            <option key={t.name} value={t.name}>
              {t.name}
            </option>
          ))}
        </select>
      </label>
      <label>
        Added from
        <input type="date" name="added_from" defaultValue={params.get("added_from") ?? ""} />
      </label>
      <label>
        Added to
        <input type="date" name="added_to" defaultValue={params.get("added_to") ?? ""} />
      </label>
      <label>
        Min CVSS (0-10)
        <input type="number" name="min_cvss" min={0} max={10} step={0.1} defaultValue={params.get("min_cvss") ?? ""} />
      </label>
      <label>
        Min EPSS (0-1)
        <input type="number" name="min_epss" min={0} max={1} step={0.01} defaultValue={params.get("min_epss") ?? ""} />
      </label>
      <fieldset>
        <legend>Severity</legend>
        {SEVERITIES.map((s) => (
          <label key={s} className="inline">
            <input type="checkbox" name="severity" value={s} defaultChecked={params.getAll("severity").includes(s)} />
            {s}
          </label>
        ))}
      </fieldset>
      <label className="inline">
        <input type="checkbox" name="ransomware" defaultChecked={params.get("ransomware") === "true"} />
        Used in ransomware
      </label>
      <div className="actions">
        <button type="submit">Apply</button>
        <button type="button" className="secondary" onClick={() => onApply(new URLSearchParams())}>
          Reset
        </button>
      </div>
    </form>
  );
}
