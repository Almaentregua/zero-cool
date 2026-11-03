import type { FormEvent } from "react";

import { SEVERITIES, type Technology } from "../api";

interface Props {
  params: URLSearchParams;
  technologies: Technology[];
  onApply: (next: URLSearchParams) => void;
}

/** Search and filters of the advisory list. Applied on submit. */
export default function AdvisoryFilterBar({ params, technologies, onApply }: Props) {
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const next = new URLSearchParams();
    for (const key of ["q", "technology", "package", "published_from", "published_to", "min_epss", "has_cve"]) {
      const value = String(form.get(key) ?? "").trim();
      if (value) next.set(key, value);
    }
    for (const value of form.getAll("severity")) next.append("severity", String(value));
    for (const key of ["sort", "order"]) {
      const value = params.get(key);
      if (value) next.set(key, value);
    }
    onApply(next);
  }

  return (
    <form className="filters" onSubmit={submit} key={params.toString()} aria-label="Filters">
      <label className="wide">
        Search
        <input
          type="search"
          name="q"
          defaultValue={params.get("q") ?? ""}
          placeholder="Advisory id, CVE, summary or package"
          maxLength={200}
        />
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
        Package name contains
        <input type="text" name="package" defaultValue={params.get("package") ?? ""} maxLength={200} />
      </label>
      <label>
        Published from
        <input type="date" name="published_from" defaultValue={params.get("published_from") ?? ""} />
      </label>
      <label>
        Published to
        <input type="date" name="published_to" defaultValue={params.get("published_to") ?? ""} />
      </label>
      <label>
        Min EPSS (0-1)
        <input type="number" name="min_epss" min={0} max={1} step={0.01} defaultValue={params.get("min_epss") ?? ""} />
      </label>
      <label>
        CVE
        <select name="has_cve" defaultValue={params.get("has_cve") ?? ""}>
          <option value="">Any</option>
          <option value="true">With a CVE</option>
          <option value="false">Without a CVE</option>
        </select>
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
      <div className="actions">
        <button type="submit">Apply</button>
        <button type="button" className="secondary" onClick={() => onApply(new URLSearchParams())}>
          Reset
        </button>
      </div>
    </form>
  );
}
