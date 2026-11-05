import { useState } from "react";

export type NotesMode = "markdown" | "plain";
const STORAGE_KEY = "notes-mode";

function loadMode(): NotesMode {
  try {
    return localStorage.getItem(STORAGE_KEY) === "plain" ? "plain" : "markdown";
  } catch {
    return "markdown"; // storage can be blocked; the preference is a convenience only
  }
}

/** Notes are stored as typed; this only changes how they are shown. Shared by all reports. */
export function useNotesMode(): [NotesMode, (mode: NotesMode) => void] {
  const [mode, setMode] = useState<NotesMode>(loadMode);
  return [
    mode,
    (next) => {
      setMode(next);
      try {
        localStorage.setItem(STORAGE_KEY, next);
      } catch {
        // ignore: the choice just will not be remembered
      }
    },
  ];
}
