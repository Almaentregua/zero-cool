import { useEffect, useState } from "react";

export type FetchState<T> =
  | { status: "loading" }
  | { status: "error"; error: Error }
  | { status: "ok"; data: T };

/** Runs `load` whenever `key` changes and cancels the previous request. */
export function useFetch<T>(load: (signal: AbortSignal) => Promise<T>, key: string): FetchState<T> {
  const [state, setState] = useState<FetchState<T>>({ status: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    setState({ status: "loading" });
    load(controller.signal)
      .then((data) => setState({ status: "ok", data }))
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        setState({ status: "error", error: error instanceof Error ? error : new Error("Unknown error") });
      });
    return () => controller.abort();
    // `key` stands for everything `load` depends on.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  return state;
}
