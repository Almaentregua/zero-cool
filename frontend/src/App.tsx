import { useEffect, useState } from "react";

type ApiStatus = "loading" | "ok" | "error";

/** Minimal shell that checks the backend is reachable. */
export default function App() {
  const [status, setStatus] = useState<ApiStatus>("loading");

  useEffect(() => {
    fetch("/api/health")
      .then((res) => (res.ok ? setStatus("ok") : setStatus("error")))
      .catch(() => setStatus("error"));
  }, []);

  return (
    <main>
      <h1>CVE Research App</h1>
      <p>API status: {status}</p>
    </main>
  );
}
