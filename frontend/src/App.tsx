import { Link, Route, Routes } from "react-router-dom";

import DetailPage from "./pages/DetailPage";
import ListPage from "./pages/ListPage";

/** Layout and routes. */
export default function App() {
  return (
    <>
      <header className="site-header">
        <Link to="/" className="brand">
          CVE Research App
        </Link>
      </header>
      <main>
        <Routes>
          <Route path="/" element={<ListPage />} />
          <Route path="/cve/:cveId" element={<DetailPage />} />
          <Route path="*" element={<p>Page not found. <Link to="/">Go to the list</Link></p>} />
        </Routes>
      </main>
    </>
  );
}
