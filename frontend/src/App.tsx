import { Link, NavLink, Route, Routes } from "react-router-dom";

import AdvisoryDetailPage from "./pages/AdvisoryDetailPage";
import AdvisoryListPage from "./pages/AdvisoryListPage";
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
        <nav aria-label="Main">
          <NavLink to="/" end>
            Known exploited (KEV)
          </NavLink>
          <NavLink to="/advisories">Package advisories</NavLink>
        </nav>
      </header>
      <main>
        <Routes>
          <Route path="/" element={<ListPage />} />
          <Route path="/cve/:cveId" element={<DetailPage />} />
          <Route path="/advisories" element={<AdvisoryListPage />} />
          <Route path="/advisory/:advisoryId" element={<AdvisoryDetailPage />} />
          <Route path="*" element={<p>Page not found. <Link to="/">Go to the list</Link></p>} />
        </Routes>
      </main>
    </>
  );
}
