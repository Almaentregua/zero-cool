import { Link, NavLink, Route, Routes } from "react-router-dom";

import AdvisoryDetailPage from "./pages/AdvisoryDetailPage";
import AdvisoryListPage from "./pages/AdvisoryListPage";
import DetailPage from "./pages/DetailPage";
import { DocPage, DocsIndexPage, DocsLayout } from "./pages/DocsPage";
import InvestigationPage from "./pages/InvestigationPage";
import ListPage from "./pages/ListPage";
import ReportListPage from "./pages/ReportListPage";
import ReportPage from "./pages/ReportPage";

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
          <NavLink to="/investigations">Investigations</NavLink>
          <NavLink to="/reports">Reports</NavLink>
          <NavLink to="/docs">Docs</NavLink>
        </nav>
      </header>
      <main>
        <Routes>
          <Route path="/" element={<ListPage />} />
          <Route path="/cve/:cveId" element={<DetailPage />} />
          <Route path="/advisories" element={<AdvisoryListPage />} />
          <Route path="/advisory/:advisoryId" element={<AdvisoryDetailPage />} />
          <Route path="/investigations" element={<InvestigationPage />} />
          <Route path="/reports" element={<ReportListPage />} />
          <Route path="/reports/:reportId" element={<ReportPage />} />
          <Route path="/docs" element={<DocsLayout />}>
            <Route index element={<DocsIndexPage />} />
            <Route path=":group/:slug" element={<DocPage />} />
          </Route>
          <Route path="*" element={<p>Page not found. <Link to="/">Go to the list</Link></p>} />
        </Routes>
      </main>
    </>
  );
}
