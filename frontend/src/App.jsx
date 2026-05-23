import { useState } from "react";
import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";

function App() {
  const [page, setPage] = useState("dashboard");
  return (
    <div className="flex min-h-screen bg-dark text-gray-300">
      <Sidebar page={page} setPage={setPage} />
      <main className="ml-60 flex-1 p-8">
        {page === "dashboard" && <Dashboard />}
      </main>
    </div>
  );
}

export default App;
