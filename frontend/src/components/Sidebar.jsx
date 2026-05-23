const MENU = [
  { id: "dashboard", label: "Overview",          icon: "◈", url: null },
  { section: "OFFENSIVE" },
  { label: "Deep Recon",       icon: "🎯", url: "/recon/scan" },
  { label: "OSINT Engine",     icon: "🕵", url: "/osint" },
  { label: "Port Scanner",     icon: "◎", url: "/ports" },
  { label: "Web Audit OWASP",  icon: "◇", url: "/owasp" },
  { section: "DEFENSIVE" },
  { label: "IDS / Forensique", icon: "🛡", url: "/ids" },
  { label: "Threat Intel",     icon: "🚨", url: "/threat" },
  { label: "Log Analyzer",     icon: "◉", url: "/logs" },
  { label: "Crypto & SecOps",  icon: "◆", url: "/secops" },
  { section: "NETWORK" },
  { label: "WHOIS & DNS",      icon: "◈", url: "/whois" },
  { label: "IP Intelligence",  icon: "◎", url: "/ip-intel" },
  { section: "REPORTING" },
  { label: "Rapport PTES",     icon: "📋", url: "/audit" },
  { label: "Pentest Checklist",icon: "📝", url: "/checklist" },
  { section: "OUTILS" },
  { label: "Assistant IA",     icon: "🤖", url: "/assistant" },
];

export default function Sidebar({ page, setPage }) {
  return (
    <aside className="fixed top-0 left-0 h-screen w-60 bg-dark border-r border-border flex flex-col overflow-y-auto z-50">
      <div className="px-5 py-6 border-b border-border">
        <h1 className="text-cyber font-bold text-lg tracking-widest">⚡ PYSECOPS</h1>
        <p className="text-dim text-xs mt-1">Security Platform v3.0</p>
      </div>
      <nav className="flex-1 py-2">
        {MENU.map((item, i) => {
          if (item.section) return (
            <div key={i} className="px-5 pt-4 pb-1 text-[10px] font-bold tracking-widest text-dim opacity-60 uppercase">
              {item.section}
            </div>
          );
          if (item.id === "dashboard") return (
            <button key={i} onClick={() => setPage("dashboard")}
              className={`w-full flex items-center gap-3 px-5 py-2.5 text-sm border-l-2 transition-all
                ${page === "dashboard"
                  ? "border-cyber text-cyber bg-cyber/10 font-semibold"
                  : "border-transparent text-dim hover:text-gray-200 hover:bg-cyber/5"}`}>
              <span className="text-xs opacity-70">{item.icon}</span>{item.label}
            </button>
          );
          return (
            <a key={i} href={item.url}
              className="flex items-center gap-3 px-5 py-2.5 text-sm border-l-2 border-transparent text-dim hover:text-gray-200 hover:bg-cyber/5 transition-all">
              <span className="text-xs opacity-70">{item.icon}</span>{item.label}
            </a>
          );
        })}
      </nav>
      <div className="px-5 py-4 border-t border-border text-xs text-dim flex items-center gap-2">
        <span className="w-2 h-2 bg-success rounded-full animate-pulse"></span>
        System Online · <strong className="text-gray-300">Hyacinthe</strong>
      </div>
    </aside>
  );
}
