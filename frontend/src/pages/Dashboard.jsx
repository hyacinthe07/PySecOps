import { useState, useEffect, useCallback } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend
} from "recharts";

// ── Composants
function StatCard({ val, label, color, icon }) {
  return (
    <div className="bg-card border border-border rounded-lg p-5 text-center
                    hover:border-cyber/50 transition-all duration-200 group">
      {icon && <div className="text-2xl mb-2">{icon}</div>}
      <div className={`text-3xl font-bold ${color || "text-cyber"}`}>{val}</div>
      <div className="text-dim text-xs uppercase tracking-wider mt-1">{label}</div>
    </div>
  );
}

function AlertCard({ type, module, msg, action, url, icon }) {
  const styles = {
    CRITIQUE: "border-danger/40 bg-danger/5",
    HAUTE:    "border-warning/40 bg-warning/5",
    INFO:     "border-cyber/40 bg-cyber/5",
    OK:       "border-success/40 bg-success/5",
  };
  const textColors = {
    CRITIQUE: "text-danger",
    HAUTE:    "text-warning",
    INFO:     "text-cyber",
    OK:       "text-success",
  };
  return (
    <a href={url}
       className={`border rounded-lg p-4 block hover:opacity-90
                   transition-opacity ${styles[type] || styles.INFO}`}>
      <div className="flex items-center gap-2 mb-1">
        <span>{icon}</span>
        <span className={`text-xs font-bold uppercase tracking-wider
                         ${textColors[type] || textColors.INFO}`}>
          {module}
        </span>
        <span className={`ml-auto text-xs font-bold px-2 py-0.5 rounded
                         ${type === "CRITIQUE" ? "bg-danger/20 text-danger" :
                           type === "HAUTE"    ? "bg-warning/20 text-warning" :
                           type === "OK"       ? "bg-success/20 text-success" :
                                                 "bg-cyber/20 text-cyber"}`}>
          {type}
        </span>
      </div>
      <div className="font-semibold text-sm text-gray-200">{msg}</div>
      <div className="text-xs text-dim mt-1">→ {action}</div>
    </a>
  );
}

const TOOLTIP_STYLE = {
  contentStyle: {
    background: '#161b22', border: '1px solid #30363d',
    borderRadius: '6px', color: '#c9d1d9', fontSize: '12px',
  }
};

const PIE_COLORS = ["#58a6ff","#f85149","#3fb950","#d29922","#bc8cff","#79c0ff"];

const QUICK_ACCESS = [
  { label:"Deep Recon",     icon:"🎯", url:"/recon/scan",  desc:"CVE + fingerprinting" },
  { label:"Import Nmap",    icon:"📡", url:"/nmap-import", desc:"Analyse XML Nmap" },
  { label:"IDS Forensique", icon:"🛡", url:"/ids",         desc:"17 signatures réelles" },
  { label:"Log Analyzer",   icon:"📋", url:"/logs",        desc:"Résumé en français" },
  { label:"Rapport PTES",   icon:"📋", url:"/audit",       desc:"PDF professionnel" },
  { label:"OSINT Engine",   icon:"🕵", url:"/osint",       desc:"Emails, Dorks, Shodan" },
  { label:"Threat Intel",   icon:"🚨", url:"/threat",      desc:"Réputation IP/domaine" },
  { label:"Assistant IA",   icon:"🤖", url:"/assistant",   desc:"Questions cybersécurité" },
];

export default function Dashboard() {
  const [stats,   setStats]   = useState(null);
  const [alertes, setAlertes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [erreur,  setErreur]  = useState(null);
  const [lastUpdate, setLastUpdate] = useState(null);

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, alertesRes] = await Promise.all([
        fetch("/api/v1/stats"),
        fetch("/api/v1/alertes"),
      ]);
      if (!statsRes.ok) throw new Error("API indisponible");
      const statsData   = await statsRes.json();
      const alertesData = await alertesRes.json();
      setStats(statsData);
      setAlertes(alertesData.alertes || []);
      setLastUpdate(new Date().toLocaleTimeString('fr-FR'));
      setLoading(false);
    } catch(e) {
      setErreur(e.message);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    // Rafraîchissement automatique toutes les 30 secondes
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [fetchData]);

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <div className="text-cyber animate-pulse text-lg font-mono">
        Chargement du dashboard...
      </div>
    </div>
  );

  if (erreur) return (
    <div className="bg-danger/10 border border-danger/30 rounded-lg p-6 text-danger">
      <p className="font-semibold">Erreur API : {erreur}</p>
      <p className="text-sm mt-1 opacity-75">
        Vérifiez que Flask tourne sur le port 8080.
      </p>
    </div>
  );

  const barData = [
    { nom:"Ports",   val: stats?.ports      || 0 },
    { nom:"OWASP",   val: stats?.owasp      || 0 },
    { nom:"Recon",   val: stats?.recon_scan || 0 },
    { nom:"IDS",     val: stats?.ids        || 0 },
    { nom:"OSINT",   val: (stats?.osint_emails||0)+(stats?.osint_dorks||0) },
    { nom:"Threat",  val: stats?.threat     || 0 },
    { nom:"Nmap",    val: stats?.nmap_import|| 0 },
    { nom:"Logs",    val: stats?.logs       || 0 },
  ].filter(d => d.val > 0);

  const pieData = barData.length > 0 ? barData : [
    { nom: "Aucune analyse", val: 1 }
  ];

  const nbCritiques = alertes.filter(a => a.type === "CRITIQUE").length;
  const nbHautes    = alertes.filter(a => a.type === "HAUTE").length;

  return (
    <div>
      {/* En-tête */}
      <div className="mb-8 pb-5 border-b border-border flex items-start
                      justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-gray-200">
            Security Operations Dashboard
          </h1>
          <p className="text-dim text-sm mt-1">
            Vue d'ensemble temps réel — PySecOps v3.0
          </p>
        </div>
        <div className="text-right">
          {lastUpdate && (
            <p className="text-dim text-xs">
              Mis à jour : {lastUpdate}
            </p>
          )}
          <button onClick={fetchData}
                  className="mt-1 text-xs text-cyber hover:underline">
            🔄 Rafraîchir
          </button>
        </div>
      </div>

      {/* Bannière alertes critiques */}
      {nbCritiques > 0 && (
        <div className="bg-danger/10 border border-danger/40 rounded-lg p-4
                        mb-6 flex items-center gap-3">
          <span className="text-2xl">🚨</span>
          <div>
            <p className="text-danger font-semibold">
              {nbCritiques} alerte(s) critique(s) nécessitent votre attention
            </p>
            <p className="text-danger/75 text-sm">
              Consultez les modules concernés ci-dessous.
            </p>
          </div>
        </div>
      )}

      {/* Stats principales */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <StatCard
          val={stats?.total || 0}
          label="Analyses totales"
          icon="📊"
        />
        <StatCard
          val={stats?.modules || 15}
          label="Modules actifs"
          color="text-success"
          icon="⚡"
        />
        <StatCard
          val={nbCritiques}
          label="Alertes critiques"
          color={nbCritiques > 0 ? "text-danger" : "text-success"}
          icon={nbCritiques > 0 ? "🚨" : "✅"}
        />
        <StatCard
          val={stats?.recon_scan || 0}
          label="Deep Recon"
          color="text-warning"
          icon="🎯"
        />
      </div>

      {/* Graphiques + Alertes */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">

        {/* Bar chart */}
        <div className="bg-card border border-border rounded-lg p-5">
          <div className="text-xs font-semibold text-dim uppercase
                          tracking-wider mb-5">
            Activité par module
          </div>
          {barData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={barData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
                <XAxis dataKey="nom"
                       tick={{fill:'#8b949e', fontSize:10}}
                       axisLine={{stroke:'#30363d'}} />
                <YAxis tick={{fill:'#8b949e', fontSize:10}}
                       axisLine={{stroke:'#30363d'}} />
                <Tooltip {...TOOLTIP_STYLE} />
                <Bar dataKey="val" fill="#58a6ff" radius={[4,4,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-48 flex items-center justify-center
                            text-dim text-sm text-center">
              <div>
                <p>Aucune donnée disponible</p>
                <p className="mt-1 text-xs">
                  Lancez des analyses pour voir les statistiques
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Pie chart répartition */}
        <div className="bg-card border border-border rounded-lg p-5">
          <div className="text-xs font-semibold text-dim uppercase
                          tracking-wider mb-5">
            Répartition des analyses
          </div>
          {(stats?.total || 0) > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} dataKey="val" nameKey="nom"
                     cx="50%" cy="50%" outerRadius={80}
                     label={({nom, percent}) =>
                       `${nom} ${(percent*100).toFixed(0)}%`
                     }
                     labelLine={false}>
                  {pieData.map((_, i) => (
                    <Cell key={i}
                          fill={PIE_COLORS[i % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip {...TOOLTIP_STYLE} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-48 flex items-center justify-center
                            text-dim text-sm">
              Aucune donnée disponible
            </div>
          )}
        </div>
      </div>

      {/* Alertes actionnables */}
      <div className="bg-card border border-border rounded-lg p-5 mb-8">
        <div className="text-xs font-semibold text-dim uppercase
                        tracking-wider mb-4 flex items-center gap-2">
          Alertes actionnables
          {nbCritiques > 0 && (
            <span className="bg-danger/20 text-danger text-xs px-2 py-0.5
                             rounded font-bold">
              {nbCritiques} CRITIQUE(S)
            </span>
          )}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {alertes.map((a, i) => (
            <AlertCard key={i} {...a} />
          ))}
        </div>
      </div>

      {/* Activité récente */}
      {(stats?.activites?.length || 0) > 0 && (
        <div className="bg-card border border-border rounded-lg p-5 mb-8">
          <div className="text-xs font-semibold text-dim uppercase
                          tracking-wider mb-4">
            Activité récente
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr>
                {["Module","Cible / Détail","Date","Heure"].map(h => (
                  <th key={h}
                      className="text-left pb-3 text-dim text-xs
                                 uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {stats.activites.slice(0, 10).map((a, i) => (
                <tr key={i}
                    className="border-t border-border hover:bg-cyber/5
                               transition-colors">
                  <td className="py-2.5">
                    <span className="bg-cyber/10 text-cyber text-xs
                                     px-2 py-0.5 rounded font-mono uppercase">
                      {a.module}
                    </span>
                  </td>
                  <td className="py-2.5 font-mono text-xs text-gray-400
                                 max-w-xs truncate">
                    {a.detail || "—"}
                  </td>
                  <td className="py-2.5 text-dim text-xs">{a.date}</td>
                  <td className="py-2.5 text-dim text-xs">{a.heure}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Accès rapide */}
      <div className="bg-card border border-border rounded-lg p-5">
        <div className="text-xs font-semibold text-dim uppercase
                        tracking-wider mb-4">
          Accès rapide
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {QUICK_ACCESS.map((item, i) => (
            <a key={i} href={item.url}
               className="flex items-center gap-3 p-3 border border-border
                          rounded-lg hover:border-cyber hover:bg-cyber/5
                          transition-all group">
              <span className="text-xl">{item.icon}</span>
              <div>
                <div className="text-sm text-gray-300 group-hover:text-white
                                font-medium transition-colors">
                  {item.label}
                </div>
                <div className="text-xs text-dim">{item.desc}</div>
              </div>
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}
