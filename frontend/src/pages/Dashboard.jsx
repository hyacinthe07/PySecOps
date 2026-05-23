import { useState, useEffect } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

function StatCard({ val, label, color }) {
  return (
    <div className="bg-card border border-border rounded-lg p-5 text-center hover:border-cyber/50 transition-colors">
      <div className={`text-3xl font-bold ${color || "text-cyber"}`}>{val}</div>
      <div className="text-dim text-xs uppercase tracking-wider mt-1">{label}</div>
    </div>
  );
}

function AlertCard({ type, msg, action }) {
  const styles = {
    CRITIQUE: "border-danger/40 bg-danger/5 text-danger",
    HAUTE:    "border-warning/40 bg-warning/5 text-warning",
    INFO:     "border-cyber/40 bg-cyber/5 text-cyber",
    OK:       "border-success/40 bg-success/5 text-success",
  };
  return (
    <div className={`border rounded-lg p-4 ${styles[type] || styles.INFO}`}>
      <div className="font-semibold text-sm">{msg}</div>
      {action && <div className="text-xs mt-1 opacity-75">→ {action}</div>}
    </div>
  );
}

const QUICK_ACCESS = [
  { label: "Deep Recon",      icon: "🎯", url: "/recon/scan", desc: "CVE + fingerprinting" },
  { label: "IDS Forensique",  icon: "🛡", url: "/ids",        desc: "17 signatures d'attaque" },
  { label: "Rapport PTES",    icon: "📋", url: "/audit",      desc: "PDF professionnel" },
  { label: "OSINT Engine",    icon: "🕵", url: "/osint",      desc: "Emails, Dorks, Shodan" },
  { label: "Threat Intel",    icon: "🚨", url: "/threat",     desc: "Réputation IP/domaine" },
  { label: "Web Audit",       icon: "◇",  url: "/owasp",      desc: "SQLi, XSS, LFI réels" },
  { label: "SSL Scanner",     icon: "🔐", url: "/secops/ssl", desc: "Certificat + alertes" },
  { label: "Assistant IA",    icon: "🤖", url: "/assistant",  desc: "Questions cybersécurité" },
];

export default function Dashboard() {
  const [stats,   setStats]   = useState(null);
  const [loading, setLoading] = useState(true);
  const [erreur,  setErreur]  = useState(null);

  useEffect(() => {
    fetch("/api/v1/stats")
      .then(r => { if (!r.ok) throw new Error("API indisponible"); return r.json(); })
      .then(d => { setStats(d); setLoading(false); })
      .catch(e => { setErreur(e.message); setLoading(false); });
  }, []);

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <div className="text-cyber animate-pulse text-lg font-mono">Chargement du dashboard...</div>
    </div>
  );

  if (erreur) return (
    <div className="bg-danger/10 border border-danger/30 rounded-lg p-6 text-danger">
      <p className="font-semibold">Erreur API : {erreur}</p>
      <p className="text-sm mt-1 opacity-75">Vérifiez que Flask tourne sur le port 8080.</p>
    </div>
  );

  const chartData = [
    { nom: "Ports",  val: stats?.ports      || 0 },
    { nom: "OWASP",  val: stats?.owasp      || 0 },
    { nom: "Recon",  val: stats?.recon_scan || 0 },
    { nom: "IDS",    val: stats?.ids        || 0 },
    { nom: "OSINT",  val: (stats?.osint_emails||0)+(stats?.osint_dorks||0) },
    { nom: "Threat", val: stats?.threat     || 0 },
  ];

  const alertes = [];
  if ((stats?.owasp      ||0)>0) alertes.push({type:"CRITIQUE", msg:`${stats.owasp} audit(s) web`,      action:"Vérifier les vulnérabilités détectées"});
  if ((stats?.ids        ||0)>0) alertes.push({type:"HAUTE",    msg:`${stats.ids} analyse(s) IDS`,       action:"Consulter la timeline d'attaque"});
  if ((stats?.ports      ||0)>0) alertes.push({type:"INFO",     msg:`${stats.ports} scan(s) de ports`,   action:"Vérifier les services dangereux"});
  if ((stats?.recon_scan ||0)>0) alertes.push({type:"INFO",     msg:`${stats.recon_scan} Deep Recon`,    action:"Consulter les CVEs détectées"});
  if (alertes.length===0)        alertes.push({type:"OK",       msg:"Aucune analyse effectuée",          action:"Lancez un scan depuis n'importe quel module"});

  return (
    <div>
      <div className="mb-8 pb-5 border-b border-border">
        <h1 className="text-2xl font-semibold text-gray-200">Security Operations Dashboard</h1>
        <p className="text-dim text-sm mt-1">Vue d'ensemble temps réel — PySecOps v3.0</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <StatCard val={stats?.total      ||0} label="Analyses totales" />
        <StatCard val={stats?.modules    ||15} label="Modules actifs"  color="text-success" />
        <StatCard val={stats?.recon_scan ||0}  label="Deep Recon"      color="text-warning" />
        <StatCard val={stats?.ids        ||0}  label="Analyses IDS"    color="text-purple" />
      </div>

      {/* Graphique + Alertes */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <div className="bg-card border border-border rounded-lg p-5">
          <div className="text-xs font-semibold text-dim uppercase tracking-wider mb-5">Activité par module</div>
          {(stats?.total||0)>0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
                <XAxis dataKey="nom" tick={{fill:'#8b949e',fontSize:10}} axisLine={{stroke:'#30363d'}} />
                <YAxis tick={{fill:'#8b949e',fontSize:10}} axisLine={{stroke:'#30363d'}} />
                <Tooltip contentStyle={{background:'#161b22',border:'1px solid #30363d',borderRadius:'6px',color:'#c9d1d9',fontSize:'12px'}} />
                <Bar dataKey="val" fill="#58a6ff" radius={[4,4,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-48 flex items-center justify-center text-dim text-sm">
              Lancez des analyses pour voir les graphiques
            </div>
          )}
        </div>

        <div className="bg-card border border-border rounded-lg p-5">
          <div className="text-xs font-semibold text-dim uppercase tracking-wider mb-5">Alertes actionnables</div>
          <div className="flex flex-col gap-3">
            {alertes.map((a,i) => <AlertCard key={i} {...a} />)}
          </div>
        </div>
      </div>

      {/* Activité récente */}
      {(stats?.activites?.length||0)>0 && (
        <div className="bg-card border border-border rounded-lg p-5 mb-8">
          <div className="text-xs font-semibold text-dim uppercase tracking-wider mb-4">Activité récente</div>
          <table className="w-full text-sm">
            <thead>
              <tr>{["Module","Cible / Détail","Date","Heure"].map(h=>(
                <th key={h} className="text-left pb-3 text-dim text-xs uppercase tracking-wider">{h}</th>
              ))}</tr>
            </thead>
            <tbody>
              {stats.activites.slice(0,10).map((a,i)=>(
                <tr key={i} className="border-t border-border hover:bg-cyber/5 transition-colors">
                  <td className="py-2.5">
                    <span className="bg-cyber/10 text-cyber text-xs px-2 py-0.5 rounded font-mono uppercase">{a.module}</span>
                  </td>
                  <td className="py-2.5 font-mono text-xs text-gray-400 max-w-xs truncate">{a.detail||"—"}</td>
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
        <div className="text-xs font-semibold text-dim uppercase tracking-wider mb-4">Accès rapide</div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {QUICK_ACCESS.map((item,i)=>(
            <a key={i} href={item.url}
               className="flex items-center gap-3 p-3 border border-border rounded-lg hover:border-cyber hover:bg-cyber/5 transition-all group">
              <span className="text-xl">{item.icon}</span>
              <div>
                <div className="text-sm text-gray-300 group-hover:text-white font-medium">{item.label}</div>
                <div className="text-xs text-dim">{item.desc}</div>
              </div>
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}
