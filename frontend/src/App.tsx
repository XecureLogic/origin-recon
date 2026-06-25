import React, { useEffect, useState, useCallback } from "react";
import { ScanForm } from "./components/ScanForm";
import { ScanResult } from "./components/ScanResult";

export type ScanStatus = {
  id: number; domain: string; status: string;
  created_at: string; completed_at: string; error?: string;
};
export type DnsRecord = {
  id?: number; type: string; name: string; value: string;
  ip?: string | null; priority?: number | null;
};
export type Subdomain = {
  id?: number; name: string; has_a_record: boolean;
  ip?: string | null; source?: string | null;
};
export type IPInfo = {
  ip: string; asn?: string | null; asn_name?: string | null; announced_asn?: string | null;
  country?: string | null; country_code?: string | null; org?: string | null;
  network?: string | null; services?: string | null; lat?: number | null; lng?: number | null;
  is_cdn?: boolean; high_risk?: boolean; reputation?: string | null; source?: string | null;
  registry?: string | null; network_name?: string | null; network_range?: string | null;
  abuse_email?: string | null; allocation_date?: string | null;
};
export type DomainWhois = {
  domain_name?: string | null; registry_domain_id?: string | null;
  registrar_whois_server?: string | null; registrar_url?: string | null;
  updated_date?: string | null; creation_date?: string | null; expiration_date?: string | null;
  registrar?: string | null; registrar_iana_id?: string | null;
  registrant_organization?: string | null; registrant_street?: string | null;
  registrant_city?: string | null; registrant_state?: string | null;
  registrant_postal_code?: string | null; registrant_country?: string | null;
  name_servers?: string[]; domain_status?: string[];
  source?: "rdap" | "whois43" | null; error?: string | null;
};
export type ScanDetail = ScanStatus & {
  edge_masked: "yes" | "no" | "unknown";
  edge_org?: string | null;
  verdict: "malicious" | "suspicious" | "clean" | "unknown";
  verdict_reasons: string[];
  whois?: DomainWhois | null;
  records: DnsRecord[]; subdomains: Subdomain[]; ips: IPInfo[];
  origin_candidates: IPInfo[]; notes?: string[];
};
export type EnrichConfig = { ipinfo: boolean; securitytrails: boolean; virustotal: boolean; abusech: boolean };
export type HistoryItem = {
  id: number; domain: string; verdict: string; edge_masked: string;
  created_at: string; host_count: number; known_bad: number;
};
export type BulkRow = {
  id?: number; domain: string; verdict: string; edge_masked?: string;
  host_count?: number; known_bad?: number; error?: string;
};
type SessionItem = { domain: string; verdict: string; detail?: ScanDetail; histId?: number };

export const API_BASE = (import.meta as any).env?.VITE_API_BASE || "http://localhost:8000";

const VERDICT_CHIP: Record<string, string> = {
  malicious: "border-red-700 bg-red-950/50 text-red-300",
  suspicious: "border-orange-700 bg-orange-950/40 text-orange-300",
  clean: "border-emerald-800 bg-emerald-950/40 text-emerald-300",
  unknown: "border-slate-700 bg-slate-900 text-slate-400",
  error: "border-slate-700 bg-slate-900 text-slate-500",
};

const App: React.FC = () => {
  const [currentScan, setCurrentScan] = useState<ScanDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [cfg, setCfg] = useState<EnrichConfig | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);   // persisted, shown in drawer
  const [session, setSession] = useState<SessionItem[]>([]);   // this run only, shown as chips
  const [bulk, setBulk] = useState<BulkRow[] | null>(null);
  const [drawer, setDrawer] = useState(false);
  const [histQuery, setHistQuery] = useState("");

  const loadHistory = useCallback(() => {
    fetch(`${API_BASE}/api/history?limit=200`).then(r => r.json())
      .then(d => setHistory(d.scans || [])).catch(() => {});
  }, []);

  useEffect(() => {
    fetch(`${API_BASE}/api/config`).then(r => r.json()).then(setCfg).catch(() => setCfg(null));
    loadHistory();
  }, [loadHistory]);

  const startScan = async (domain: string) => {
    setLoading(true); setCurrentScan(null); setBulk(null);
    try {
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });
      if (!res.ok) { const d = await res.json().catch(() => ({})); alert(`Scan failed: ${d.detail || res.statusText}`); return; }
      const scan: ScanDetail = await res.json();
      setCurrentScan(scan);
      setSession(prev => [{ domain: scan.domain, verdict: scan.verdict, detail: scan }, ...prev]);
      loadHistory();
    } catch (e) { console.error(e); alert("Error contacting the API. Is the backend running on :8000?"); }
    finally { setLoading(false); }
  };

  const startBulk = async (domains: string[]) => {
    setLoading(true); setCurrentScan(null); setBulk(null);
    try {
      const res = await fetch(`${API_BASE}/api/scan/bulk`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domains }),
      });
      const d = await res.json();
      const rows: BulkRow[] = d.results || [];
      setBulk(rows);
      setSession(prev => [
        ...rows.map(r => ({ domain: r.domain, verdict: r.verdict, histId: r.id })),
        ...prev,
      ]);
      loadHistory();
    } catch (e) { console.error(e); alert("Bulk scan failed."); }
    finally { setLoading(false); }
  };

  const recall = async (id: number) => {
    try {
      const res = await fetch(`${API_BASE}/api/history/${id}`);
      if (!res.ok) return;
      setBulk(null); setCurrentScan(await res.json());
      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch { /* ignore */ }
  };

  const openSession = (item: SessionItem) => {
    if (item.detail) { setBulk(null); setCurrentScan(item.detail); window.scrollTo({ top: 0, behavior: "smooth" }); }
    else if (item.histId) recall(item.histId);
  };

  const removeHistory = async (id: number) => {
    try { await fetch(`${API_BASE}/api/history/${id}`, { method: "DELETE" }); loadHistory(); } catch { /* ignore */ }
  };

  const exportIocs = async () => {
    if (!currentScan) return;
    try {
      const res = await fetch(`${API_BASE}/api/iocs`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: currentScan.domain }),
      });
      const csv = await res.text();
      downloadBlob(csv, `iocs_${currentScan.domain}.csv`, "text/csv");
    } catch (e) { console.error(e); alert("IOC export failed."); }
  };

  const exportFeed = (kind: "stix" | "misp") => {
    if (!currentScan) return;
    const a = document.createElement("a");
    a.href = `${API_BASE}/api/export/${kind}?domain=${encodeURIComponent(currentScan.domain)}`;
    a.click();
  };

  const filteredHistory = history.filter(h => h.domain.toLowerCase().includes(histQuery.trim().toLowerCase()));

  return (
    <div className="min-h-screen flex flex-col items-center px-4 py-10">
      <button onClick={() => setDrawer(true)}
        className="fixed top-4 right-4 z-30 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 border border-slate-700">
        History {history.length > 0 && <span className="text-slate-400">({history.length})</span>}
      </button>

      <div className="w-full max-w-6xl">
        <header className="mb-8 text-center">
          <h1 className="text-3xl font-bold mb-3">Origin Recon</h1>
          <p className="text-[14px] text-slate-400 max-w-2xl mx-auto">
            Passive DNS &amp; origin-infrastructure recon. Enumerates records and subdomains,
            geo-locates resolved hosts, classifies CDN edge vs. real origin, and flags
            bulletproof ASNs and known-bad infrastructure.
          </p>
          {cfg && (
            <div className="mt-3 flex flex-wrap justify-center gap-2 text-[11px]">
              <Cap on={cfg.ipinfo} label="ipinfo geo" />
              <Cap on={cfg.securitytrails} label="SecurityTrails" />
              <Cap on={cfg.virustotal} label="VirusTotal" />
              <Cap on={cfg.abusech} label="abuse.ch" />
            </div>
          )}
        </header>

        <ScanForm onSubmit={startScan} onBulk={startBulk} loading={loading} />

        {session.length > 0 && (
          <div className="mt-5 rounded-xl border border-slate-800 bg-slate-900/40 p-3">
            <div className="text-[11px] uppercase tracking-wide text-slate-500 mb-2">This session</div>
            <div className="flex flex-wrap gap-2">
              {session.map((s, i) => (
                <button key={`${s.domain}-${i}`} onClick={() => openSession(s)}
                  className={`inline-flex items-center px-2 py-1 rounded-lg border text-[11px] font-mono hover:brightness-125 ${VERDICT_CHIP[s.verdict] || VERDICT_CHIP.unknown}`}
                  title={s.verdict}>
                  {s.domain}
                </button>
              ))}
            </div>
          </div>
        )}

        <main className="mt-8">
          {loading && (
            <div className="flex flex-col items-center gap-3 mt-4">
              <p className="text-slate-300 text-sm">Running recon…</p>
              <div className="w-full flex justify-center">
                <div className="w-1/2 max-w-sm">
                  <div className="h-1.5 rounded-full bg-slate-900 overflow-hidden border border-slate-800">
                    <div className="scan-progress-bar h-full w-1/2 bg-sky-500/70" />
                  </div>
                </div>
              </div>
            </div>
          )}

          {!loading && bulk && <BulkResults rows={bulk} onRecall={recall} />}

          {!loading && !bulk && currentScan ? (
            <ScanResult scan={currentScan} onExportIocs={exportIocs} onExportFeed={exportFeed} />
          ) : !loading && !bulk ? (
            <p className="text-slate-500 text-center">Run a scan to map records, hosts, origins and locations.</p>
          ) : null}
        </main>

        <footer className="mt-12 pt-5 border-t border-slate-800/60 text-center">
          <p className="text-[11px] text-slate-500">
            Origin Recon — built by{" "}
            <a href="https://xecurelogic.com" target="_blank" rel="noopener noreferrer"
              className="text-slate-300 hover:text-sky-400 underline underline-offset-2">
              XecureLogic
            </a>{" "}
            · xecurelogic.com
          </p>
        </footer>
      </div>

      {/* History drawer */}
      {drawer && (
        <div className="fixed inset-0 z-40">
          <div className="absolute inset-0 bg-black/50" onClick={() => setDrawer(false)} />
          <aside className="absolute right-0 top-0 h-full w-full max-w-md bg-slate-950 border-l border-slate-800 p-4 overflow-y-auto">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-slate-200">History ({history.length})</h2>
              <button onClick={() => setDrawer(false)} className="text-slate-400 hover:text-slate-200 text-lg leading-none">×</button>
            </div>
            <input value={histQuery} onChange={e => setHistQuery(e.target.value)} placeholder="Filter by domain…"
              className="w-full mb-3 rounded-lg bg-slate-900 border border-slate-700 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-sky-500" />
            {filteredHistory.length === 0 ? (
              <p className="text-xs text-slate-500">No matching scans.</p>
            ) : (
              <ul className="space-y-2">
                {filteredHistory.map(h => (
                  <li key={h.id} className="flex items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2">
                    <button onClick={() => { recall(h.id); setDrawer(false); }} className="flex-1 text-left min-w-0">
                      <div className="font-mono text-xs text-slate-200 truncate">{h.domain}</div>
                      <div className="text-[10px] text-slate-500">{new Date(h.created_at).toLocaleString()} · {h.host_count} hosts · {h.known_bad} known-bad</div>
                    </button>
                    <span className={`px-2 py-0.5 rounded-full border text-[10px] whitespace-nowrap ${VERDICT_CHIP[h.verdict] || VERDICT_CHIP.unknown}`}>{(h.verdict || "unknown").toUpperCase()}</span>
                    <button onClick={() => removeHistory(h.id)} className="text-slate-600 hover:text-red-400 text-sm" title="Delete">×</button>
                  </li>
                ))}
              </ul>
            )}
          </aside>
        </div>
      )}
    </div>
  );
};

const BulkResults: React.FC<{ rows: BulkRow[]; onRecall: (id: number) => void }> = ({ rows, onRecall }) => (
  <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 md:p-5">
    <h2 className="text-sm font-semibold text-slate-200 mb-3">Bulk results ({rows.length})</h2>
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead className="text-slate-400 border-b border-slate-800">
          <tr><th className="text-left py-2">Domain</th><th className="text-left">Verdict</th><th className="text-left">Hosts</th><th className="text-left">Known-bad</th><th></th></tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="border-b border-slate-900">
              <td className="py-2 font-mono text-slate-200">{r.domain}</td>
              <td><span className={`px-2 py-0.5 rounded-full border text-[10px] ${VERDICT_CHIP[r.verdict] || VERDICT_CHIP.unknown}`}>{(r.verdict || "unknown").toUpperCase()}</span></td>
              <td className="font-mono text-slate-300">{r.host_count ?? "-"}</td>
              <td className="font-mono text-slate-300">{r.known_bad ?? "-"}</td>
              <td className="text-right">{r.id ? <button onClick={() => onRecall(r.id!)} className="text-sky-400 hover:underline">open</button> : r.error ? <span className="text-slate-500" title={r.error}>error</span> : null}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  </div>
);

const Cap: React.FC<{ on: boolean; label: string }> = ({ on, label }) => (
  <span className={`px-2 py-0.5 rounded-full border ${on ? "border-emerald-700 bg-emerald-900/30 text-emerald-300" : "border-slate-700 bg-slate-900 text-slate-500"}`}>
    {on ? "●" : "○"} {label}
  </span>
);

function downloadBlob(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

export default App;
