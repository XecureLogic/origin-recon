import React, { useState } from "react";
import type { ScanDetail, IPInfo } from "../App";
import { API_BASE } from "../App";

type Props = { scan: ScanDetail };

// Defang for safe display / copy into tickets and chat.
const defang = (s: string) =>
  (s || "").replace(/^https:/i, "hxxps:").replace(/^http:/i, "hxxp:").replace(/\./g, "[.]");

const Copy: React.FC<{ text: string; label: string }> = ({ text, label }) => {
  const [done, setDone] = useState(false);
  return (
    <button
      onClick={async () => { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1200); }}
      className="px-1.5 py-0.5 rounded text-[10px] border border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-300"
      title={`Copy ${label}`}
    >
      {done ? "copied" : label}
    </button>
  );
};

const VERDICT_STYLE: Record<string, { label: string; c: string }> = {
  malicious: { label: "MALICIOUS", c: "border-red-600 bg-red-950/50 text-red-300" },
  suspicious: { label: "SUSPICIOUS", c: "border-orange-600 bg-orange-950/40 text-orange-300" },
  clean: { label: "NO MALICIOUS SIGNALS", c: "border-emerald-700 bg-emerald-950/40 text-emerald-300" },
  unknown: { label: "INCONCLUSIVE", c: "border-slate-600 bg-slate-900 text-slate-300" },
};

const CandidateRow: React.FC<{ ip: IPInfo; domain: string }> = ({ ip, domain }) => {
  const [probe, setProbe] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const confirm = async () => {
    if (!window.confirm(`Actively probe ${ip.ip} with a spoofed Host header for ${domain}?\n\nThis sends one HTTP request directly to the candidate — the first active touch of target infrastructure.`)) return;
    setBusy(true); setProbe(null);
    try {
      const res = await fetch(`${API_BASE}/api/confirm-origin`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, ip: ip.ip }),
      });
      const j = await res.json();
      if (!j.ok) setProbe(j.error || "probe refused");
      else setProbe(`${j.confirmed ? "CONFIRMED" : "not confirmed"} — ${j.detail}`);
    } catch { setProbe("probe failed"); }
    finally { setBusy(false); }
  };

  return (
    <div className="flex flex-col gap-1 rounded-lg border border-slate-800 bg-slate-950 p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-slate-100">{defang(ip.ip)}</span>
        <div className="flex items-center gap-1">
          <Copy text={ip.ip} label="copy" />
          <Copy text={defang(ip.ip)} label="defanged" />
          {ip.high_risk && <span className="px-1.5 py-0.5 rounded text-[10px] bg-orange-900/40 border border-orange-700 text-orange-300">HIGH-RISK ASN</span>}
          {ip.reputation && <span className="px-1.5 py-0.5 rounded text-[10px] bg-red-900/40 border border-red-700 text-red-300">KNOWN-BAD</span>}
        </div>
      </div>
      <div className="text-[11px] text-slate-400">{ip.org || ip.asn_name || "unknown ASN"} {ip.country ? `· ${ip.country}` : ""}</div>
      {ip.announced_asn && ip.announced_asn !== (ip.asn_name || "") && (
        <div className="text-[11px] text-slate-500">announced as {ip.announced_asn}</div>
      )}
      {ip.reputation && <div className="text-[11px] text-red-300">{ip.reputation}</div>}
      <div className="flex items-center justify-between mt-1">
        <span className="text-[10px] text-slate-600">via {ip.source || "live"}</span>
        <button onClick={confirm} disabled={busy}
          className="px-1.5 py-0.5 rounded text-[10px] border border-sky-800 bg-sky-950/40 hover:bg-sky-900/40 text-sky-300 disabled:opacity-50">
          {busy ? "probing…" : "Confirm origin"}
        </button>
      </div>
      {probe && <div className={`text-[10px] mt-1 ${probe.startsWith("CONFIRMED") ? "text-emerald-300" : "text-slate-400"}`}>{probe}</div>}
    </div>
  );
};

export const Verdict: React.FC<Props> = ({ scan }) => {
  const candidates = scan.origin_candidates || [];
  const v = VERDICT_STYLE[scan.verdict] || VERDICT_STYLE.unknown;
  const [uh, setUh] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [submitUrl, setSubmitUrl] = useState(`http://${scan.domain}/`);
  const [submitMsg, setSubmitMsg] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const checkUrlhaus = async () => {
    setChecking(true); setUh(null);
    try {
      const res = await fetch(`${API_BASE}/api/report/urlhaus-check`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ value: scan.domain }),
      });
      const j = await res.json();
      if (j.enabled === false) setUh("abuse.ch key not set");
      else if (j.known) setUh(`KNOWN to URLhaus — ${j.threat || "listed"}${j.url_count ? ` (${j.url_count} URL(s))` : ""}`);
      else if (j.error) setUh(`error: ${j.error}`);
      else setUh("not currently listed in URLhaus");
    } catch { setUh("lookup failed"); }
    finally { setChecking(false); }
  };

  const submitUrlhaus = async () => {
    const url = submitUrl.trim();
    if (!url) return;
    if (!window.confirm(`Submit to URLhaus:\n\n${url}\n\nThis is a PUBLIC report under your abuse.ch account. Only submit URLs actively serving malware. Continue?`)) return;
    setSubmitting(true); setSubmitMsg(null);
    try {
      const res = await fetch(`${API_BASE}/api/report/urlhaus-submit`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, threat: "malware_download" }),
      });
      const j = await res.json();
      if (j.enabled === false) setSubmitMsg("abuse.ch key not set");
      else if (j.ok) setSubmitMsg(`submitted (HTTP ${j.http_status}) — ${JSON.stringify(j.response).slice(0, 200)}`);
      else setSubmitMsg(`failed: ${j.error || JSON.stringify(j.response).slice(0, 200)}`);
    } catch { setSubmitMsg("submit failed"); }
    finally { setSubmitting(false); }
  };

  return (
    <div className="space-y-3">
      <div className={`rounded-2xl border p-4 md:p-5 ${v.c}`}>
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <span className="text-lg font-bold tracking-wide">{v.label}</span>
            <span className="text-xs opacity-70 font-mono">{defang(scan.domain)}</span>
          </div>
          <button onClick={checkUrlhaus} disabled={checking}
            className="px-2.5 py-1 rounded-lg text-xs border border-current/40 bg-black/20 hover:bg-black/40 disabled:opacity-50">
            {checking ? "checking…" : "Check URLhaus"}
          </button>
        </div>
        {scan.verdict_reasons?.length > 0 && (
          <ul className="mt-2 space-y-0.5">
            {scan.verdict_reasons.map((r, i) => <li key={i} className="text-xs opacity-90">• {r}</li>)}
          </ul>
        )}
        {uh && <div className="mt-2 text-xs font-mono opacity-90">URLhaus: {uh}</div>}

        {/* Contribute back: gated public submission */}
        <div className="mt-3 pt-3 border-t border-current/20 flex flex-col sm:flex-row gap-2 sm:items-center">
          <input value={submitUrl} onChange={(e) => setSubmitUrl(e.target.value)}
            className="flex-1 rounded-lg bg-black/30 border border-current/30 px-2 py-1 text-xs font-mono text-current placeholder:opacity-50 focus:outline-none"
            placeholder="full malware URL to report" />
          <button onClick={submitUrlhaus} disabled={submitting}
            className="px-2.5 py-1 rounded-lg text-xs border border-current/40 bg-black/20 hover:bg-black/40 disabled:opacity-50 whitespace-nowrap">
            {submitting ? "submitting…" : "Submit to URLhaus"}
          </button>
        </div>
        {submitMsg && <div className="mt-1 text-[11px] font-mono opacity-90 break-all">{submitMsg}</div>}
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 md:p-5">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-slate-200">Edge / Origin</h3>
          <span className="px-2 py-0.5 rounded-full border text-[11px] border-slate-700 bg-slate-900 text-slate-300">
            {scan.edge_masked === "yes" ? "CDN edge — origin masked" : scan.edge_masked === "no" ? "Direct host — origin exposed" : "edge unknown"}
          </span>
        </div>
        <p className="text-xs text-slate-400 mb-3">
          {scan.edge_masked === "yes"
            ? `Public DNS resolves to ${scan.edge_org || "a CDN"}; the real origin is hidden. Candidates below come from passive DNS / off-CDN leaks.`
            : scan.edge_masked === "no"
            ? `Public DNS resolves directly to ${scan.edge_org || "the host"} — no CDN in front.`
            : "Could not determine edge status (no A record resolved)."}
        </p>
        {candidates.length ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {candidates.map((ip, i) => <CandidateRow key={`${ip.ip}-${i}`} ip={ip} domain={scan.domain} />)}
          </div>
        ) : (
          <p className="text-xs text-slate-500">No origin candidates surfaced.</p>
        )}
        {scan.notes && scan.notes.length > 0 && (
          <ul className="mt-3 space-y-1">
            {scan.notes.map((n, i) => <li key={i} className="text-[11px] text-amber-300/80">• {n}</li>)}
          </ul>
        )}
        <p className="mt-3 text-[10px] text-slate-600">Reminder: shared-hosting co-location is low-confidence; verify before attribution.</p>
      </div>
    </div>
  );
};
