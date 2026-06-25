import React from "react";
import type { ScanDetail, DomainWhois } from "../App";

const fmtDate = (s?: string | null): string => {
  if (!s) return "—";
  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d.toLocaleString();
};

// A single label/value cell. Renders "Redacted" and empty values distinctly so an
// analyst can tell privacy-masking apart from a field that was never returned.
const Field: React.FC<{ label: string; value?: string | null; mono?: boolean }> = ({ label, value, mono }) => {
  const redacted = value === "Redacted";
  const empty = value == null || value === "";
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wide text-slate-500">{label}</div>
      <div
        className={
          empty
            ? "text-slate-600"
            : redacted
            ? "text-amber-400/80 italic"
            : `text-slate-200 ${mono ? "font-mono break-all" : ""}`
        }
      >
        {empty ? "—" : value}
      </div>
    </div>
  );
};

export const WhoisPanel: React.FC<{ scan: ScanDetail }> = ({ scan }) => {
  const w: DomainWhois | null | undefined = scan.whois;
  if (!w) return null;

  const sourceLabel = w.source === "rdap" ? "RDAP" : w.source === "whois43" ? "WHOIS :43" : "—";
  const addr = [w.registrant_street, w.registrant_city, w.registrant_state, w.registrant_postal_code, w.registrant_country]
    .filter(v => v && v !== "Redacted");
  const anyRegistrant = w.registrant_organization || w.registrant_street || w.registrant_city ||
    w.registrant_state || w.registrant_postal_code || w.registrant_country;

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 md:p-5">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-slate-200">Domain WHOIS</h3>
        <span className="px-2 py-0.5 rounded-full border border-slate-700 bg-slate-900 text-[10px] text-slate-400"
          title="Source: authoritative registry RDAP or port-43 WHOIS (no third-party API)">
          {sourceLabel}
        </span>
      </div>

      {w.error && (
        <p className="text-xs text-amber-400/80 mb-3">Lookup degraded: {w.error}</p>
      )}

      <div className="grid grid-cols-2 md:grid-cols-3 gap-x-6 gap-y-3 text-xs">
        <Field label="Domain Name" value={w.domain_name} mono />
        <Field label="Registry Domain ID" value={w.registry_domain_id} mono />
        <Field label="Registrar" value={w.registrar} />
        <Field label="Registrar IANA ID" value={w.registrar_iana_id} mono />
        <Field label="Registrar WHOIS Server" value={w.registrar_whois_server} mono />
        <Field label="Registrar URL" value={w.registrar_url} mono />
        <Field label="Creation Date" value={fmtDate(w.creation_date)} />
        <Field label="Updated Date" value={fmtDate(w.updated_date)} />
        <Field label="Expiration Date" value={fmtDate(w.expiration_date)} />
      </div>

      {/* Registrant block — usually GDPR-redacted for gTLDs; show it honestly. */}
      <div className="mt-4 pt-4 border-t border-slate-800/60">
        <div className="text-[11px] uppercase tracking-wide text-slate-500 mb-2">Registrant</div>
        {anyRegistrant ? (
          <div className="grid grid-cols-2 md:grid-cols-3 gap-x-6 gap-y-3 text-xs">
            <Field label="Organization" value={w.registrant_organization} />
            <Field label="Street" value={w.registrant_street} />
            <Field label="City" value={w.registrant_city} />
            <Field label="State/Province" value={w.registrant_state} />
            <Field label="Postal Code" value={w.registrant_postal_code} />
            <Field label="Country" value={w.registrant_country} />
          </div>
        ) : (
          <p className="text-xs text-slate-600">
            No registrant data published (privacy-protected under GDPR/ICANN policy for most gTLDs).
          </p>
        )}
        {addr.length > 0 && (
          <p className="mt-2 text-[11px] text-slate-500">Address: {addr.join(", ")}</p>
        )}
      </div>

      {(w.name_servers?.length || w.domain_status?.length) ? (
        <div className="mt-4 pt-4 border-t border-slate-800/60 grid md:grid-cols-2 gap-4">
          <div>
            <div className="text-[11px] uppercase tracking-wide text-slate-500 mb-2">Name Servers</div>
            {w.name_servers?.length ? (
              <ul className="space-y-1">
                {w.name_servers.map(ns => (
                  <li key={ns} className="font-mono text-xs text-slate-300 break-all">{ns}</li>
                ))}
              </ul>
            ) : <span className="text-xs text-slate-600">—</span>}
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wide text-slate-500 mb-2">Domain Status</div>
            {w.domain_status?.length ? (
              <div className="flex flex-wrap gap-1.5">
                {w.domain_status.map(s => (
                  <span key={s} className="px-2 py-0.5 rounded-full border border-slate-700 bg-slate-900 text-[10px] text-slate-300">{s}</span>
                ))}
              </div>
            ) : <span className="text-xs text-slate-600">—</span>}
          </div>
        </div>
      ) : null}
    </div>
  );
};
