import React, { useMemo } from "react";
import type { ScanDetail } from "../App";
import { GeoMap } from "./GeoMap";

type Props = { scan: ScanDetail };

const flagUrl = (code: string) => `https://flagcdn.com/16x12/${code.toLowerCase()}.png`;

export const SystemLocations: React.FC<Props> = ({ scan }) => {
  const ips = scan.ips || [];

  const countryCodes = useMemo(() => {
    const set = new Set<string>();
    ips.forEach((ip) => {
      const c = (ip.country_code || ip.country || "").trim();
      if (/^[A-Za-z]{2}$/.test(c)) set.add(c.toUpperCase());
    });
    return Array.from(set).sort();
  }, [ips]);

  const hostingEntries = useMemo(() => {
    const map = new Map<string, number>();
    ips.forEach((ip) => {
      const key = String(ip.asn_name || ip.org || "UNKNOWN").toUpperCase().trim();
      map.set(key, (map.get(key) || 0) + 1);
    });
    return Array.from(map.entries()).sort((a, b) => b[1] - a[1]);
  }, [ips]);

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 md:p-5">
      <div className="flex flex-col lg:flex-row gap-6">
        <div className="lg:flex-[2] flex flex-col">
          <h3 className="font-semibold mb-3 text-sm uppercase tracking-wide text-slate-300">System Locations</h3>
          <GeoMap ips={ips} />
          <div className="mt-2 flex flex-wrap gap-2 text-[11px] text-slate-300">
            {countryCodes.length ? (
              countryCodes.map((c) => (
                <span key={c} className="px-2 py-0.5 rounded-full bg-slate-800/80 border border-slate-700 flex items-center gap-1">
                  <img src={flagUrl(c)} alt={c} className="h-3 w-4 rounded-sm" />
                  {c}
                </span>
              ))
            ) : (
              <span className="text-slate-500">No country data for resolved IPs.</span>
            )}
          </div>
        </div>

        <div className="lg:flex-1 flex flex-col gap-4">
          <div className="flex flex-col">
            <h3 className="font-semibold mb-3 text-sm uppercase tracking-wide text-slate-300">Hosting / Networks</h3>
            <div className="rounded-xl border border-slate-800 bg-slate-950 p-3">
              {hostingEntries.length ? (
                <div className="space-y-3 text-xs">
                  {hostingEntries.slice(0, 6).map(([name, count]) => {
                    const max = hostingEntries[0][1] || 1;
                    return (
                      <div key={name} className="flex items-center gap-3">
                        <div className="w-32 text-[11px] text-slate-300 truncate" title={name}>{name}</div>
                        <div className="flex-1">
                          <div className="h-4 rounded bg-sky-900/50 border border-sky-800" style={{ width: 30 + (count / max) * 120 }} />
                        </div>
                        <div className="w-6 text-right text-slate-400 text-[11px]">{count}</div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <p className="text-xs text-slate-500">No ASN / hosting metadata available yet.</p>
              )}
            </div>
          </div>

          <div className="flex flex-col">
            <h3 className="font-semibold mb-3 text-sm uppercase tracking-wide text-slate-300">Risk Summary</h3>
            <div className="rounded-xl border border-slate-800 bg-slate-950 p-3 space-y-2 text-xs">
              <Stat label="Hosts resolved" value={ips.length} />
              <Stat label="On CDN edge" value={ips.filter((i) => i.is_cdn).length} />
              <Stat label="High-risk ASN" value={ips.filter((i) => i.high_risk).length} danger />
              <Stat label="Known-bad (abuse.ch)" value={ips.filter((i) => i.reputation).length} danger />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const Stat: React.FC<{ label: string; value: number; danger?: boolean }> = ({ label, value, danger }) => (
  <div className="flex items-center justify-between">
    <span className="text-slate-400">{label}</span>
    <span className={`font-mono ${danger && value > 0 ? "text-red-400" : "text-slate-200"}`}>{value}</span>
  </div>
);
