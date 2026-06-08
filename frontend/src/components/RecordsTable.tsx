import React, { useMemo } from "react";
import type { ScanDetail, DnsRecord, IPInfo } from "../App";

type Props = { scan: ScanDetail };

export const RecordsTable: React.FC<Props> = ({ scan }) => {
  const records = scan.records || [];
  const ips = scan.ips || [];
  const ipIndex = useMemo(() => new Map<string, IPInfo>(ips.map((i) => [i.ip, i])), [ips]);
  const byType = (t: string) => records.filter((r) => r.type === t || (t === "A" && r.type === "AAAA"));
  return (
    <div className="space-y-6">
      <Section title="A Records" color="text-emerald-300" records={byType("A")} ipIndex={ipIndex} showIp />
      <Section title="MX Records" color="text-sky-300" records={byType("MX")} ipIndex={ipIndex} showIp showPriority />
      <Section title="NS Records" color="text-violet-300" records={byType("NS")} ipIndex={ipIndex} showIp />
      <Generic title="TXT Records" color="text-amber-300" records={byType("TXT")} />
      <Generic title="SOA Records" color="text-rose-300" records={byType("SOA")} />
    </div>
  );
};

type SectionProps = {
  title: string; color: string; records: DnsRecord[];
  ipIndex: Map<string, IPInfo>; showIp?: boolean; showPriority?: boolean;
};

const Section: React.FC<SectionProps> = ({ title, color, records, ipIndex, showIp, showPriority }) => {
  if (!records.length) return null;
  return (
    <section>
      <h3 className={`text-sm font-semibold mb-2 ${color}`}>{title}</h3>
      <div className="overflow-x-auto text-xs rounded-xl border border-slate-800 bg-slate-950">
        <table className="min-w-full border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400">
              <th className="py-2 px-3 text-left">Host</th>
              {showIp && <th className="py-2 px-3 text-left">IP</th>}
              <th className="py-2 px-3 text-left">ASN</th>
              <th className="py-2 px-3 text-left">ASN Name</th>
              <th className="py-2 px-3 text-left">Announced (Cymru)</th>
              <th className="py-2 px-3 text-left">Risk</th>
              {showPriority && <th className="py-2 px-3 text-left">Priority</th>}
            </tr>
          </thead>
          <tbody>
            {records.map((r, idx) => {
              const ip = (r.ip || (r.type === "A" ? r.value : undefined) || "") as string;
              const meta = ipIndex.get(ip);
              return (
                <tr key={`${r.type}-${r.name}-${idx}`} className="border-b border-slate-900 align-top">
                  <td className="py-2 px-3 text-slate-100 font-mono">
                    {r.name || "-"}
                    <div className="text-slate-500 text-[11px]">{r.type !== "A" ? r.value : ""}</div>
                  </td>
                  {showIp && <td className="py-2 px-3 font-mono text-slate-200">{ip || "-"}</td>}
                  <td className="py-2 px-3 text-slate-200">{meta?.asn ? `AS${meta.asn}` : "-"}</td>
                  <td className="py-2 px-3 text-slate-200">{meta?.asn_name || meta?.org || "-"}</td>
                  <td className="py-2 px-3 text-slate-300">{meta?.announced_asn || "-"}</td>
                  <td className="py-2 px-3">
                    {meta?.reputation ? (
                      <span className="text-red-400" title={meta.reputation}>known-bad</span>
                    ) : meta?.high_risk ? (
                      <span className="text-orange-400">high-risk</span>
                    ) : meta?.is_cdn ? (
                      <span className="text-sky-400">cdn</span>
                    ) : (
                      <span className="text-slate-500">-</span>
                    )}
                  </td>
                  {showPriority && <td className="py-2 px-3 text-slate-200">{r.priority ?? "-"}</td>}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
};

const Generic: React.FC<{ title: string; color: string; records: DnsRecord[] }> = ({ title, color, records }) =>
  !records.length ? null : (
    <section>
      <h3 className={`text-sm font-semibold mb-2 ${color}`}>{title}</h3>
      <div className="overflow-x-auto text-xs rounded-xl border border-slate-800 bg-slate-950">
        <table className="min-w-full border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400">
              <th className="py-2 px-3 text-left">Name</th>
              <th className="py-2 px-3 text-left">Value</th>
            </tr>
          </thead>
          <tbody>
            {records.map((r, idx) => (
              <tr key={`${r.type}-${idx}`} className="border-b border-slate-900">
                <td className="py-2 px-3 text-slate-100 font-mono">{r.name}</td>
                <td className="py-2 px-3 text-slate-300 font-mono text-[11px] break-all">{r.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
