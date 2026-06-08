import React, { useMemo } from "react";
import { geoNaturalEarth1, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import worldTopo from "../assets/countries-110m.json";
import type { IPInfo } from "../App";

type Props = { ips: IPInfo[]; width?: number; height?: number };

// Renders an accurate world map (Natural Earth projection) from a bundled
// TopoJSON, then projects each geo-located IP to its true lat/lng position.
// Replaces the old hand-drawn placeholder that plotted dots at arbitrary points.
export const GeoMap: React.FC<Props> = ({ ips, width = 760, height = 380 }) => {
  const { countries, projection } = useMemo(() => {
    const topo: any = worldTopo as any;
    const fc: any = feature(topo, topo.objects.countries);
    const proj = geoNaturalEarth1().fitSize([width, height], fc);
    return { countries: fc.features as any[], projection: proj };
  }, [width, height]);

  const path = useMemo(() => geoPath(projection), [projection]);

  const markers = useMemo(() => {
    const out: { ip: IPInfo; x: number; y: number }[] = [];
    for (const ip of ips) {
      if (typeof ip.lat !== "number" || typeof ip.lng !== "number") continue;
      const xy = projection([ip.lng as number, ip.lat as number]);
      if (xy) out.push({ ip, x: xy[0], y: xy[1] });
    }
    return out;
  }, [ips, projection]);

  const colorFor = (ip: IPInfo) =>
    ip.reputation ? "#ef4444" : ip.high_risk ? "#f97316" : ip.is_cdn ? "#38bdf8" : "#22c55e";

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950 overflow-hidden">
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-auto" role="img" aria-label="System locations map">
        <rect width={width} height={height} fill="#020617" />
        {countries.map((f, i) => (
          <path key={i} d={path(f as any) || undefined} fill="#0f1b2d" stroke="#1e293b" strokeWidth={0.5} />
        ))}
        {markers.map(({ ip, x, y }, i) => {
          const c = colorFor(ip);
          return (
            <g key={`${ip.ip}-${i}`}>
              <circle cx={x} cy={y} r={8} fill={c} opacity={0.22} />
              <circle cx={x} cy={y} r={3.2} fill={c} stroke="#020617" strokeWidth={0.6}>
                <title>
                  {`${ip.ip}\n${ip.org || ip.asn_name || "unknown ASN"}\n${ip.country || "?"}` +
                    (ip.high_risk ? "\n⚠ HIGH-RISK ASN" : "") +
                    (ip.reputation ? `\n☠ KNOWN-BAD: ${ip.reputation}` : "")}
                </title>
              </circle>
            </g>
          );
        })}
      </svg>
      <div className="flex flex-wrap gap-3 px-3 py-2 text-[11px] text-slate-400 border-t border-slate-800">
        <Legend color="#22c55e" label="origin host" />
        <Legend color="#38bdf8" label="CDN edge" />
        <Legend color="#f97316" label="high-risk ASN" />
        <Legend color="#ef4444" label="known-bad" />
        {markers.length === 0 && <span className="text-slate-500">No geolocation data for resolved IPs.</span>}
      </div>
    </div>
  );
};

const Legend: React.FC<{ color: string; label: string }> = ({ color, label }) => (
  <span className="inline-flex items-center gap-1">
    <span className="inline-block w-2 h-2 rounded-full" style={{ background: color }} />
    {label}
  </span>
);
