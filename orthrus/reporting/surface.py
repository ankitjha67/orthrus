"""Attack-surface graph — visualize a scan's recon as a live node graph.

Recon already collects the pieces (hosts, resolved IPs, open ports, fingerprinted
technologies, discovered endpoints); this turns them into a single self-contained
HTML page: an interactive force-directed graph of target → host → port / technology,
plus an endpoints table underneath. No external assets or CDN — the force
simulation is a few dozen lines of vanilla JS embedded inline, so it renders from
`file://`, inside the dashboard, or emailed as-is.
"""

from __future__ import annotations

import html
import json
from urllib.parse import urlsplit

from orthrus.core.schemas import Asset, Endpoint

# Colours here are red/white/black only — canonical tokens in orthrus/utils/palette.py.
# Ports that are worth flagging red in the graph (admin / data / remote-access).
_RISKY_PORTS = {21, 22, 23, 445, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 9200, 27017}


def _host_of(url: str) -> str:
    netloc = urlsplit(url).netloc or url
    return netloc.split("@")[-1].split(":")[0]


def build_surface(target: str, assets: list[Asset], endpoints: list[Endpoint]) -> dict:
    """Build the {nodes, links, endpoints, stats} graph model (pure — unit-tested)."""
    root = _host_of(target) or target
    nodes: dict[str, dict] = {}
    links: list[dict] = []

    def node(nid: str, **kw) -> str:
        if nid not in nodes:
            nodes[nid] = {"id": nid, **kw}
        return nid

    node(f"host:{root}", label=root, group="target", detail=f"scan target · {target}")

    # Hosts discovered by recon (fall back to the target host if recon stored none).
    hosts = {a.fqdn: a for a in assets}
    if root not in hosts:
        hosts.setdefault(root, None)  # type: ignore[arg-type]

    ep_by_host: dict[str, int] = {}
    for ep in endpoints:
        ep_by_host[_host_of(ep.url)] = ep_by_host.get(_host_of(ep.url), 0) + 1

    for fqdn, asset in hosts.items():
        hid = node(
            f"host:{fqdn}",
            label=fqdn,
            group="target" if fqdn == root else "host",
            detail=_host_detail(fqdn, asset, ep_by_host.get(fqdn, 0)),
        )
        if fqdn != root:
            links.append({"source": f"host:{root}", "target": hid})
        if asset is None:
            continue
        for port in sorted(set(asset.ports)):
            pid = node(f"port:{fqdn}:{port}", label=str(port),
                       group="risky-port" if port in _RISKY_PORTS else "port",
                       detail=f"{fqdn}:{port}")
            links.append({"source": hid, "target": pid})
        for tech in asset.technologies:
            label = tech.name + (f" {tech.version}" if tech.version else "")
            tid = node(f"tech:{label}", label=label, group="tech",
                       detail=f"{tech.category or 'technology'}: {label}")
            links.append({"source": hid, "target": tid})

    # Give the graph structure from the endpoints themselves: group each host's
    # endpoints by first path segment, then hang a capped set of endpoint leaves
    # off those path nodes. Even a recon run that found no subdomains/ports still
    # yields a meaningful URL-structure tree.
    _EP_LEAF_CAP = 60
    leaves = 0
    for ep in endpoints:
        h = _host_of(ep.url)
        hid = f"host:{h}"
        if hid not in nodes:
            continue
        parts = [p for p in urlsplit(ep.url).path.split("/") if p]
        seg = "/" + parts[0] if parts else "/"
        pid = node(f"path:{h}:{seg}", label=seg, group="path", detail=f"{h}{seg}")
        links.append({"source": hid, "target": pid})
        if leaves < _EP_LEAF_CAP:
            leaf = "/".join(parts[1:]) or seg
            eid = node(f"ep:{ep.url}", label=(leaf[-24:] or seg), group="endpoint",
                       detail=f"{ep.method.value} {ep.url}"
                              + (f" → {ep.response_status}" if ep.response_status else ""))
            links.append({"source": pid, "target": eid})
            leaves += 1

    rows = [
        {
            "method": ep.method.value,
            "url": ep.url,
            "status": ep.response_status,
            "params": ", ".join(sorted({p.name for p in ep.params})),
        }
        for ep in endpoints
    ]
    stats = {
        "hosts": len(hosts),
        "ports": sum(1 for n in nodes.values() if n["group"] in ("port", "risky-port")),
        "technologies": sum(1 for n in nodes.values() if n["group"] == "tech"),
        "endpoints": len(endpoints),
    }
    return {"nodes": list(nodes.values()), "links": links, "endpoints": rows, "stats": stats}


def _host_detail(fqdn: str, asset: Asset | None, ep_count: int) -> str:
    if asset is None:
        return f"{fqdn} · {ep_count} endpoint(s)"
    bits = [fqdn]
    if asset.ips:
        bits.append("IP " + ", ".join(asset.ips[:3]))
    if asset.status_code:
        bits.append(f"HTTP {asset.status_code}")
    if asset.title:
        bits.append(asset.title[:50])
    bits.append(f"{ep_count} endpoint(s)")
    if asset.ip_intel and asset.ip_intel.as_org:
        bits.append(asset.ip_intel.as_org[:40])
    return " · ".join(bits)


_GRAPH_JS = r"""
const G = __DATA__;
const svg = document.getElementById('graph'), W = svg.clientWidth || 900, H = 560;
svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
const COL = {target:'#d70000', host:'#f0f0f0', port:'#b8b8b8', 'risky-port':'#ff3b3b',
             tech:'#8f8f8f', path:'#6f6f6f', endpoint:'#454545'};
const R = {target:16, host:11, 'risky-port':7, port:6, tech:6, path:7, endpoint:4};
const idx = {}; G.nodes.forEach((n,i)=>{idx[n.id]=n;
  n.x = W/2 + 240*Math.cos(i)*(0.3+((i*53)%7)/10); n.y = H/2 + 180*Math.sin(i)*(0.3+((i*31)%5)/10);
  n.vx=0; n.vy=0;});
G.links.forEach(l=>{l.s=idx[l.source]; l.t=idx[l.target];});
const gL = document.getElementById('links'), gN = document.getElementById('nodes');
G.links.forEach(l=>{const e=document.createElementNS(svg.namespaceURI,'line');
  e.setAttribute('stroke','#333'); e.setAttribute('stroke-width','1'); l.el=e; gL.appendChild(e);});
G.nodes.forEach(n=>{const g=document.createElementNS(svg.namespaceURI,'g'); g.style.cursor='grab';
  const c=document.createElementNS(svg.namespaceURI,'circle');
  c.setAttribute('r', R[n.group]||6); c.setAttribute('fill', COL[n.group]||'#789');
  c.setAttribute('stroke','#0f0f0f'); c.setAttribute('stroke-width','1.5');
  const t=document.createElementNS(svg.namespaceURI,'text'); t.textContent=n.label;
  t.setAttribute('font-size', n.group==='target'?'13':'10'); t.setAttribute('fill','#d0d0d0');
  t.setAttribute('dx', (R[n.group]||6)+3); t.setAttribute('dy','3'); t.style.pointerEvents='none';
  g.appendChild(c); g.appendChild(t); n.g=g; n.el=c;
  g.addEventListener('mousedown',e=>{drag=n; n.fixed=true; e.preventDefault();});
  g.addEventListener('mouseenter',()=>{tip.textContent=n.detail||n.label; tip.style.opacity=1;});
  g.addEventListener('mouseleave',()=>{tip.style.opacity=0;});
  gN.appendChild(g);});
const tip = document.getElementById('tip'); let drag=null;
svg.addEventListener('mousemove',e=>{const r=svg.getBoundingClientRect();
  const mx=(e.clientX-r.left)/r.width*W, my=(e.clientY-r.top)/r.height*H;
  tip.style.left=(e.clientX-r.left+12)+'px'; tip.style.top=(e.clientY-r.top+12)+'px';
  if(drag){drag.x=mx; drag.y=my; drag.vx=drag.vy=0;}});
window.addEventListener('mouseup',()=>{if(drag){drag.fixed=false; drag=null;}});
function step(){
  for(const a of G.nodes){for(const b of G.nodes){if(a===b)continue;
    let dx=a.x-b.x, dy=a.y-b.y, d2=dx*dx+dy*dy+0.01; if(d2>90000)continue;
    let f=2200/d2; a.vx+=dx*f*0.02; a.vy+=dy*f*0.02;}}
  for(const l of G.links){let dx=l.t.x-l.s.x, dy=l.t.y-l.s.y, d=Math.hypot(dx,dy)||1;
    let f=(d-80)*0.02; let ux=dx/d*f, uy=dy/d*f;
    if(!l.s.fixed){l.s.vx+=ux; l.s.vy+=uy;} if(!l.t.fixed){l.t.vx-=ux; l.t.vy-=uy;}}
  for(const n of G.nodes){ n.vx+=(W/2-n.x)*0.002; n.vy+=(H/2-n.y)*0.002;
    if(n.fixed)continue; n.vx*=0.85; n.vy*=0.85; n.x+=n.vx; n.y+=n.vy;
    n.x=Math.max(20,Math.min(W-20,n.x)); n.y=Math.max(20,Math.min(H-20,n.y));}
  for(const l of G.links){l.el.setAttribute('x1',l.s.x);l.el.setAttribute('y1',l.s.y);
    l.el.setAttribute('x2',l.t.x);l.el.setAttribute('y2',l.t.y);}
  for(const n of G.nodes){n.g.setAttribute('transform',`translate(${n.x},${n.y})`);}
  requestAnimationFrame(step);
}
step();
"""


def render_surface_html(
    target: str, assets: list[Asset], endpoints: list[Endpoint], *, title: str = "Attack surface"
) -> str:
    """Render the self-contained interactive attack-surface page."""
    model = build_surface(target, assets, endpoints)
    s = model["stats"]
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(r['method'])}</td>"
        f"<td><code>{html.escape(r['url'])}</code></td>"
        f"<td>{r['status'] if r['status'] is not None else ''}</td>"
        f"<td>{html.escape(r['params'])}</td>"
        "</tr>"
        for r in model["endpoints"]
    )
    legend = (
        "<span style='color:#d70000'>● target</span> "
        "<span style='color:#f0f0f0'>● host</span> "
        "<span style='color:#b8b8b8'>● port</span> "
        "<span style='color:#ff3b3b'>● risky port</span> "
        "<span style='color:#8f8f8f'>● technology</span> "
        "<span style='color:#6f6f6f'>● path</span> "
        "<span style='color:#454545'>● endpoint</span>"
    )
    data_json = json.dumps({"nodes": model["nodes"], "links": model["links"]})
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width, initial-scale=1">'
        f"<title>{html.escape(title)} — {html.escape(target)}</title><style>"
        "body{font-family:system-ui,'Segoe UI',sans-serif;background:#0f0f0f;color:#f0f0f0;margin:0;padding:20px}"
        "h1{color:#d70000;margin:0 0 2px;font-size:20px} .muted{color:#a8a8a8;font-size:13px}"
        "#wrap{position:relative;border:1px solid #2b2b2b;border-radius:8px;margin:12px 0;background:#0b0b0b}"
        "#graph{width:100%;height:560px;display:block}"
        "#tip{position:absolute;pointer-events:none;background:#181818;border:1px solid #333;color:#f0f0f0;"
        "padding:5px 9px;border-radius:6px;font-size:12px;opacity:0;transition:opacity .1s;max-width:340px;z-index:5}"
        ".legend{font-size:12px;margin:6px 0}"
        "table{border-collapse:collapse;width:100%;margin-top:10px;font-size:13px}"
        "th,td{text-align:left;padding:6px 9px;border-bottom:1px solid #2b2b2b} th{color:#a8a8a8}"
        "code{color:#e0e0e0;word-break:break-all}"
        "</style></head><body>"
        f"<h1>Attack surface — {html.escape(target)}</h1>"
        f"<div class=muted>{s['hosts']} host(s) · {s['ports']} open port(s) · "
        f"{s['technologies']} technolog(y/ies) · {s['endpoints']} endpoint(s) · drag nodes to explore</div>"
        f"<div class=legend>{legend}</div>"
        "<div id=wrap><svg id=graph xmlns='http://www.w3.org/2000/svg'>"
        "<g id=links></g><g id=nodes></g></svg><div id=tip></div></div>"
        f"<h2 style='font-size:15px;color:#a8a8a8'>Endpoints ({s['endpoints']})</h2>"
        "<table><tr><th>Method</th><th>URL</th><th>Status</th><th>Params</th></tr>"
        + (rows or "<tr><td colspan=4>No endpoints recorded.</td></tr>")
        + "</table>"
        "<script>" + _GRAPH_JS.replace("__DATA__", data_json) + "</script>"
        "</body></html>"
    )


__all__ = ["build_surface", "render_surface_html"]
