"""report/html_timeline.py -- one self-contained HTML page for the timeline (owner: Member 5).

The page works offline (no internet, no libraries). It shows the findings on top and the
full timeline below, with search, filters by source and by event type, an IST / UTC switch,
and a click-through from a finding to the exact events that triggered it.

    python -m report.html_timeline --timeline output/timeline.csv \
        --findings output/findings.csv --sessions output/sessions.csv --out output/timeline.html

main.py also calls write() for you after every run.

Safety note: the evidence can contain any text (web addresses, file names).  All of it is
embedded as data and shown with textContent, never as HTML, so evidence cannot inject
anything into the page.
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import os
import sys
from collections import Counter
from typing import Dict, List, Optional, Tuple

SOURCE_COLORS = {
    "Prefetch": "#3f9e3f", "LNK": "#2f7fd0", "EventLog": "#e08a1e",
    "RecycleBin": "#cc4125", "USB": "#8a6fd1", "Browser": "#b08900",
}
DEFAULT_COLOR = "#6b7a8f"


def _read_csv(path: str) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def _evidence_rows(evidence: str, key_to_idx: Dict[Tuple[str, str, str], List[int]]) -> List[int]:
    """findings.csv lists evidence as 'IST | source | summary || IST | source | summary'.
    Turn that back into row numbers of the timeline."""
    found: List[int] = []
    for part in (evidence or "").split(" || "):
        bits = part.split(" | ", 2)
        if len(bits) == 3:
            for i in key_to_idx.get((bits[0].strip(), bits[1].strip(), bits[2].strip()), []):
                if i not in found:
                    found.append(i)
    return found


def build_payload(timeline_rows: List[Dict[str, str]], findings_rows: Optional[List[Dict[str, str]]] = None,
                  sessions_rows: Optional[List[Dict[str, str]]] = None, title: str = "Windows activity timeline") -> Dict:
    rows = []
    key_to_idx: Dict[Tuple[str, str, str], List[int]] = {}
    for i, r in enumerate(timeline_rows):
        rows.append({
            "ist": r.get("timestamp_ist", ""), "utc": r.get("timestamp_utc", ""),
            "source": r.get("source", ""), "type": r.get("event_type", ""), "user": r.get("user", ""),
            "summary": r.get("summary", ""), "meaning": r.get("time_meaning", ""),
            "details": r.get("details", ""), "file": r.get("evidence_file", ""),
        })
        key_to_idx.setdefault((r.get("timestamp_ist", ""), r.get("source", ""), r.get("summary", "")), []).append(i)

    findings = []
    for f in findings_rows or []:
        findings.append({
            "id": f.get("finding_id", ""), "severity": f.get("severity", ""), "rule": f.get("rule_id", ""),
            "name": f.get("rule_name", ""), "user": f.get("user", ""), "session": f.get("session_id", ""),
            "start": f.get("start_ist", ""), "desc": f.get("description", ""),
            "rows": _evidence_rows(f.get("evidence", ""), key_to_idx),
            "count": f.get("evidence_count", ""),
        })

    sessions = [{"id": s.get("session_id", ""), "user": s.get("user", ""), "start": s.get("start_ist", ""),
                 "end": s.get("end_ist", ""), "ended": s.get("ended_by", ""), "events": s.get("event_count", "")}
                for s in (sessions_rows or [])]

    present = sorted({r["source"] for r in rows if r["source"]})
    colors = {s: SOURCE_COLORS.get(s, DEFAULT_COLOR) for s in present}
    return {"title": title, "rows": rows, "findings": findings, "sessions": sessions,
            "sources": present, "colors": colors, "counts": dict(Counter(r["source"] for r in rows))}


def render(payload: Dict) -> str:
    # ensure_ascii + escaping "<" means the data can never close the script tag or start a comment
    data = json.dumps(payload, ensure_ascii=True).replace("<", "\\u003c")
    return _TEMPLATE.replace("__TITLE__", html.escape(payload["title"])).replace("__DATA__", data)


def write(out_path: str, timeline_csv: str, findings_csv: Optional[str] = None,
          sessions_csv: Optional[str] = None, title: str = "Windows activity timeline") -> str:
    payload = build_payload(
        _read_csv(timeline_csv),
        _read_csv(findings_csv) if findings_csv and os.path.exists(findings_csv) else None,
        _read_csv(sessions_csv) if sessions_csv and os.path.exists(sessions_csv) else None,
        title)
    folder = os.path.dirname(os.path.abspath(out_path))
    os.makedirs(folder, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(render(payload))
    return out_path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Build the HTML timeline page")
    ap.add_argument("--timeline", default=os.path.join("output", "timeline.csv"))
    ap.add_argument("--findings", default=os.path.join("output", "findings.csv"))
    ap.add_argument("--sessions", default=os.path.join("output", "sessions.csv"))
    ap.add_argument("--out", default=os.path.join("output", "timeline.html"))
    ap.add_argument("--title", default="Windows activity timeline")
    args = ap.parse_args(argv)
    if not os.path.exists(args.timeline):
        print("timeline file not found: %s (run main.py first)" % args.timeline, file=sys.stderr)
        return 2
    print("wrote", write(args.out, args.timeline, args.findings, args.sessions, args.title))
    return 0


_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#f5f6f8;--card:#fff;--ink:#1c2430;--mute:#5b6675;--line:#d9dee6;--accent:#1f3a5f;--hit:#fff1b8;--high:#c0392b;--med:#d9822b;--low:#6b7a8f}
@media (prefers-color-scheme:dark){:root{--bg:#10151c;--card:#18202a;--ink:#e6ebf2;--mute:#9aa6b6;--line:#2b3644;--accent:#8fb4e8;--hit:#4a3f12;--high:#ef6b5c;--med:#e9a258;--low:#93a1b5}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1120px;margin:0 auto;padding:20px 16px 48px}
h1{font-size:22px;margin:0 0 4px;color:var(--accent)}
h2{font-size:15px;margin:22px 0 8px;color:var(--accent)}
.sub{color:var(--mute);margin:0 0 14px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.card b{display:block;font-size:20px}.card span{color:var(--mute);font-size:12px}
.finding{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--low);border-radius:8px;padding:10px 12px;margin-bottom:8px}
.finding.High{border-left-color:var(--high)}.finding.Medium{border-left-color:var(--med)}
.finding.sel{outline:2px solid var(--accent)}
.badge{display:inline-block;font-size:11px;font-weight:700;color:#fff;border-radius:4px;padding:1px 7px;margin-right:6px;background:var(--low)}
.badge.High{background:var(--high)}.badge.Medium{background:var(--med)}
.fmeta{color:var(--mute);font-size:12px;margin:2px 0 4px}
button{font:inherit;color:inherit;background:var(--card);border:1px solid var(--line);border-radius:6px;padding:4px 10px;cursor:pointer}
button:hover{border-color:var(--accent)}button:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
button[aria-pressed=true]{background:var(--accent);color:var(--bg);border-color:var(--accent)}
.bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0}
input[type=search],select{font:inherit;color:inherit;background:var(--card);border:1px solid var(--line);border-radius:6px;padding:5px 8px}
input[type=search]{min-width:220px;flex:1}
.chip{display:inline-flex;align-items:center;gap:6px}.dot{width:9px;height:9px;border-radius:50%;background:var(--c)}
.tablewrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%;min-width:720px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--mute);position:sticky;top:0;background:var(--card)}
tr.ev{cursor:pointer;box-shadow:inset 4px 0 0 var(--c)}tr.ev:hover{background:rgba(127,127,127,.08)}
tr.hit{background:var(--hit)}
td.t{white-space:nowrap;font-variant-numeric:tabular-nums}
.src{font-weight:600;color:var(--c)}.type{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
tr.detail td{background:rgba(127,127,127,.07);font-size:12.5px}
.kv{display:grid;grid-template-columns:110px 1fr;gap:2px 10px}.kv b{color:var(--mute);font-weight:600}
pre{margin:4px 0 0;white-space:pre-wrap;word-break:break-word;font-size:12px}
.note{color:var(--mute);font-size:12px;margin:6px 2px}.empty{padding:18px;color:var(--mute)}
@media print{button,input,select,.bar{display:none}body{background:#fff}}
</style>
</head>
<body>
<div class="wrap">
<h1 id="title"></h1>
<p class="sub" id="sub"></p>
<div class="cards" id="cards"></div>

<h2 id="fh">Findings</h2>
<div id="findings"></div>

<h2 id="sh" hidden>Logon sessions</h2>
<div class="tablewrap" id="sessionswrap" hidden><table id="sessions"></table></div>

<h2>Timeline</h2>
<div class="bar">
  <input type="search" id="q" placeholder="Search summary, user, file, details..." aria-label="Search the timeline">
  <select id="type" aria-label="Filter by event type"></select>
  <button id="tz" aria-pressed="false" title="Switch between Indian time and UTC">Showing IST</button>
</div>
<div class="bar" id="chips" aria-label="Filter by source"></div>
<div class="bar" id="banner" hidden>
  <span id="bannertext"></span>
  <button id="only" aria-pressed="true">Only these events</button>
  <button id="clear">Clear</button>
</div>
<div class="note" id="count"></div>
<div class="tablewrap"><table id="tl"></table></div>
<p class="note">Times come from the evidence files. Click a row to see its details and the file it came from.</p>
</div>

<script>
const DATA = __DATA__;
(function(){
"use strict";
var rows = DATA.rows, findings = DATA.findings, LIMIT = 2000;
var state = {tz:"ist", q:"", type:"", sources:{}, finding:null, only:true, expanded:{}, all:false};
DATA.sources.forEach(function(s){state.sources[s]=true;});
rows.forEach(function(r){r.hay=[r.summary,r.type,r.source,r.user,r.details,r.file,r.meaning].join(" ").toLowerCase();});

function $(id){return document.getElementById(id);}
function el(tag,cls,text){var e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;}
function color(s){return DATA.colors[s]||"#6b7a8f";}
function when(r){return state.tz==="ist"?r.ist:r.utc.replace("T"," ").replace("Z"," UTC");}

$("title").textContent = DATA.title;
$("sub").textContent = rows.length ? "First event "+rows[0].ist+" IST, last event "+rows[rows.length-1].ist+" IST" : "No events";

(function cards(){
  var box=$("cards");
  function add(n,l){var c=el("div","card");c.appendChild(el("b",null,String(n)));c.appendChild(el("span",null,l));box.appendChild(c);}
  add(rows.length,"events");
  add(DATA.sources.length,"sources");
  var sev={High:0,Medium:0,Low:0};findings.forEach(function(f){if(sev[f.severity]!==undefined)sev[f.severity]++;});
  add(findings.length,"findings ("+sev.High+" high, "+sev.Medium+" medium, "+sev.Low+" low)");
  if(DATA.sessions.length)add(DATA.sessions.length,"logon sessions");
})();

(function buildFindings(){
  var box=$("findings");
  if(!findings.length){box.appendChild(el("div","empty","No findings. Either nothing suspicious was seen, or the rules were not run."));return;}
  findings.forEach(function(f,i){
    var d=el("div","finding "+f.severity);d.id="f"+i;
    var h=el("div");h.appendChild(el("span","badge "+f.severity,f.severity));
    h.appendChild(el("b",null,"["+f.rule+"] "+f.name));d.appendChild(h);
    d.appendChild(el("div","fmeta",f.start+" IST"+(f.user?" | user "+f.user:"")+(f.session?" | session "+f.session:"")));
    d.appendChild(el("div",null,f.desc));
    var b=el("button",null,"Show the "+f.rows.length+(f.rows.length===1?" event":" events")+" behind this");b.style.marginTop="6px";
    b.addEventListener("click",function(){select(state.finding===i?null:i);});
    d.appendChild(b);box.appendChild(d);
  });
})();

(function buildSessions(){
  if(!DATA.sessions.length)return;
  $("sh").hidden=false;$("sessionswrap").hidden=false;
  var t=$("sessions"),hr=el("tr");
  ["#","User","Start (IST)","End (IST)","Ended by","Events"].forEach(function(h){hr.appendChild(el("th",null,h));});
  var th=el("thead");th.appendChild(hr);t.appendChild(th);var tb=el("tbody");
  DATA.sessions.forEach(function(s){var tr=el("tr");[s.id,s.user,s.start,s.end,s.ended,s.events].forEach(function(v){tr.appendChild(el("td",null,v));});tb.appendChild(tr);});
  t.appendChild(tb);
})();

(function buildFilters(){
  var sel=$("type"),types={};rows.forEach(function(r){types[r.type]=1;});
  var o=el("option",null,"All event types");o.value="";sel.appendChild(o);
  Object.keys(types).sort().forEach(function(t){var x=el("option",null,t);x.value=t;sel.appendChild(x);});
  sel.addEventListener("change",function(){state.type=sel.value;state.all=false;render();});
  $("q").addEventListener("input",function(){state.q=this.value;state.all=false;render();});
  $("tz").addEventListener("click",function(){state.tz=state.tz==="ist"?"utc":"ist";this.textContent=state.tz==="ist"?"Showing IST":"Showing UTC";this.setAttribute("aria-pressed",state.tz==="utc");render();});
  var chips=$("chips");
  DATA.sources.forEach(function(s){
    var b=el("button","chip");b.setAttribute("aria-pressed","true");
    var d=el("span","dot");d.style.setProperty("--c",color(s));b.appendChild(d);
    b.appendChild(document.createTextNode(s+" ("+DATA.counts[s]+")"));
    b.addEventListener("click",function(){state.sources[s]=!state.sources[s];b.setAttribute("aria-pressed",state.sources[s]);state.all=false;render();});
    chips.appendChild(b);
  });
  $("only").addEventListener("click",function(){state.only=!state.only;this.setAttribute("aria-pressed",state.only);render();});
  $("clear").addEventListener("click",function(){select(null);});
})();

function select(i){
  state.finding=i;state.all=false;
  var cards=document.querySelectorAll(".finding");
  Array.prototype.forEach.call(cards,function(c,k){c.classList.toggle("sel",k===i);});
  render();
  if(i!==null)$("tl").scrollIntoView({behavior:"smooth",block:"start"});
}

function visible(){
  var hit=state.finding===null?null:findings[state.finding].rows;
  var hitSet={};if(hit)hit.forEach(function(i){hitSet[i]=1;});
  var q=state.q.trim().toLowerCase(),out=[];
  rows.forEach(function(r,i){
    if(hit&&state.only){if(hitSet[i])out.push(i);return;}
    if(!state.sources[r.source])return;
    if(state.type&&r.type!==state.type)return;
    if(q&&r.hay.indexOf(q)<0)return;
    out.push(i);
  });
  return {list:out,hit:hitSet};
}

function render(){
  var v=visible(),t=$("tl");
  while(t.firstChild)t.removeChild(t.firstChild);
  var hr=el("tr");["Time ("+(state.tz==="ist"?"IST":"UTC")+")","Source","Event type","User","What happened"].forEach(function(h){hr.appendChild(el("th",null,h));});
  var th=el("thead");th.appendChild(hr);t.appendChild(th);
  var banner=$("banner");
  if(state.finding!==null){banner.hidden=false;var f=findings[state.finding];$("bannertext").textContent="Finding ["+f.rule+"] "+f.name+": "+f.rows.length+(f.rows.length===1?" event":" events");}
  else banner.hidden=true;
  var tb=el("tbody"),shown=state.all?v.list:v.list.slice(0,LIMIT);
  shown.forEach(function(i){
    var r=rows[i],tr=el("tr","ev"+(v.hit[i]?" hit":""));tr.style.setProperty("--c",color(r.source));
    tr.appendChild(el("td","t",when(r)));
    tr.appendChild(el("td","src",r.source));
    tr.appendChild(el("td","type",r.type));
    tr.appendChild(el("td",null,r.user));
    tr.appendChild(el("td",null,r.summary));
    tr.tabIndex=0;
    function toggle(){state.expanded[i]=!state.expanded[i];render();}
    tr.addEventListener("click",toggle);
    tr.addEventListener("keydown",function(e){if(e.key==="Enter"||e.key===" "){e.preventDefault();toggle();}});
    tb.appendChild(tr);
    if(state.expanded[i]){
      var dr=el("tr","detail"),td=el("td");td.colSpan=5;var kv=el("div","kv");
      function line(k,val){kv.appendChild(el("b",null,k));kv.appendChild(el("span",null,val));}
      line("UTC time",r.utc);line("IST time",r.ist);line("Time means",r.meaning);line("From file",r.file||"-");
      td.appendChild(kv);
      var pretty=r.details;try{pretty=JSON.stringify(JSON.parse(r.details),null,2);}catch(e){}
      if(pretty&&pretty!=="{}"){td.appendChild(el("pre",null,pretty));}
      dr.appendChild(td);tb.appendChild(dr);
    }
  });
  t.appendChild(tb);
  if(!v.list.length){var m=el("div","empty","No events match these filters.");t.parentNode.appendChild(m);m.id="emptymsg";}
  else{var old=$("emptymsg");if(old)old.parentNode.removeChild(old);}
  var c=$("count");c.textContent="Showing "+shown.length+" of "+v.list.length+" matching events ("+rows.length+" in total)";
  if(shown.length<v.list.length){
    var more=el("button",null,"Show all "+v.list.length);more.style.marginLeft="8px";
    more.addEventListener("click",function(){state.all=true;render();});c.appendChild(more);
  }
}
render();
})();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    sys.exit(main())
