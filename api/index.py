import os
import requests
import re
import json
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ==========================================================
# 1. CONFIGURAÇÕES DA API E PARÂMETROS
# ==========================================================
# Na Vercel, configure a variável de ambiente VTURB_API_TOKEN no painel do projeto
API_TOKEN = os.environ.get("VTURB_API_TOKEN", "a1e325dc0b36b0dbf3c3b610f8c9d7b1d41c0f4690a7c7271ed8efdf2c4cbfad")
FILTRO_NOME = "apex burn"

headers = {
    "X-Api-Token": API_TOKEN,
    "X-Api-Version": "v1",
    "Content-Type": "application/json"
}

BASE_URL = "https://analytics.vturb.net"
LIST_URL = f"{BASE_URL}/players/list"
STATS_URL = f"{BASE_URL}/sessions/stats"

# ==========================================================
# 2. LÓGICA DE BUSCA DA API
# ==========================================================
def fetch_stats(player, start_str, end_str):
    p_id = player["id"]
    
    created_at = player.get("created_at", "")
    start_efetivo = start_str
    if created_at:
        c_date = created_at.split("T")[0]
        if c_date > start_str.split(" ")[0]:
            start_efetivo = f"{c_date} 00:00:00"

    payload = {
        "player_id": p_id,
        "start_date": start_efetivo,
        "end_date": end_str,
        "timezone": "America/Sao_Paulo",
        "video_duration": player.get("duration", 0)
    }

    try:
        res = requests.post(STATS_URL, headers=headers, json=payload, timeout=8)
        if res.status_code == 200:
            d = res.json()
            return p_id, {
                "views": d.get("total_viewed", 0) or 0,
                "unique_views": d.get("total_viewed_device_uniq", 0) or 0,
                "plays": d.get("total_started", 0) or 0,
                "unique_plays": d.get("total_started_device_uniq", 0) or 0,
                "play_rate": float(d.get("play_rate", 0) or 0),
                "pitch_retention": float(d.get("over_pitch_rate", 0) or 0),
                "pitch_audience": d.get("total_over_pitch", 0) or 0,
                "engagement": float(d.get("engagement_rate", 0) or 0),
                "button_clicks": d.get("total_clicked_device_uniq", 0) or 0,
                "conversions": d.get("total_conversions", 0) or 0,
                "conversion_rate": float(d.get("overall_conversion_rate", 0) or 0),
                "revenue": (float(d.get("total_amount_brl", 0) or 0)) / 100.0
            }
    except Exception:
        pass

    return p_id, {
        "views": 0, "unique_views": 0, "plays": 0, "unique_plays": 0,
        "play_rate": 0, "pitch_retention": 0, "pitch_audience": 0,
        "engagement": 0, "button_clicks": 0, "conversions": 0,
        "conversion_rate": 0, "revenue": 0.0
    }

def buscar_dados_completos(start_str, end_str):
    res = requests.get(LIST_URL, headers=headers, timeout=10)
    if res.status_code != 200:
        return []

    all_players = res.json()
    players = [p for p in all_players if FILTRO_NOME in p.get("name", "").lower()]

    metricas_map = {}
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(fetch_stats, p, start_str, end_str) for p in players]
        for future in as_completed(futures):
            p_id, stats = future.result()
            metricas_map[p_id] = stats

    pastas_semanas = defaultdict(list)
    outros_videos = []

    for player in players:
        nome_video = player.get("name", "")
        match_vs = re.search(r'v\d+s(\d{1,2})', nome_video, re.IGNORECASE)
        if not match_vs:
            match_vs = re.search(r'Semana\s*(\d{1,2})', nome_video, re.IGNORECASE)

        v_data = {
            "id": player["id"],
            "name": nome_video,
            "duration": player.get("duration", 0),
            "stats": metricas_map.get(player["id"], {})
        }

        if match_vs:
            num_semana = int(match_vs.group(1))
            pastas_semanas[f"SEMANA {num_semana:02d}"].append(v_data)
        else:
            outros_videos.append(v_data)

    estrutura = []
    for nome_pasta, v_list in sorted(pastas_semanas.items()):
        estrutura.append({"folder": nome_pasta, "videos": v_list})
    if outros_videos:
        estrutura.append({"folder": "OUTROS VÍDEOS", "videos": outros_videos})

    return estrutura

# ==========================================================
# 3. HTML / CSS NEUTRO & EXECUTIVE
# ==========================================================
def gerar_html(estrutura, start_date, end_date):
    return f'''<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Analytics Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-dark: #0b0f17;
            --sidebar-bg: #111827;
            --card-bg: #1e293b;
            --card-border: #334155;
            --accent-blue: #38bdf8;
            --accent-blue-bg: rgba(56, 189, 248, 0.1);
            --accent-green: #10b981;
            --accent-green-bg: rgba(16, 185, 129, 0.1);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --text-dim: #64748b;
            --font-mono: 'JetBrains Mono', monospace;
            --font-sans: 'Plus Jakarta Sans', sans-serif;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: var(--font-sans); background-color: var(--bg-dark); color: var(--text-main); display: flex; min-height: 100vh; overflow-x: hidden; }}
        .sidebar {{ width: 240px; background-color: var(--sidebar-bg); border-right: 1px solid var(--card-border); display: flex; flex-direction: column; padding: 24px 16px; position: fixed; top: 0; left: 0; bottom: 0; z-index: 100; }}
        .sidebar-brand {{ display: flex; align-items: center; gap: 12px; padding-bottom: 24px; border-bottom: 1px solid var(--card-border); margin-bottom: 24px; }}
        .brand-logo {{ width: 36px; height: 36px; background: linear-gradient(135deg, #38bdf8, #0284c7); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: 800; color: #fff; font-size: 1rem; }}
        .brand-text h2 {{ font-size: 0.95rem; font-weight: 800; letter-spacing: -0.02em; color: #f8fafc; }}
        .brand-text span {{ font-size: 0.68rem; color: var(--accent-blue); font-weight: 700; text-transform: uppercase; }}
        .nav-list {{ list-style: none; display: flex; flex-direction: column; gap: 6px; }}
        .nav-item a {{ display: flex; align-items: center; gap: 12px; padding: 10px 14px; border-radius: 8px; color: var(--text-muted); text-decoration: none; font-size: 0.85rem; font-weight: 600; transition: all 0.2s; }}
        .nav-item.active a, .nav-item a:hover {{ background: var(--accent-blue-bg); color: var(--accent-blue); border: 1px solid rgba(56, 189, 248, 0.2); }}
        .sidebar-footer {{ margin-top: auto; padding-top: 16px; border-top: 1px solid var(--card-border); }}
        .user-profile {{ display: flex; align-items: center; gap: 10px; padding: 10px; background: rgba(255,255,255,0.02); border-radius: 8px; border: 1px solid var(--card-border); }}
        .avatar {{ width: 32px; height: 32px; background: var(--card-border); border-radius: 50%; color: var(--accent-blue); font-weight: 800; display: flex; align-items: center; justify-content: center; font-size: 0.75rem; }}
        .user-info div {{ font-size: 0.8rem; font-weight: 700; color: #fff; }}
        .user-info span {{ font-size: 0.65rem; color: var(--accent-green); font-weight: 600; }}
        .main-content {{ margin-left: 240px; flex: 1; padding: 32px 40px; display: flex; flex-direction: column; gap: 24px; max-width: 1400px; }}
        .top-filter-bar {{ display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; background: var(--sidebar-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 18px 24px; gap: 16px; }}
        .page-title h1 {{ font-size: 1.25rem; font-weight: 800; letter-spacing: -0.02em; color: #fff; }}
        .page-title span {{ font-size: 0.72rem; color: var(--text-dim); font-family: var(--font-mono); }}
        .filters-form {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
        .filter-pill {{ background: var(--bg-dark); border: 1px solid var(--card-border); padding: 6px 12px; border-radius: 8px; display: flex; align-items: center; gap: 8px; }}
        .filter-pill label {{ font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase; font-weight: 700; }}
        .filter-pill input[type="date"] {{ background: transparent; border: none; color: var(--text-main); font-family: var(--font-mono); font-size: 0.8rem; outline: none; color-scheme: dark; }}
        .btn-submit {{ background: var(--accent-blue); color: #0b0f17; font-weight: 800; border: none; padding: 8px 18px; border-radius: 8px; font-size: 0.82rem; cursor: pointer; transition: opacity 0.2s; }}
        .btn-submit:hover {{ opacity: 0.9; }}
        .ai-signal {{ background: var(--sidebar-bg); border: 1px solid var(--card-border); border-left: 4px solid var(--accent-blue); border-radius: 10px; padding: 14px 20px; display: flex; align-items: center; gap: 14px; font-size: 0.82rem; color: var(--text-muted); }}
        .ai-tag {{ background: var(--accent-blue-bg); color: var(--accent-blue); border: 1px solid rgba(56, 189, 248, 0.3); padding: 3px 8px; border-radius: 4px; font-weight: 800; font-family: var(--font-mono); font-size: 0.7rem; }}
        .kpi-row {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }}
        .kpi-card {{ background: var(--sidebar-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 20px; display: flex; flex-direction: column; gap: 10px; }}
        .kpi-head {{ display: flex; justify-content: space-between; align-items: center; }}
        .kpi-label {{ font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase; font-weight: 700; }}
        .kpi-value {{ font-size: 1.8rem; font-weight: 800; font-family: var(--font-mono); letter-spacing: -0.03em; }}
        .kpi-badge {{ font-size: 0.7rem; font-weight: 700; font-family: var(--font-mono); padding: 2px 6px; border-radius: 4px; display: inline-flex; align-items: center; }}
        .kpi-badge.success {{ background: var(--accent-green-bg); color: var(--accent-green); }}
        .search-bar {{ background: var(--sidebar-bg); border: 1px solid var(--card-border); border-radius: 10px; padding: 12px 18px; color: var(--text-main); font-size: 0.9rem; width: 100%; outline: none; }}
        .folder {{ background: var(--sidebar-bg); border: 1px solid var(--card-border); border-radius: 12px; overflow: hidden; margin-bottom: 16px; }}
        .folder-header {{ padding: 16px 20px; background: rgba(255,255,255,0.01); cursor: pointer; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--card-border); user-select: none; }}
        .folder-title {{ font-weight: 700; font-size: 1rem; display: flex; align-items: center; gap: 10px; color: #fff; }}
        .badge-count {{ background: var(--bg-dark); border: 1px solid var(--card-border); color: var(--accent-blue); font-size: 0.75rem; font-weight: 700; padding: 3px 10px; border-radius: 20px; font-family: var(--font-mono); }}
        .video-grid {{ padding: 16px; display: flex; flex-direction: column; gap: 14px; }}
        .video-card {{ background: var(--bg-dark); border: 1px solid var(--card-border); border-radius: 10px; padding: 18px; transition: border-color 0.2s; }}
        .video-card:hover {{ border-color: #475569; }}
        .v-header {{ display: flex; justify-content: space-between; align-items: center; padding-bottom: 12px; margin-bottom: 12px; border-bottom: 1px dashed var(--card-border); }}
        .v-title {{ font-weight: 700; font-size: 0.95rem; color: #fff; }}
        .v-id {{ font-family: var(--font-mono); font-size: 0.78rem; color: var(--accent-blue); background: var(--sidebar-bg); border: 1px solid var(--card-border); padding: 3px 8px; border-radius: 4px; display: flex; gap: 8px; align-items: center; }}
        .metrics-subgrid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(125px, 1fr)); gap: 8px; }}
        .m-box {{ background: var(--sidebar-bg); border: 1px solid var(--card-border); border-radius: 6px; padding: 10px; text-align: center; }}
        .m-lbl {{ font-size: 0.65rem; color: var(--text-dim); text-transform: uppercase; font-weight: 700; }}
        .m-val {{ font-size: 1.05rem; font-weight: 800; font-family: var(--font-mono); margin-top: 2px; color: #fff; }}
        .m-val.blue {{ color: var(--accent-blue); }}
        .m-val.green {{ color: var(--accent-green); }}
        .collapsed .video-grid {{ display: none; }}
        .arrow {{ transition: transform 0.2s; font-size: 0.75rem; color: var(--text-dim); }}
        .collapsed .arrow {{ transform: rotate(-90deg); }}
    </style>
</head>
<body>
<aside class="sidebar">
    <div class="sidebar-brand">
        <div class="brand-logo">VT</div>
        <div class="brand-text"><h2>Analytics</h2><span>Performance Suite</span></div>
    </div>
    <ul class="nav-list">
        <li class="nav-item active"><a href="#">⚡ Performance</a></li>
    </ul>
    <div class="sidebar-footer">
        <div class="user-profile">
            <div class="avatar">DS</div>
            <div class="user-info"><div>Diego Santos</div><span>● Conectado</span></div>
        </div>
    </div>
</aside>
<main class="main-content">
    <div class="top-filter-bar">
        <div class="page-title">
            <h1>PAINEL DE PERFORMANCE — APEX BURN</h1>
            <span>PERÍODO SELECIONADO: {start_date} até {end_date}</span>
        </div>
        <form class="filters-form" action="/" method="GET">
            <div class="filter-pill"><label>DE:</label><input type="date" name="start" value="{start_date}"></div>
            <div class="filter-pill"><label>ATÉ:</label><input type="date" name="end" value="{end_date}"></div>
            <button type="submit" class="btn-submit">⚡ Atualizar Painel</button>
        </form>
    </div>
    <div class="ai-signal">
        <span class="ai-tag">ANALYTICS ENGINE</span>
        <span>Relatório executivo gerado com sucesso. Dados filtrados e sincronizados via VTurb API.</span>
    </div>
    <div class="kpi-row">
        <div class="kpi-card"><div class="kpi-head"><span class="kpi-label">Total Visualizações</span></div><div class="kpi-value" id="kpiViews">0</div></div>
        <div class="kpi-card"><div class="kpi-head"><span class="kpi-label">Total Plays</span></div><div class="kpi-value" id="kpiPlays">0</div></div>
        <div class="kpi-card"><div class="kpi-head"><span class="kpi-label">Play Rate Médio</span><span class="kpi-badge success">OK</span></div><div class="kpi-value" style="color: var(--accent-blue);" id="kpiPlayRate">0,00%</div></div>
        <div class="kpi-card"><div class="kpi-head"><span class="kpi-label">Faturamento Total</span><span class="kpi-badge success">BRL</span></div><div class="kpi-value" style="color: var(--accent-green);" id="kpiRevenue">R$ 0,00</div></div>
    </div>
    <input type="text" id="searchInput" class="search-bar" placeholder="🔍 Pesquisar por vídeo, semana ou ID..." onkeyup="filterSearch()">
    <div id="foldersContainer"></div>
</main>
<script>
    const PASTAS = {json.dumps(estrutura, ensure_ascii=False)};
    function renderStructure() {{
        const container = document.getElementById('foldersContainer');
        const fmt = (val) => new Intl.NumberFormat('pt-BR').format(val);
        const fmtCurr = (val) => new Intl.NumberFormat('pt-BR', {{ style: 'currency', currency: 'BRL' }}).format(val);
        let totViews = 0, totPlays = 0, totRevenue = 0, sumPlayRate = 0, countPR = 0;
        container.innerHTML = PASTAS.map(p => `
            <div class="folder collapsed" data-foldername="${{p.folder.toLowerCase()}}">
                <div class="folder-header" onclick="toggleFolder(this)">
                    <div class="folder-title"><span class="arrow">▼</span> 📁 ${{p.folder}}</div>
                    <span class="badge-count">${{p.videos.length}} VÍDEOS</span>
                </div>
                <div class="video-grid">
                    ${{p.videos.map(v => {{
                        const s = v.stats;
                        totViews += s.views || 0; totPlays += s.plays || 0; totRevenue += s.revenue || 0;
                        if (s.views > 0) {{ sumPlayRate += s.play_rate; countPR++; }}
                        return `
                        <div class="video-card" data-search="${{v.name.toLowerCase()}} ${{v.id.toLowerCase()}}">
                            <div class="v-header">
                                <div class="v-title">🎬 ${{v.name}}</div>
                                <div class="v-id">ID: ${{v.id}} <button class="copy-btn" onclick="copyId('${{v.id}}')" style="background:transparent; border:none; cursor:pointer;">📋</button></div>
                            </div>
                            <div class="metrics-subgrid">
                                <div class="m-box"><div class="m-lbl">Visualizações</div><div class="m-val">${{fmt(s.views || 0)}}</div></div>
                                <div class="m-box"><div class="m-lbl">Visitas Únicas</div><div class="m-val">${{fmt(s.unique_views || 0)}}</div></div>
                                <div class="m-box"><div class="m-lbl">Plays</div><div class="m-val">${{fmt(s.plays || 0)}}</div></div>
                                <div class="m-box"><div class="m-lbl">Plays Únicos</div><div class="m-val">${{fmt(s.unique_plays || 0)}}</div></div>
                                <div class="m-box"><div class="m-lbl">Play Rate</div><div class="m-val blue">${{(s.play_rate || 0).toFixed(2).replace('.', ',')}}%</div></div>
                                <div class="m-box"><div class="m-lbl">Retenção Pitch</div><div class="m-val">${{(s.pitch_retention || 0).toFixed(2).replace('.', ',')}}%</div></div>
                                <div class="m-box"><div class="m-lbl">Audiência Pitch</div><div class="m-val">${{fmt(s.pitch_audience || 0)}}</div></div>
                                <div class="m-box"><div class="m-lbl">Engajamento</div><div class="m-val">${{(s.engagement || 0).toFixed(2).replace('.', ',')}}%</div></div>
                                <div class="m-box"><div class="m-lbl">Cliques Botão</div><div class="m-val">${{fmt(s.button_clicks || 0)}}</div></div>
                                <div class="m-box"><div class="m-lbl">Conversões</div><div class="m-val">${{fmt(s.conversions || 0)}}</div></div>
                                <div class="m-box"><div class="m-lbl">Taxa Conversão</div><div class="m-val">${{(s.conversion_rate || 0).toFixed(2).replace('.', ',')}}%</div></div>
                                <div class="m-box"><div class="m-lbl">Receita</div><div class="m-val green">${{fmtCurr(s.revenue || 0)}}</div></div>
                            </div>
                        </div>`;
                    }}).join('')}}
                </div>
            </div>
        `).join('');
        document.getElementById('kpiViews').innerText = fmt(totViews);
        document.getElementById('kpiPlays').innerText = fmt(totPlays);
        document.getElementById('kpiRevenue').innerText = fmtCurr(totRevenue);
        const avgPR = countPR > 0 ? (sumPlayRate / countPR).toFixed(2).replace('.', ',') + '%' : '0,00%';
        document.getElementById('kpiPlayRate').innerText = avgPR;
    }}
    function toggleFolder(header) {{ header.parentElement.classList.toggle('collapsed'); }}
    function copyId(id) {{ navigator.clipboard.writeText(id); alert('ID copiado: ' + id); }}
    function filterSearch() {{
        const term = document.getElementById('searchInput').value.toLowerCase().trim();
        document.querySelectorAll('.folder').forEach(folder => {{
            const folderName = folder.getAttribute('data-foldername');
            const items = folder.querySelectorAll('.video-card');
            let visible = 0;
            items.forEach(item => {{
                if (item.getAttribute('data-search').includes(term) || folderName.includes(term)) {{ item.style.display = 'block'; visible++; }} 
                else {{ item.style.display = 'none'; }}
            }});
            if (visible > 0) {{ folder.style.display = 'block'; if (term !== '') folder.classList.remove('collapsed'); }} 
            else {{ folder.style.display = 'none'; }}
        }});
    }}
    window.onload = renderStructure;
</script>
</body>
</html>'''

# ==========================================================
# 4. HANDLER DA VERCEL SERVERLESS
# ==========================================================
class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        hoje = datetime.now()
        start = f"{hoje.year}-01-01"
        end = hoje.strftime("%Y-%m-%d")

        if "start" in params and params["start"][0]:
            start = params["start"][0]
        if "end" in params and params["end"][0]:
            end = params["end"][0]

        estrutura = buscar_dados_completos(f"{start} 00:00:00", f"{end} 23:59:59")
        html_out = gerar_html(estrutura, start, end)

        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html_out.encode('utf-8'))