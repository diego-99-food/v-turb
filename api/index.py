# -*- coding: utf-8 -*-
"""
Painel VSL Intelligence — vTurb Analytics
=========================================

Handler serverless único (compatível com Vercel / qualquer runtime que exponha
BaseHTTPRequestHandler) que autentica via Google OAuth, consulta a API de
Analytics da vTurb e renderiza um painel de decisão para operação de VSL.

ATENÇÃO — CREDENCIAIS
---------------------
Os valores de fallback abaixo existem só para não quebrar deploys antigos.
Defina TODOS eles como variáveis de ambiente e rotacione qualquer chave que
já tenha circulado fora do seu cofre de segredos.
"""

import os
import re
import json
import time
import hmac
import base64
import hashlib
import logging
import threading
from datetime import datetime, timedelta
from collections import defaultdict, OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, urlencode

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover
    Retry = None

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("painel-vsl")

# ==========================================================
# 1. CONFIGURAÇÃO
# ==========================================================

# Credenciais vêm só do ambiente (Vercel → Settings → Environment Variables).
# Sem elas o painel mostra a tela de configuração em vez de subir.
API_TOKEN = os.environ.get("VTURB_API_TOKEN", "")
GOOGLE_CLIENT_ID = os.environ.get(
    "GOOGLE_CLIENT_ID",
    "925506093716-ri88s3cof579g0duh1ok0q5up0dv97k1.apps.googleusercontent.com",
)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")

_DEFAULT_SECRET = "troque-este-segredo-em-producao"
SESSION_SECRET = os.environ.get("SESSION_SECRET", _DEFAULT_SECRET)
SECRET_INSEGURO = SESSION_SECRET == _DEFAULT_SECRET

# Hash da conta vTurb usado para embutir o player dentro do modal.
VTURB_ACCOUNT_HASH = os.environ.get(
    "VTURB_ACCOUNT_HASH", "0becd9a1-c128-4b07-a7d1-b3f261cc971d"
)

# Sessão cai em 8h de vida total e 2h de inatividade.
SESSION_MAX_AGE = int(os.environ.get("SESSION_MAX_AGE", 60 * 60 * 8))
SESSION_IDLE_MAX = int(os.environ.get("SESSION_IDLE_MAX", 60 * 60 * 2))
COOKIE_NAME = "vsl_session"

EMAILS_AUTORIZADOS = [
    e.strip().lower()
    for e in os.environ.get(
        "EMAILS_AUTORIZADOS",
        "contato.diegosouza24@gmail.com,time@useapexlabs.com",
    ).split(",")
    if e.strip()
]

# Grupo de criativos analisado na aba de retenção. Aceita uma lista de nomes
# exatos OU, se vazia, cai num filtro por substring configurável.
GRUPO_RETENCAO_FILTRO = os.environ.get("GRUPO_RETENCAO_FILTRO", "Apex Boost")

BASE_URL = "https://analytics.vturb.net"
LIST_URL = f"{BASE_URL}/players/list"
STATS_URL = f"{BASE_URL}/sessions/stats"
RETENTION_URL = f"{BASE_URL}/times/user_engagement"

TIMEZONE = os.environ.get("VTURB_TIMEZONE", "America/Sao_Paulo")

# Testes A/B da vTurb (pasta "TG Brands GUI" etc.). A API de Analytics só
# enxerga players, não o objeto "teste". Então o vínculo variação -> teste vem
# de um destes dois lugares, nesta ordem:
#   1. VTURB_TESTES_AB: JSON {"TG - B 1 : Grax Midia - NERVE": ["<player_id>", ...]}
#   2. TESTE_AB_REGEX: regex aplicada ao nome do player; o grupo 1 vira o número
#      do teste. O padrão pega nomes como "TG - B 1", "TG-B12", "TG - B 03".
try:
    TESTES_AB = json.loads(os.environ.get("VTURB_TESTES_AB", "") or "{}")
except ValueError:
    TESTES_AB = {}
    logging.getLogger("painel-vsl").warning("VTURB_TESTES_AB não é um JSON válido; ignorado.")
TESTE_POR_PLAYER = {
    str(pid): nome for nome, ids in TESTES_AB.items() for pid in (ids or [])
}
_RE_TESTE_AB = re.compile(
    os.environ.get("TESTE_AB_REGEX", r"\bTG\s*-\s*B\s*0*(\d{1,3})\b"), re.IGNORECASE
)

HEADERS_VTURB = {
    "X-Api-Token": API_TOKEN,
    "X-Api-Version": "v1",
    "Content-Type": "application/json",
}

MAX_WORKERS = int(os.environ.get("VTURB_MAX_WORKERS", 16))
CACHE_TTL = int(os.environ.get("VTURB_CACHE_TTL", 90))


# ==========================================================
# 2. CACHE EM MEMÓRIA (TTL) + SESSÃO HTTP COM RETRY
# ==========================================================

class TTLCache:
    """Cache LRU simples com expiração. Contêineres serverless são reutilizados
    entre invocações, então isso corta boa parte das chamadas repetidas."""

    def __init__(self, maxsize=512, ttl=CACHE_TTL):
        self.maxsize = maxsize
        self.ttl = ttl
        self._data = OrderedDict()
        self._lock = threading.Lock()

    def get(self, chave):
        with self._lock:
            item = self._data.get(chave)
            if not item:
                return None
            expira, valor = item
            if expira < time.time():
                self._data.pop(chave, None)
                return None
            self._data.move_to_end(chave)
            return valor

    def set(self, chave, valor):
        with self._lock:
            self._data[chave] = (time.time() + self.ttl, valor)
            self._data.move_to_end(chave)
            while len(self._data) > self.maxsize:
                self._data.popitem(last=False)


CACHE = TTLCache()


def _montar_sessao_http():
    s = requests.Session()
    if Retry is not None:
        retry = Retry(
            total=2,
            backoff_factor=0.4,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "POST"]),
        )
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=MAX_WORKERS * 2)
    else:  # pragma: no cover
        adapter = HTTPAdapter(pool_maxsize=MAX_WORKERS * 2)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


HTTP = _montar_sessao_http()


def _chave_cache(prefixo, payload):
    bruto = json.dumps(payload, sort_keys=True, default=str)
    return prefixo + ":" + hashlib.md5(bruto.encode("utf-8")).hexdigest()


# ==========================================================
# 3. SESSÃO ASSINADA (COOKIE HMAC)
# ==========================================================

def _b64e(dados: bytes) -> str:
    return base64.urlsafe_b64encode(dados).decode("utf-8").rstrip("=")


def _b64d(texto: str) -> bytes:
    pad = "=" * (-len(texto) % 4)
    return base64.urlsafe_b64decode(texto + pad)


def criar_sessao(email, nome, foto):
    agora = int(time.time())
    payload = {
        "email": email,
        "name": nome or "",
        "picture": foto or "",
        "iat": agora,
        "seen": agora,
        "exp": agora + SESSION_MAX_AGE,
    }
    corpo = _b64e(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    assinatura = hmac.new(
        SESSION_SECRET.encode("utf-8"), corpo.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"{corpo}.{assinatura}"


def validar_sessao(valor):
    if not valor or "." not in valor:
        return None
    try:
        corpo, assinatura = valor.rsplit(".", 1)
        esperada = hmac.new(
            SESSION_SECRET.encode("utf-8"), corpo.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(assinatura, esperada):
            return None

        payload = json.loads(_b64d(corpo).decode("utf-8"))
        agora = time.time()

        if payload.get("exp", 0) < agora:
            return None
        if agora - payload.get("seen", 0) > SESSION_IDLE_MAX:
            return None
        if payload.get("email", "").lower() not in EMAILS_AUTORIZADOS:
            return None
        return payload
    except Exception:
        return None


def renovar_sessao(payload):
    """Reemite o cookie mantendo exp original e atualizando o último acesso."""
    novo = dict(payload)
    novo["seen"] = int(time.time())
    corpo = _b64e(json.dumps(novo, separators=(",", ":")).encode("utf-8"))
    assinatura = hmac.new(
        SESSION_SECRET.encode("utf-8"), corpo.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"{corpo}.{assinatura}"


def montar_cookie(nome, valor, host, deletar=False):
    local = "localhost" in host or "127.0.0.1" in host
    partes = [f"{nome}={valor}", "Path=/", "HttpOnly", "SameSite=Lax"]
    if not local:
        partes.append("Secure")
    partes.append("Max-Age=0" if deletar else f"Max-Age={SESSION_MAX_AGE}")
    return "; ".join(partes)


CABECALHOS_SEGURANCA = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "geolocation=(), microphone=(), camera=()"),
]


def configuracao_pendente():
    """Lista o que falta configurar para o painel funcionar."""
    faltando = []
    if not API_TOKEN:
        faltando.append(("VTURB_API_TOKEN", "token da API de Analytics da vTurb"))
    if not GOOGLE_CLIENT_ID:
        faltando.append(("GOOGLE_CLIENT_ID", "client ID do OAuth do Google"))
    if not GOOGLE_CLIENT_SECRET:
        faltando.append(("GOOGLE_CLIENT_SECRET", "client secret do OAuth do Google"))
    if SECRET_INSEGURO:
        faltando.append(("SESSION_SECRET", "chave usada para assinar o cookie de sessão"))
    return faltando


# ==========================================================
# 4. INTEGRAÇÃO COM A API DA VTURB
# ==========================================================

_STATS_VAZIO = {
    "views": 0, "unique_views": 0, "plays": 0, "unique_plays": 0,
    "play_rate": 0.0, "pitch_retention": 0.0, "pitch_audience": 0,
    "engagement": 0.0, "button_clicks": 0, "conversions": 0,
    "conversion_rate": 0.0, "revenue": 0.0, "erro": True,
}

_RE_PITCH = re.compile(r"pitch\s*[-–]?\s*(\d{1,3})[_:\.](\d{1,2})", re.IGNORECASE)
_RE_SEMANA = re.compile(r"v\d+s(\d{1,2})", re.IGNORECASE)
_RE_SEMANA_ALT = re.compile(r"semana\s*(\d{1,2})", re.IGNORECASE)


def segundo_do_pitch(nome):
    """Os criativos carregam o instante da oferta no próprio nome
    ('... - Pitch 18_04'). Isso vira uma marcação exata na curva de retenção,
    coisa que a API sozinha não entrega."""
    if not nome:
        return None
    m = _RE_PITCH.search(nome)
    if not m:
        return None
    try:
        minutos, segundos = int(m.group(1)), int(m.group(2))
    except ValueError:
        return None
    if segundos > 59:
        return None
    return minutos * 60 + segundos


class ErroVTurb(Exception):
    """Falha ao falar com a API da vTurb, com mensagem pronta para a tela."""


def listar_players():
    cache = CACHE.get("players")
    if cache is not None:
        return cache
    try:
        res = HTTP.get(LIST_URL, headers=HEADERS_VTURB, timeout=12)
    except Exception as exc:
        raise ErroVTurb(f"Não foi possível alcançar a vTurb ({type(exc).__name__}).")

    if res.status_code in (401, 403):
        raise ErroVTurb("A vTurb recusou o token de API. Confira VTURB_API_TOKEN.")
    if res.status_code != 200:
        raise ErroVTurb(f"A vTurb respondeu {res.status_code} ao listar os vídeos.")

    try:
        dados = res.json()
    except ValueError:
        raise ErroVTurb("A vTurb devolveu uma resposta que não é JSON.")

    CACHE.set("players", dados)
    return dados


def buscar_stats(player, inicio, fim):
    """Métricas agregadas de um criativo no período.

    O período efetivo nunca começa antes da criação do player — senão a vTurb
    devolve zeros que sujam as médias.
    """
    pid = player["id"]
    inicio_efetivo = inicio
    criado_em = player.get("created_at", "")
    if criado_em:
        dia_criacao = criado_em.split("T")[0]
        if dia_criacao > inicio.split(" ")[0]:
            inicio_efetivo = f"{dia_criacao} 00:00:00"

    payload = {
        "player_id": pid,
        "start_date": inicio_efetivo,
        "end_date": fim,
        "timezone": TIMEZONE,
        "video_duration": player.get("duration", 0),
    }

    chave = _chave_cache("stats", payload)
    em_cache = CACHE.get(chave)
    if em_cache is not None:
        return pid, em_cache

    try:
        res = HTTP.post(STATS_URL, headers=HEADERS_VTURB, json=payload, timeout=12)
        if res.status_code != 200:
            log.warning("stats %s -> HTTP %s", pid, res.status_code)
            return pid, dict(_STATS_VAZIO)

        d = res.json()

        # A API não expõe audiência do pitch deduplicada por device: só o
        # total bruto de eventos (total_over_pitch) e a taxa já calculada
        # (over_pitch_rate). Usar o bruto como se fosse único inflava a
        # retenção. A taxa oficial é a fonte da verdade; a audiência é
        # derivada dela sobre os plays únicos.
        taxa_pitch = float(d.get("over_pitch_rate", 0) or 0)
        plays_unicos = int(d.get("total_started_device_uniq", 0) or 0)
        audiencia_pitch = round((taxa_pitch / 100.0) * plays_unicos)

        stats = {
            "views": int(d.get("total_viewed", 0) or 0),
            "unique_views": int(d.get("total_viewed_device_uniq", 0) or 0),
            "plays": int(d.get("total_started", 0) or 0),
            "unique_plays": plays_unicos,
            "play_rate": float(d.get("play_rate", 0) or 0),
            "pitch_retention": taxa_pitch,
            "pitch_audience": audiencia_pitch,
            "engagement": float(d.get("engagement_rate", 0) or 0),
            "button_clicks": int(d.get("total_clicked_device_uniq", 0) or 0),
            "conversions": int(d.get("total_conversions", 0) or 0),
            "conversion_rate": float(d.get("overall_conversion_rate", 0) or 0),
            "revenue": float(d.get("total_amount_brl", 0) or 0) / 100.0,
            "erro": False,
        }
        CACHE.set(chave, stats)
        return pid, stats

    except Exception as exc:
        log.warning("stats %s falhou: %s", pid, exc)
        return pid, dict(_STATS_VAZIO)


def buscar_stats_lote(players, inicio, fim):
    mapa = {}
    if not players:
        return mapa
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futuros = [pool.submit(buscar_stats, p, inicio, fim) for p in players]
        for f in as_completed(futuros):
            pid, stats = f.result()
            mapa[pid] = stats
    return mapa


def _reamostrar(curva, alvo=360):
    """Uma VSL de 60 min devolve ~3600 pontos por vídeo. Doze vídeos disso
    viram um JSON de vários megabytes. Reduz para ~360 pontos preservando o
    mínimo de cada balde (a retenção é monotônica: o mínimo é o que importa)."""
    if len(curva) <= alvo:
        return curva
    passo = len(curva) / float(alvo)
    saida = []
    i = 0.0
    while int(i) < len(curva):
        ini = int(i)
        fim = min(int(i + passo), len(curva))
        if fim <= ini:
            fim = ini + 1
        bloco = curva[ini:fim]
        menor = min(bloco, key=lambda p: p["pct"])
        saida.append({"t": bloco[0]["t"], "users": menor["users"], "pct": menor["pct"]})
        i += passo
    return saida


def buscar_curva_retencao(player, inicio, fim):
    """Curva de retenção segundo a segundo via POST /times/user_engagement."""
    pid = player["id"]
    payload = {
        "player_id": pid,
        "video_duration": player.get("duration", 0) or 0,
        "start_date": inicio,
        "end_date": fim,
        "timezone": TIMEZONE,
    }

    chave = _chave_cache("curva", payload)
    em_cache = CACHE.get(chave)
    if em_cache is not None:
        return pid, em_cache

    vazio = {"curve": [], "average_watched_time": 0, "engagement_rate": 0}
    try:
        res = HTTP.post(RETENTION_URL, headers=HEADERS_VTURB, json=payload, timeout=15)
        if res.status_code != 200:
            return pid, vazio

        d = res.json()
        pontos = sorted(d.get("grouped_timed", []) or [], key=lambda g: g.get("timed", 0) or 0)
        if not pontos:
            return pid, vazio

        base = max((p.get("total_users", 0) or 0) for p in pontos) or 0
        curva = []
        piso = 100.0
        for p in pontos:
            usuarios = p.get("total_users", 0) or 0
            pct = round((usuarios / base) * 100, 2) if base else 0.0
            # A retenção é monotônica por definição: quem saiu não volta.
            # Ruído de amostragem que "sobe" é achatado aqui, na origem.
            piso = min(piso, pct)
            curva.append({"t": p.get("timed", 0) or 0, "users": usuarios, "pct": piso})

        resultado = {
            "curve": _reamostrar(curva),
            "average_watched_time": d.get("average_watched_time", 0) or 0,
            "engagement_rate": d.get("engagement_rate", 0) or 0,
        }
        CACHE.set(chave, resultado)
        return pid, resultado

    except Exception as exc:
        log.warning("curva %s falhou: %s", pid, exc)
        return pid, vazio


def buscar_curvas_lote(players, inicio, fim):
    mapa = {}
    if not players:
        return mapa
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futuros = [pool.submit(buscar_curva_retencao, p, inicio, fim) for p in players]
        for f in as_completed(futuros):
            pid, curva = f.result()
            mapa[pid] = curva
    return mapa


# ==========================================================
# 5. ORGANIZAÇÃO DOS DADOS
# ==========================================================

def _rotulo_semana(nome):
    m = _RE_SEMANA.search(nome or "") or _RE_SEMANA_ALT.search(nome or "")
    if not m:
        return None
    return f"Semana {int(m.group(1)):02d}"


def _rotulo_teste_ab(player):
    """Em qual teste A/B da vTurb esse player está, ou None."""
    pid = str(player.get("id", ""))
    if pid in TESTE_POR_PLAYER:
        return TESTE_POR_PLAYER[pid]
    m = _RE_TESTE_AB.search(player.get("name", "") or "")
    if m and m.groups():
        return f"TG - B{int(m.group(1)):02d}"
    return None


def _rotulo_produto(nome):
    """'Tells - v5s19 - Apex Boost - Pitch 18_04' -> 'Apex Boost'."""
    partes = [p.strip() for p in (nome or "").split(" - ")]
    if len(partes) >= 3:
        return partes[2]
    return "Sem produto"


def agrupar(players, stats_por_id):
    pastas = defaultdict(list)
    soltos = []

    for player in players:
        stats = stats_por_id.get(player["id"], {})
        if not stats.get("views") and not stats.get("plays"):
            continue

        nome = player.get("name", "")
        item = {
            "id": player["id"],
            "name": nome,
            "duration": player.get("duration", 0),
            "product": _rotulo_produto(nome),
            "pitch_at": segundo_do_pitch(nome),
            "ab_test": _rotulo_teste_ab(player),
            "stats": stats,
        }

        rotulo = _rotulo_semana(nome)
        if rotulo:
            pastas[rotulo].append(item)
        else:
            soltos.append(item)

    estrutura = [
        {"folder": nome, "videos": videos}
        for nome, videos in sorted(pastas.items())
    ]
    if soltos:
        estrutura.append({"folder": "Sem semana", "videos": soltos})
    return estrutura


def filtrar_players(todos, campanha):
    if not campanha:
        return todos
    termos = [t.strip().lower() for t in campanha.split(",") if t.strip()]
    if not termos:
        return todos
    return [
        p for p in todos
        if any(t in (p.get("name", "") or "").lower() for t in termos)
    ]


def carregar_periodo(inicio, fim, base_inicio=None, base_fim=None, campanha=""):
    players = filtrar_players(listar_players(), campanha)

    atual = agrupar(players, buscar_stats_lote(players, inicio, fim))

    anterior = []
    if base_inicio and base_fim:
        anterior = agrupar(players, buscar_stats_lote(players, base_inicio, base_fim))

    return atual, anterior


def carregar_retencao(inicio, fim, filtro=""):
    """Curvas de retenção do grupo de criativos pedido."""
    termo = (filtro or GRUPO_RETENCAO_FILTRO or "").strip().lower()
    todos = listar_players()
    players = [p for p in todos if termo in (p.get("name", "") or "").lower()] if termo else todos

    if not players:
        return []

    curvas = buscar_curvas_lote(players, inicio, fim)
    stats = buscar_stats_lote(players, inicio, fim)

    views_totais = sum((stats.get(p["id"], {}) or {}).get("views", 0) for p in players)

    saida = []
    for p in players:
        curva = curvas.get(p["id"]) or {"curve": [], "average_watched_time": 0, "engagement_rate": 0}
        s = stats.get(p["id"], {}) or {}
        views = s.get("views", 0)
        saida.append({
            "id": p["id"],
            "name": p.get("name", ""),
            "duration": p.get("duration", 0),
            "product": _rotulo_produto(p.get("name", "")),
            "pitch_at": segundo_do_pitch(p.get("name", "")),
            "ab_test": _rotulo_teste_ab(p),
            "traffic": round((views / views_totais) * 100, 2) if views_totais else 0,
            "curve": curva["curve"],
            "average_watched_time": curva["average_watched_time"],
            "engagement_rate": curva["engagement_rate"],
            "stats": s,
        })

    saida.sort(key=lambda v: v["traffic"], reverse=True)
    return saida


# ==========================================================
# 5b. TG BRANDS — TRÁFEGO x FATURAMENTO POR DIA
# ==========================================================

STATS_DIA_URL = f"{BASE_URL}/sessions/stats_by_day"

# Quais VSLs compõem cada brand do TG (pasta "TG Brands GUI" da vTurb). A API de
# Analytics não enxerga o objeto "teste A/B", então o vínculo vem daqui, pelo
# nome exato do player — tirado da planilha KPIs_TG_Brands_GUI. Pode ser
# sobrescrito por VTURB_TG_BRANDS (JSON {"brand": ["nome do player", ...]}).
# Um mesmo vídeo pode rodar em dois brands; no total geral ele conta uma vez só.
_TG_BRANDS_PADRAO = OrderedDict([
    ("TG - B 1 : Grax Midia - NERVE", [
        "TG DIEGO🚀 ⚽BRAND1 - V8S23 - VSL 8 (Semana 23) - Apex Gold - Pitch 43:10.mp4",
        "GOAT - BRAND 1 TG - VSL 2 (Semana 5) - Apex Gold - Pitch - 45_08.mp4",
        "TG DIEGO🚀 BRAND 1 - TG - VSL 3 (Semana 5) - Apex Gold Pitch - 44_36.mp4",
        "TG GraxMedia - v6s26 - Apex Gold - Pitch 27_57",
    ]),
    ("TG - B 2 : Inova - WL", [
        "TG DIEGO🚀 V4S33 - VSL 4 (Semana 33) - Inova - Pitch 35_03.mp4",
        "TG DIEGO🚀 V7S31 - VSL 7 (Semana 31) - Apex Burn - Inova - 01_02_53.mp4",
        "TG DIEGO🚀 Tells - v4s28 - Apex Burn - Inova - Pitch 38_03",
        "⚽BRAND2 - V8S30 - VSL 8 (Semana 30) - Apex Burn - Pitch - 37_42.mp4",
        "DIEGO🚀 V10S37 - VSL 10 (Semana 37) - Apex Burn Pitch 43.59.mp4",
        "DIEGO🚀 V9S37 - VSL 9 (Semana 37) - Apex Burn - Pitch 36_00.mp4",
        "GOAT - BRAND 2 TG - v3s8 - Pitch 35_16.mp4",
        "TG Inova [TOP1] ✅V3S4 - APEX BURN PITCH 48_01",
    ]),
    ("TG - B 3 : Mr Servicos - MEMO", [
        "TG DIEGO🚀 ⚽BRAND3 - V18S5 - VSL 18 (Semana 5) - Apex Neuro Elite - Pitch 31_05.mp4",
        "TG DIEGO🚀 GOAT - BRAND3 - V9S15 - VSL 9 (Semana 15) - Apex Neuro Elite - Pitch 44:13.mp4",
    ]),
    ("TG - B 4 : Insight7 - DIA", [
        "TG DIEGO🚀 B8 TG MGT - DIA - V9S32 - VSL 9 (Semana 32) - Apex Sugar Shield - Pitch 57_24.mp4",
        "GOAT - [B4TG] - V5S23 - VSL 5 (Semana 23) - Apex Sugar Shield - Pitch 57:19.mp4",
    ]),
    ("TG - B 5 : Agencia Giga - NERVE", [
        "TG DIEGO🚀 ⚽BRAND5 - V8S23 - VSL 8 (Semana 23) - Apex Gold - Pitch 43:10.mp4",
        "TG DIEGO🚀 [B5TG] - V9S23 - VSL 9 (Semana 23) - Apex Gold - Pitch 26:08.mp4",
        "TG DIEGO🚀 BRAND 1 - TG - VSL 3 (Semana 5) - Apex Gold Pitch - 44_36.mp4",
        "DIEGO🚀 [B5TG] - [TOP1 NERV] - V5s6 - Apex Gold - Pitch 22:30.mp4",
        "DIEGO🚀 [B5TG] - [TOP5 NERV] - V5S11 - Apex Gold - Pitch 35:59.mp4",
        "GOAT - BRAND 1 TG - VSL 2 (Semana 5) - Apex Gold - Pitch - 45_08.mp4",
    ]),
    ("TG - B 6 : Samuel Pieper - WL", [
        "TG DIEGO🚀 V4S33 - VSL 4 (Semana 33) - Spieper - Pitch 35_03.mp4",
        "TG DIEGO🚀 ⚽BRAND6 - V8S30 - VSL 8 (Semana 30) - Apex Burn - Pitch - 37_42.mp4",
        "DIEGO🚀 V7S31 - VSL 7 (Semana 31) - Apex Burn - Pieper - 01_02_53.mp4",
        "GOAT - [B6TG] - v3s8 - Pitch 35_16.mp4",
    ]),
    ("TG - B 7 : Mps Promotora - MEMO", [
        "TG DIEGO🚀 GOAT - 🏆[B7TG] - V9S15 - VSL 9 (Semana 15) - Apex Neuro Elite - Pitch 44:13.mp4",
    ]),
    ("TG - B 8 : Mgt Negocios - DIA", [
        "TG DIEGO🚀 B8 TG MGT - DIA - V9S32 - VSL 9 (Semana 32) - Apex Sugar Shield - Pitch 57_24.mp4",
        "⚽BRAND8 - V10S26 - VSL 10 (Semana 26) - Apex Sugar Shield - Pitch 48:10.mp4",
        "GOAT - BRAND 8 TG - V5S23 - VSL 5 (Semana 23) - Apex Sugar Shield - Pitch 57:19.mp4",
    ]),
    ("TG - B 9 : Rudimar - WL - Bellatrim", [
        "TG DIEGO🚀 GOAT - TG B9 - Rudimar - V1S34 - VSL 1 (SEMANA 34) - BellaTrim - WL - Pitch 35 16.mp4",
        "DIEGO🚀 V4S33 - VSL 4 (Semana 33) - Rudimar - Pitch 35_03.mp4",
        "DIEGO🚀 V5S32 - VSL 5 (Semana 32) - Apex Burn - Rudimar - Pitch 40_25.mp4",
        "DIEGO🚀 V5S33 - VSL 5 (Semana 33) - Apex Burn - Rudimar - Pitch 38_31.mp4",
        "DIEGO🚀 V7S31 - VSL 7 (Semana 31) - Apex Burn - Rudimar - 01_02_53.mp4",
    ]),
    ("TG - B10 : Contos - WL - BellaTrim", [
        "TG DIEGO🚀 TG B10 - Contos - V1S34 - VSL 1 (SEMANA 34) - BellaTrim - WL - Pitch 35 16.mp4",
        "TG DIEGO🚀 V2S34 - VSL 2 (SEMANA 34) - BellaTrim - Pitch 35_14.mp4 ✅",
        "DIEGO🚀 V4S33 - VSL 4 (Semana 33) - Contos - Pitch 35_03.mp4",
        "DIEGO🚀 V7S31 - VSL 7 (Semana 31) - Apex Burn - Contos - 01_02_53.mp4",
    ]),
    ("TG - B11 : Ribeiro e Hedel - MEMOFORGE", [
        "TG DIEGO🚀 GOAT - Ribeiro Bio 1 - V11S34 - VSL 11 (Semana 34) - MemoForge - Pitch - 44_13.mp4",
    ]),
    ("TG - B12 : Maluna Promocao - MEMOFORGE", [
        "TG DIEGO🚀 GOAT - Maluna 1 - V11S34 - VSL 11 (Semana 34) - MemoForge - Pitch - 44_13.mp4",
    ]),
    ("TG - B13 : Digge Marketing - ZENVORIX", [
        "TG DIEGO🚀 TG - Brand 13: V3S27 - VSL 3 (Semana 27) - Zenvorix - Pitch 48_36.mp4",
        "TG DIEGO🚀 TG - Brand 13: V4S34 - VSL 4 (SEMANA 34) - Zenvorix -pitch 19.38.mp4",
        "TG - Brand 13: V3S34 - VSL 3 (SEMANA 34) - Zenvorix - pitch 57.08.mp4",
    ]),
    ("TG - B14 : Mrt Experience - ZENVORIX", [
        "TG DIEGO🚀 TG - Brand 14: V3S34 - VSL 3 (SEMANA 34) - Zenvorix - pitch 57.08.mp4",
        "TG DIEGO🚀 TG - Brand 14: V3S27 - VSL 3 (Semana 27) - Zenvorix - Pitch 48_36.mp4",
        "TG - Brand 14: V4S34 - VSL 4 (SEMANA 34) - Zenvorix -pitch 19.38.mp4",
    ]),
    ("TG - B15 : Lets - NERVARA", [
        "TG DIEGO🚀 TG - Brand15: Lets - V5S34 - VSL 5 (SEMANA 34) - Nervara - NR - Pitch 45_08.mp4",
        "TG DIEGO🚀 TG - Brand15: Lets - V7S34 - VSL 7 (SEMANA 34) - Nervara - NR - Pitch 22_00 .mp4",
        "TG - Brand15: Lets - V6S34 - VSL 6 (SEMANA 34) - Nervara - Pitch 26 08.mp4",
    ]),
    ("TG - B16 : Macari - NERVARA", [
        "TG DIEGO🚀 TG - Brand16: Macari - V5S34 - VSL 5 (SEMANA 34) - Nervara - NR - Pitch 45_08.mp4",
        "TG DIEGO🚀 TG - Brand16: Macari - V7S34 - VSL 7 (SEMANA 34) - Nervara - NR - Pitch 22_00 .mp4",
        "TG - Brand16: Macari - V6S34 - VSL 6 (SEMANA 34) - Nervara - Pitch 26 08.mp4",
    ]),
])

try:
    TG_BRANDS = json.loads(os.environ.get("VTURB_TG_BRANDS", "") or "null", object_pairs_hook=OrderedDict) \
        or _TG_BRANDS_PADRAO
except ValueError:
    TG_BRANDS = _TG_BRANDS_PADRAO
    logging.getLogger("painel-vsl").warning("VTURB_TG_BRANDS não é um JSON válido; usando o mapa padrão.")

_DIA_VAZIO = {"views": 0, "unique_views": 0, "plays": 0, "unique_plays": 0, "conversions": 0, "revenue": 0.0}


def _nome_normalizado(nome):
    return re.sub(r"\s+", " ", (nome or "").strip().lower())


def buscar_stats_por_dia(player, inicio, fim):
    """Série diária de um player via POST /sessions/stats_by_day.
    Uma chamada cobre o período inteiro; a vTurb completa com dias zerados
    nas pontas, que são descartados por quem chama."""
    pid = player["id"]
    payload = {
        "player_id": pid,
        "start_date": inicio,
        "end_date": fim,
        "timezone": TIMEZONE,
        "video_duration": player.get("duration", 0) or 0,
    }
    chave = _chave_cache("dia", payload)
    em_cache = CACHE.get(chave)
    if em_cache is not None:
        return pid, em_cache

    try:
        res = HTTP.post(STATS_DIA_URL, headers=HEADERS_VTURB, json=payload, timeout=15)
        if res.status_code != 200:
            log.warning("stats_by_day %s -> HTTP %s", pid, res.status_code)
            return pid, None
        serie = {}
        for d in res.json() or []:
            dia = d.get("date_key")
            if not dia:
                continue
            serie[dia] = {
                "views": int(d.get("total_viewed", 0) or 0),
                "unique_views": int(d.get("total_viewed_device_uniq", 0) or 0),
                "plays": int(d.get("total_started", 0) or 0),
                "unique_plays": int(d.get("total_started_device_uniq", 0) or 0),
                "conversions": int(d.get("total_conversions", 0) or 0),
                "revenue": float(d.get("total_amount_brl", 0) or 0) / 100.0,
            }
        CACHE.set(chave, serie)
        return pid, serie
    except Exception as exc:
        log.warning("stats_by_day %s falhou: %s", pid, exc)
        return pid, None


def _somar_series(series, dias):
    linhas = []
    for dia in dias:
        linha = {"date": dia, **_DIA_VAZIO}
        for serie in series:
            ponto = serie.get(dia)
            if ponto:
                for k in _DIA_VAZIO:
                    linha[k] += ponto[k]
        linha["revenue"] = round(linha["revenue"], 2)
        linhas.append(linha)
    return linhas


def _totais(linhas):
    tot = dict(_DIA_VAZIO)
    for l in linhas:
        for k in _DIA_VAZIO:
            tot[k] += l[k]
    tot["revenue"] = round(tot["revenue"], 2)
    return tot


# ----------------------------------------------------------
# Divisão de tráfego configurada nos testes A/B da vTurb.
# A API de Analytics não expõe esse número, então o time digita no painel e
# ele fica guardado num Redis da Upstash (integração da Vercel, que cadastra
# KV_REST_API_URL/KV_REST_API_TOKEN ou UPSTASH_REDIS_REST_URL/_TOKEN).
# Chave por brand + player: a mesma VSL pode ter pesos diferentes em brands
# diferentes (ex.: B4 e B8).
# ----------------------------------------------------------

REDIS_URL = (os.environ.get("KV_REST_API_URL") or os.environ.get("UPSTASH_REDIS_REST_URL") or "").rstrip("/")
REDIS_TOKEN = os.environ.get("KV_REST_API_TOKEN") or os.environ.get("UPSTASH_REDIS_REST_TOKEN") or ""
_CHAVE_DIVISAO = "tg:divisao"
_CHAVE_DIVISAO_META = "tg:divisao:meta"


class ErroArmazenamento(Exception):
    """Falha ao ler ou gravar a divisão configurada."""


def _redis(*comando):
    if not (REDIS_URL and REDIS_TOKEN):
        raise ErroArmazenamento("O banco de configurações não está conectado ao projeto.")
    try:
        res = HTTP.post(REDIS_URL, headers={"Authorization": f"Bearer {REDIS_TOKEN}"},
                        json=list(comando), timeout=8)
    except Exception as exc:
        raise ErroArmazenamento(f"Não foi possível falar com o banco ({type(exc).__name__}).")
    if res.status_code != 200:
        raise ErroArmazenamento(f"O banco respondeu {res.status_code}.")
    dados = res.json()
    if "error" in dados:
        raise ErroArmazenamento(f"O banco recusou o comando: {dados['error']}")
    return dados.get("result")


def _hash_para_dict(lista):
    lista = lista or []
    return {lista[i]: lista[i + 1] for i in range(0, len(lista) - 1, 2)}


def ler_divisao():
    """{brand: {"pesos": {player_id: pct}, "meta": {...}}}. Vazio se o banco
    não estiver conectado: o painel continua funcionando sem a coluna."""
    if not (REDIS_URL and REDIS_TOKEN):
        return {}, False
    try:
        pesos = _hash_para_dict(_redis("HGETALL", _CHAVE_DIVISAO))
        metas = _hash_para_dict(_redis("HGETALL", _CHAVE_DIVISAO_META))
    except ErroArmazenamento as exc:
        log.warning("divisão: %s", exc)
        return {}, False
    saida = defaultdict(lambda: {"pesos": {}, "meta": None})
    for campo, valor in pesos.items():
        brand, _, pid = campo.rpartition("|")
        try:
            saida[brand]["pesos"][pid] = float(valor)
        except ValueError:
            continue
    for brand, meta in metas.items():
        try:
            saida[brand]["meta"] = json.loads(meta)
        except ValueError:
            pass
    return dict(saida), True


def salvar_divisao(brand, pesos, usuario):
    """Substitui a divisão configurada de um brand. pesos: {player_id: pct}."""
    if brand not in TG_BRANDS:
        raise ValueError("Brand desconhecido.")
    limpos = {}
    for pid, pct in (pesos or {}).items():
        pid = str(pid)[:64]
        if pct is None or pct == "":
            continue
        try:
            valor = float(pct)
        except (TypeError, ValueError):
            raise ValueError("Use só números entre 0 e 100.")
        if not 0 <= valor <= 100:
            raise ValueError("Cada porcentagem precisa estar entre 0 e 100.")
        limpos[pid] = round(valor, 2)
    if len(limpos) > 60:
        raise ValueError("VSLs demais num brand só.")

    # Apaga o que havia do brand antes de gravar: campo vazio = sem valor.
    atuais = _hash_para_dict(_redis("HGETALL", _CHAVE_DIVISAO))
    velhos = [c for c in atuais if c.rpartition("|")[0] == brand]
    if velhos:
        _redis("HDEL", _CHAVE_DIVISAO, *velhos)
    if limpos:
        pares = []
        for pid, valor in limpos.items():
            pares += [f"{brand}|{pid}", str(valor)]
        _redis("HSET", _CHAVE_DIVISAO, *pares)
    agora_brt = datetime.utcnow() - timedelta(hours=3)
    meta = {"em": agora_brt.strftime("%Y-%m-%d %H:%M"), "por": usuario}
    _redis("HSET", _CHAVE_DIVISAO_META, brand, json.dumps(meta, ensure_ascii=False))
    return {"pesos": limpos, "meta": meta}


def carregar_tg(inicio, fim):
    """Tráfego e faturamento diários de todos os brands do TG somados, mais o
    mesmo recorte do período imediatamente anterior (mesma duração) para dar
    contexto às variações. Uma única chamada por player cobre os dois."""
    d_ini = datetime.strptime(inicio, "%Y-%m-%d")
    d_fim = datetime.strptime(fim, "%Y-%m-%d")
    n_dias = (d_fim - d_ini).days + 1
    b_ini = d_ini - timedelta(days=n_dias)
    dias = [(d_ini + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(n_dias)]
    dias_base = [(b_ini + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(n_dias)]

    por_nome = defaultdict(list)
    for p in listar_players():
        por_nome[_nome_normalizado(p.get("name"))].append(p)

    nao_achados = []
    players_brand = OrderedDict()
    unicos = {}
    for brand, nomes in TG_BRANDS.items():
        lista = []
        for nome in nomes:
            achados = por_nome.get(_nome_normalizado(nome)) \
                or por_nome.get(_nome_normalizado(re.sub(r"\.mp4.*$", "", nome, flags=re.I)))
            if not achados:
                nao_achados.append({"brand": brand, "name": nome})
                continue
            for p in achados:
                lista.append(p)
                unicos[p["id"]] = p
        players_brand[brand] = lista

    series = {}
    falhas = 0
    if unicos:
        ini_api = f"{b_ini.strftime('%Y-%m-%d')} 00:00:00"
        fim_api = f"{fim} 23:59:59"
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futuros = [pool.submit(buscar_stats_por_dia, p, ini_api, fim_api) for p in unicos.values()]
            for f in as_completed(futuros):
                pid, serie = f.result()
                if serie is None:
                    falhas += 1
                    serie = {}
                series[pid] = serie

    todas = list(series.values())
    geral = _somar_series(todas, dias)
    geral_base = _somar_series(todas, dias_base)

    brands = []
    for brand, lista in players_brand.items():
        ids = list(OrderedDict.fromkeys(p["id"] for p in lista))
        linhas = _somar_series([series.get(i, {}) for i in ids], dias)
        # Cada VSL do brand, para ver como o tráfego se divide entre elas e
        # quanto cada uma devolve em faturamento.
        vsls = []
        for i in ids:
            dias_vsl = _somar_series([series.get(i, {})], dias)
            vsls.append({
                "id": i,
                "name": unicos[i].get("name", ""),
                "days": dias_vsl,
                "totals": _totais(dias_vsl),
            })
        brands.append({
            "name": brand,
            "videos": len(ids),
            "days": linhas,
            "totals": _totais(linhas),
            "prev_totals": _totais(_somar_series([series.get(i, {}) for i in ids], dias_base)),
            "vsls": vsls,
        })

    return {
        "days": geral,
        "totals": _totais(geral),
        "prev_days": geral_base,
        "prev_totals": _totais(geral_base),
        "prev_start": dias_base[0], "prev_end": dias_base[-1],
        "brands": brands,
        "players": len(unicos),
        "missing": nao_achados,
        "failed": falhas,
    }


# ==========================================================
# 6. SISTEMA DE DESIGN
# ==========================================================

_HEAD_ASSETS = """
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
    <script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
    <script src="https://cdn.jsdelivr.net/npm/flatpickr/dist/l10n/pt.js"></script>
"""

_TOKENS = r"""
:root {
  color-scheme: dark;
  --ink:        #0a0b10;
  --panel:      #101219;
  --panel-2:    #161923;
  --panel-3:    #1e2230;
  --line:       #1e2130;
  --line-2:     #2c3145;
  --ink-1:      #eef0f6;
  --ink-2:      #9aa1b4;
  --ink-3:      #646b80;
  --brand:      #6e5bff;
  --brand-2:    #9c8bff;
  --brand-wash: rgba(110, 91, 255, 0.13);
  --cyan:       #22d3ee;
  --pos:        #2dd4a7;
  --pos-wash:   rgba(45, 212, 167, 0.12);
  --neg:        #ff5c7a;
  --neg-wash:   rgba(255, 92, 122, 0.12);
  --warn:       #ffb020;
  --warn-wash:  rgba(255, 176, 32, 0.12);
  --sans: 'Inter', ui-sans-serif, system-ui, -apple-system, sans-serif;
  --mono: 'IBM Plex Mono', ui-monospace, SFMono-Regular, monospace;
  --r-xs: 6px;
  --r-sm: 9px;
  --r-md: 13px;
  --r-lg: 18px;
  --lift: 0 1px 2px rgba(0,0,0,.35), 0 8px 24px -12px rgba(0,0,0,.6);
  --rail: 232px;
}

[data-theme="light"] {
  color-scheme: light;
  --ink:        #f7f7fa;
  --panel:      #ffffff;
  --panel-2:    #f4f5f8;
  --panel-3:    #eaecf2;
  --line:       #e6e8ef;
  --line-2:     #d3d7e2;
  --ink-1:      #12141c;
  --ink-2:      #565d70;
  --ink-3:      #858c9e;
  --brand:      #5a45f0;
  --brand-2:    #7a66ff;
  --brand-wash: rgba(90, 69, 240, 0.09);
  --cyan:       #0891b2;
  --pos:        #0f9d76;
  --pos-wash:   rgba(15, 157, 118, 0.10);
  --neg:        #e0355c;
  --neg-wash:   rgba(224, 53, 92, 0.10);
  --warn:       #b97309;
  --warn-wash:  rgba(185, 115, 9, 0.11);
  --lift: 0 1px 2px rgba(16,20,40,.05), 0 10px 24px -16px rgba(16,20,40,.22);
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html { -webkit-text-size-adjust: 100%; }

body {
  font-family: var(--sans);
  background: var(--ink);
  color: var(--ink-1);
  font-size: 15px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}

body, .panel, .rail, .btn, input, select, textarea {
  transition: background-color .28s ease, border-color .28s ease, color .28s ease;
}

::selection { background: var(--brand); color: #fff; }

a { color: inherit; text-decoration: none; }

:focus-visible {
  outline: 2px solid var(--brand-2);
  outline-offset: 2px;
  border-radius: var(--r-xs);
}

.num { font-family: var(--mono); font-variant-numeric: tabular-nums; letter-spacing: -.02em; }

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: .01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: .01ms !important;
  }
}
"""

_CSS = r"""
/* ---------- ESTRUTURA ---------- */
.shell { display: flex; min-height: 100vh; }

.rail {
  width: var(--rail);
  flex: none;
  position: fixed;
  inset: 0 auto 0 0;
  z-index: 60;
  display: flex;
  flex-direction: column;
  gap: 26px;
  padding: 22px 16px 18px;
  background: var(--panel);
  border-right: 1px solid var(--line);
  overflow-y: auto;
}

.rail-mark { display: flex; align-items: center; gap: 10px; padding: 0 8px; }
.rail-mark img { max-width: 132px; max-height: 40px; height: auto; }
/* A logo é branca com fundo transparente: no tema claro ela é invertida para
   escurecer as letras, e o hue-rotate devolve o dourado do traço. */
[data-theme="light"] .rail-mark img, [data-theme="light"] .gate-mark img { filter: invert(1) hue-rotate(180deg); }
.rail-mark .fallback {
  font-weight: 700; font-size: 15px; letter-spacing: -.02em;
}
.rail-mark .fallback span { color: var(--brand-2); }

.nav { display: flex; flex-direction: column; gap: 2px; }
.nav-group-label {
  font-size: 11.5px; color: var(--ink-3); padding: 14px 10px 6px; font-weight: 500;
}
.nav a {
  display: flex; align-items: center; gap: 11px;
  padding: 9px 10px; border-radius: var(--r-sm);
  font-size: 14px; font-weight: 500; color: var(--ink-2);
  position: relative;
}
.nav a svg { flex: none; opacity: .8; }
.nav a:hover { background: var(--panel-2); color: var(--ink-1); }
.nav a[aria-current="page"] { background: var(--brand-wash); color: var(--brand-2); font-weight: 600; }
.nav a[aria-current="page"] svg { opacity: 1; }
.nav .kbd { margin-left: auto; }

.kbd {
  font-family: var(--mono); font-size: 10.5px; color: var(--ink-3);
  border: 1px solid var(--line-2); border-radius: 5px;
  padding: 1px 5px; background: var(--panel-2); line-height: 1.5;
}

.rail-foot { margin-top: auto; display: flex; flex-direction: column; gap: 10px; }

.who {
  display: flex; align-items: center; gap: 10px;
  padding: 9px 10px; border-radius: var(--r-md);
  background: var(--panel-2); border: 1px solid var(--line);
}
.who img, .who .initials {
  width: 30px; height: 30px; border-radius: 50%; flex: none;
}
.who .initials {
  display: grid; place-items: center; background: var(--brand-wash);
  color: var(--brand-2); font-size: 11.5px; font-weight: 700;
}
.who-text { min-width: 0; flex: 1; }
.who-name { font-size: 13px; font-weight: 600; }
.who-mail { font-size: 11.5px; color: var(--ink-3); }
.who-name, .who-mail { display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

.rail-actions { display: flex; gap: 6px; }
.rail-actions .btn { flex: 1; justify-content: center; }

/* ---------- BOTÕES ---------- */
.btn {
  display: inline-flex; align-items: center; gap: 7px; justify-content: center;
  font-family: var(--sans); font-size: 13.5px; font-weight: 600;
  padding: 9px 14px; border-radius: var(--r-sm); cursor: pointer;
  border: 1px solid var(--line-2); background: var(--panel-2); color: var(--ink-1);
}
.btn:hover { border-color: var(--ink-3); }
.btn-primary { background: var(--brand); border-color: var(--brand); color: #fff; }
.btn-primary:hover { background: var(--brand-2); border-color: var(--brand-2); }
.btn-ghost { background: transparent; border-color: transparent; color: var(--ink-2); }
.btn-ghost:hover { background: var(--panel-2); color: var(--ink-1); }
.btn-sm { padding: 6px 11px; font-size: 12.5px; }
.btn-danger { color: var(--neg); }
.btn-danger:hover { border-color: var(--neg); background: var(--neg-wash); }

/* ---------- PALCO ---------- */
.stage { flex: 1; margin-left: var(--rail); min-width: 0; }
.wrap { max-width: 1420px; padding: 0 40px 96px; margin: 0 auto; }

.masthead {
  position: sticky; top: 0; z-index: 40;
  background: color-mix(in srgb, var(--ink) 86%, transparent);
  backdrop-filter: blur(14px) saturate(1.4);
  border-bottom: 1px solid var(--line);
}
.masthead-inner {
  max-width: 1420px; margin: 0 auto; padding: 16px 40px;
  display: flex; align-items: center; gap: 18px; flex-wrap: wrap;
}
.masthead h1 { font-size: 17px; font-weight: 700; letter-spacing: -.025em; }
.masthead .period { font-size: 12.5px; color: var(--ink-3); margin-top: 1px; }
.masthead .spacer { flex: 1; }

/* barra de progresso do topo */
#loadbar {
  position: fixed; top: 0; left: 0; height: 2px; width: 0;
  background: linear-gradient(90deg, var(--brand), var(--cyan));
  z-index: 200; opacity: 0; transition: width .3s ease, opacity .3s ease;
}
#loadbar.on { opacity: 1; }

/* ---------- FILTROS ---------- */
.filters { display: flex; align-items: flex-end; gap: 10px; flex-wrap: wrap; }
.field { display: flex; flex-direction: column; gap: 5px; }
.field > label { font-size: 11.5px; color: var(--ink-3); font-weight: 500; padding-left: 2px; }
.field input[type="text"], .field select {
  font-family: var(--sans); font-size: 13.5px; font-weight: 500;
  color: var(--ink-1); background: var(--panel); border: 1px solid var(--line-2);
  border-radius: var(--r-sm); padding: 8px 11px; min-width: 190px; outline: none;
}
.field input::placeholder { color: var(--ink-3); font-weight: 400; }
.field input:focus, .field select:focus { border-color: var(--brand); box-shadow: 0 0 0 3px var(--brand-wash); }

.presets { display: flex; gap: 3px; background: var(--panel-2); padding: 3px; border-radius: var(--r-sm); border: 1px solid var(--line); }
.presets button {
  border: 0; background: transparent; color: var(--ink-2); cursor: pointer;
  font-family: var(--sans); font-size: 12.5px; font-weight: 600;
  padding: 6px 10px; border-radius: 6px;
}
.presets button:hover { color: var(--ink-1); }
.presets button[aria-pressed="true"] { background: var(--panel); color: var(--brand-2); box-shadow: var(--lift); }

.switch { display: inline-flex; align-items: center; gap: 8px; font-size: 13px; color: var(--ink-2); cursor: pointer; user-select: none; }
.switch input { position: absolute; opacity: 0; width: 0; height: 0; }
.switch .track {
  width: 34px; height: 19px; border-radius: 20px; background: var(--panel-3);
  border: 1px solid var(--line-2); position: relative; transition: background .2s ease;
}
.switch .track::after {
  content: ""; position: absolute; top: 2px; left: 2px;
  width: 13px; height: 13px; border-radius: 50%; background: var(--ink-3);
  transition: transform .2s ease, background .2s ease;
}
.switch input:checked + .track { background: var(--brand); border-color: var(--brand); }
.switch input:checked + .track::after { transform: translateX(15px); background: #fff; }
.switch input:focus-visible + .track { outline: 2px solid var(--brand-2); outline-offset: 2px; }

/* ---------- VIEWS ---------- */
.view { display: none; }
.view.on { display: block; }

.block { padding-top: 40px; }
.block-head { display: flex; align-items: flex-end; gap: 16px; flex-wrap: wrap; margin-bottom: 16px; }
.block-head h2 { font-size: 15.5px; font-weight: 650; letter-spacing: -.02em; }
.block-head p { font-size: 13px; color: var(--ink-3); margin-top: 3px; max-width: 68ch; }
.block-head .spacer { flex: 1; }

.panel {
  background: var(--panel); border: 1px solid var(--line);
  border-radius: var(--r-md); box-shadow: var(--lift);
}
.panel-pad { padding: 22px; }

/* ---------- FAIXA DE KPIs ---------- */
.ticker {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
  border: 1px solid var(--line); border-radius: var(--r-md);
  background: var(--panel); overflow: hidden; box-shadow: var(--lift);
}
.tick {
  padding: 16px 18px 15px;
  border-right: 1px solid var(--line); border-bottom: 1px solid var(--line);
}
.tick-k { font-size: 12px; color: var(--ink-2); font-weight: 500; }
.tick-v {
  font-size: clamp(19px, 1.6vw, 23px); font-weight: 600; letter-spacing: -.035em;
  margin: 7px 0 5px; font-variant-numeric: tabular-nums; line-height: 1.15;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.tick.lead { background: linear-gradient(180deg, var(--brand-wash), transparent 72%); }
.tick.lead .tick-v { color: var(--brand-2); }

.chg { display: inline-flex; align-items: center; gap: 5px; font-size: 12px; font-weight: 600; font-family: var(--mono); }
.chg::before { content: ""; width: 0; height: 0; border-left: 4px solid transparent; border-right: 4px solid transparent; }
.chg.up { color: var(--pos); } .chg.up::before { border-bottom: 5px solid var(--pos); }
.chg.down { color: var(--neg); } .chg.down::before { border-top: 5px solid var(--neg); }
.chg.flat { color: var(--ink-3); } .chg.flat::before { border: 0; width: 7px; height: 1.5px; background: var(--ink-3); }
.chg.none { color: var(--ink-3); font-family: var(--sans); font-weight: 500; }
.chg.none::before { display: none; }

/* ---------- DIAGNÓSTICO ---------- */
.verdict {
  display: grid; grid-template-columns: 46px 1fr auto; gap: 18px; align-items: center;
  padding: 20px 22px; border-radius: var(--r-md);
  border: 1px solid var(--line); background: var(--panel);
  border-left: 3px solid var(--brand); box-shadow: var(--lift);
}
.verdict.sev-crit { border-left-color: var(--neg); }
.verdict.sev-warn { border-left-color: var(--warn); }
.verdict.sev-good { border-left-color: var(--pos); }
.verdict-glyph { width: 46px; height: 46px; border-radius: var(--r-sm); display: grid; place-items: center; font-size: 20px; background: var(--brand-wash); }
.verdict.sev-crit .verdict-glyph { background: var(--neg-wash); }
.verdict.sev-warn .verdict-glyph { background: var(--warn-wash); }
.verdict.sev-good .verdict-glyph { background: var(--pos-wash); }
.verdict h3 { font-size: 15px; font-weight: 650; letter-spacing: -.015em; }
.verdict p { font-size: 13.5px; color: var(--ink-2); margin-top: 4px; max-width: 82ch; }

.notes { display: grid; grid-template-columns: repeat(auto-fill, minmax(310px, 1fr)); gap: 12px; }
.note {
  padding: 15px 16px; border-radius: var(--r-sm);
  background: var(--panel); border: 1px solid var(--line);
  border-top: 2px solid var(--line-2);
  display: flex; flex-direction: column; gap: 6px;
}
.note.sev-crit { border-top-color: var(--neg); }
.note.sev-warn { border-top-color: var(--warn); }
.note.sev-good { border-top-color: var(--pos); }
.note.sev-info { border-top-color: var(--brand); }
.note h4 { font-size: 13.5px; font-weight: 650; display: flex; align-items: center; gap: 7px; }
.note p { font-size: 12.8px; color: var(--ink-2); line-height: 1.55; }
.note .note-do { font-size: 12.5px; color: var(--ink-1); font-weight: 550; }
.note-link {
  align-self: flex-start; margin-top: 2px; background: none; border: 0; padding: 0;
  color: var(--brand-2); font-family: var(--sans); font-size: 12.5px; font-weight: 600;
  cursor: pointer; text-align: left;
}
.note-link:hover { text-decoration: underline; }
"""

_CSS += r"""
/* ---------- TABELA ---------- */
.grid-wrap { border: 1px solid var(--line); border-radius: var(--r-md); background: var(--panel); overflow: hidden; box-shadow: var(--lift); }
.scroll-x { overflow-x: auto; }
table.grid { width: 100%; border-collapse: collapse; min-width: 940px; }
table.grid thead th {
  text-align: left; font-size: 12px; font-weight: 550; color: var(--ink-3);
  padding: 12px 11px; background: var(--panel-2);
  border-bottom: 1px solid var(--line); white-space: nowrap; position: relative;
}
table.grid thead th.r { text-align: right; }
table.grid thead th[data-sort] { cursor: pointer; user-select: none; }
table.grid thead th[data-sort]:hover { color: var(--ink-1); }
table.grid thead th[aria-sort] { color: var(--brand-2); }
table.grid thead th .caret { font-size: 9px; margin-left: 3px; }
table.grid tbody td { padding: 10px 11px; border-bottom: 1px solid var(--line); font-size: 13.5px; }
table.grid tbody tr:last-child td { border-bottom: 0; }
table.grid tbody tr { cursor: pointer; }
table.grid tbody tr:hover { background: var(--panel-2); }
table.grid td.r { text-align: right; font-family: var(--mono); font-variant-numeric: tabular-nums; white-space: nowrap; font-size: 13px; }
td.r.pos { color: var(--pos); } td.r.neg { color: var(--neg); }
td.r.hot { color: var(--brand-2); font-weight: 600; }

.pos-idx { font-family: var(--mono); font-size: 12px; color: var(--ink-3); width: 26px; display: inline-block; }
.pos-idx.podium { color: var(--brand-2); font-weight: 600; }
.cell-title { font-weight: 600; font-size: 13.5px; }
.cell-sub { font-size: 11.5px; color: var(--ink-3); margin-top: 2px; display: flex; gap: 8px; flex-wrap: wrap; }
table.grid .cell-title {
  max-width: 240px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; display: block;
}
table.grid .cell-sub {
  max-width: 240px; flex-wrap: nowrap; overflow: hidden; white-space: nowrap;
}
.share { display: block; height: 2px; border-radius: 2px; background: var(--brand); margin-top: 9px; opacity: .5; min-width: 2px; }
table.grid.tg-grid { min-width: 820px; }
table.grid.tg-grid td.tg-fatia { min-width: 128px; white-space: nowrap; font-size: 13px; }
table.grid.tg-grid td.tg-fatia .share { opacity: .7; }
table.grid.tg-grid tbody tr.tg-vazia td { opacity: .45; }
table.grid.tg-grid .cell-title { max-width: 360px; }
.tg-pct { width: 64px; padding: 5px 7px; border-radius: var(--r-xs); border: 1px solid var(--line-2);
  background: var(--panel-2); color: var(--ink-1); font-family: var(--mono); font-size: 13px; text-align: right; }
.tg-pct:focus { outline: none; border-color: var(--brand); box-shadow: 0 0 0 3px var(--brand-wash); }
.tg-pct:disabled { opacity: .5; }
.tg-savebar { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; margin-top: 12px; font-size: 13px; color: var(--ink-3); }
.tg-savebar .tg-soma { font-family: var(--mono); font-weight: 600; }
.tg-bar { display: block; height: 5px; border-radius: 3px; background: var(--panel-3); margin-top: 7px; overflow: hidden; }
.tg-bar > span { display: block; height: 100%; border-radius: 3px; min-width: 2px; }
table.grid.tg-grid tbody tr.tg-total td { background: var(--panel-2); font-weight: 600; cursor: default; }
table.grid.tg-grid tbody tr[aria-selected="true"] td { background: var(--brand-wash); }
table.grid.tg-grid .tg-day { color: var(--ink-3); font-size: 11.5px; margin-left: 6px; }
.tg-spark { display: block; width: 120px; height: 26px; }
.tg-traffic { fill: var(--cyan); opacity: .55; }
.tg-traffic:hover { opacity: .85; }
.tg-rev { fill: none; stroke: var(--brand-2); stroke-width: 2.2; stroke-linejoin: round; stroke-linecap: round; }
.tg-dot { fill: var(--brand-2); stroke: var(--panel); stroke-width: 2; }
.tg-avg { stroke: var(--warn); stroke-width: 1.2; stroke-dasharray: 5 4; }
.tg-hit { fill: transparent; }
.tg-hit:hover { fill: var(--line); opacity: .45; }

.pill {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 2px 8px; border-radius: 20px; font-size: 11.5px; font-weight: 600;
  border: 1px solid var(--line-2); color: var(--ink-2); background: var(--panel-2);
}
.pill.good { color: var(--pos); border-color: color-mix(in srgb, var(--pos) 35%, transparent); background: var(--pos-wash); }
.pill.bad  { color: var(--neg); border-color: color-mix(in srgb, var(--neg) 35%, transparent); background: var(--neg-wash); }
.pill.mid  { color: var(--warn); border-color: color-mix(in srgb, var(--warn) 35%, transparent); background: var(--warn-wash); }
.pill.info { color: var(--brand-2); border-color: color-mix(in srgb, var(--brand) 40%, transparent); background: var(--brand-wash); }

/* ---------- GRÁFICOS ---------- */
.chart { width: 100%; height: auto; display: block; overflow: visible; }
.g-line { stroke: var(--line-2); stroke-width: 1; }
.g-dash { stroke: var(--line-2); stroke-width: 1; stroke-dasharray: 3 4; }
.g-text { fill: var(--ink-3); font-size: 11px; font-family: var(--mono); }
.g-title { fill: var(--ink-2); font-size: 11.5px; font-family: var(--sans); font-weight: 500; }
.bar-now { fill: var(--brand); }
.bar-was { fill: var(--ink-3); opacity: .38; }
.bar-now:hover, .bar-was:hover { opacity: .78; }
.dot { stroke: var(--panel); stroke-width: 1.5; cursor: pointer; }
.dot:hover { stroke: var(--ink-1); stroke-width: 2; }
.dot.q-scale { fill: var(--pos); }
.dot.q-cta   { fill: var(--cyan); }
.dot.q-hook  { fill: var(--warn); }
.dot.q-cut   { fill: var(--neg); }

.legend { display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 14px; }
.legend-item {
  display: inline-flex; align-items: center; gap: 7px; font-size: 12.5px;
  color: var(--ink-2); font-weight: 500; cursor: pointer; user-select: none;
  border: 0; background: none; font-family: var(--sans); padding: 0;
}
.legend-item .swatch { width: 9px; height: 9px; border-radius: 3px; flex: none; }
.legend-item[aria-pressed="false"] { opacity: .35; }
.legend-item:hover { color: var(--ink-1); }

.segmented { display: inline-flex; gap: 3px; padding: 3px; background: var(--panel-2); border: 1px solid var(--line); border-radius: var(--r-sm); flex-wrap: wrap; }
.segmented button {
  border: 0; background: transparent; color: var(--ink-2); cursor: pointer;
  font-family: var(--sans); font-size: 12.5px; font-weight: 600; padding: 6px 12px; border-radius: 6px;
}
.segmented button:hover { color: var(--ink-1); }
.segmented button[aria-pressed="true"] { background: var(--panel); color: var(--brand-2); box-shadow: var(--lift); }

#tip {
  position: fixed; z-index: 300; pointer-events: none; display: none;
  background: var(--panel-3); border: 1px solid var(--line-2); border-radius: var(--r-sm);
  padding: 10px 12px; font-size: 12.5px; box-shadow: var(--lift); max-width: 300px;
}
#tip .tip-h { font-size: 12px; color: var(--ink-2); margin-bottom: 5px; font-weight: 600; }
#tip .tip-row { display: flex; align-items: center; gap: 8px; justify-content: space-between; font-family: var(--mono); font-size: 12px; }
#tip .tip-row .swatch { width: 8px; height: 8px; border-radius: 2px; flex: none; }
#tip .tip-row span:first-child { display: flex; align-items: center; gap: 6px; font-family: var(--sans); color: var(--ink-2); }

/* ---------- FUNIL ---------- */
.funnel { display: flex; flex-direction: column; }
.stage-row {
  display: grid; grid-template-columns: 186px 1fr 132px 116px 96px; gap: 16px; align-items: center;
  padding: 13px 0; border-bottom: 1px solid var(--line);
}
.stage-row:last-child { border-bottom: 0; }
.stage-name { font-size: 13.5px; font-weight: 600; }
.stage-desc { font-size: 11.5px; color: var(--ink-3); margin-top: 2px; }
.stage-bar { height: 12px; border-radius: 20px; background: var(--panel-2); overflow: hidden; }
.stage-fill { height: 100%; border-radius: 20px; background: linear-gradient(90deg, var(--brand), color-mix(in srgb, var(--brand) 55%, var(--cyan))); min-width: 3px; }
.stage-num { font-family: var(--mono); font-size: 13px; font-weight: 600; font-variant-numeric: tabular-nums; }
.stage-num em { font-style: normal; display: block; font-family: var(--sans); font-size: 11px; color: var(--ink-3); font-weight: 500; margin-top: 2px; }
.stage-drop { text-align: right; font-family: var(--mono); font-size: 12.5px; font-weight: 600; white-space: nowrap; }
.stage-drop.worst { color: var(--neg); }
.stage-cmp { text-align: right; }

/* ---------- SEMANAS ---------- */
.cohort {
  border: 1px solid var(--line); border-radius: var(--r-md);
  background: var(--panel); margin-bottom: 8px; overflow: hidden;
}
.cohort > summary {
  display: flex; align-items: center; gap: 14px; flex-wrap: wrap;
  padding: 13px 16px; cursor: pointer; list-style: none;
}
.cohort > summary::-webkit-details-marker { display: none; }
.cohort > summary:hover { background: var(--panel-2); }
.cohort .twist { color: var(--ink-3); font-size: 10px; transition: transform .2s ease; }
.cohort[open] .twist { transform: rotate(90deg); }
.cohort-name { font-weight: 650; font-size: 14px; }
.cohort-stats { margin-left: auto; display: flex; gap: 26px; flex-wrap: wrap; }
.cohort-stat { text-align: right; }
.cohort-stat b { display: block; font-family: var(--mono); font-size: 13px; font-weight: 600; font-variant-numeric: tabular-nums; }
.cohort-stat i { font-style: normal; font-size: 11px; color: var(--ink-3); }
.cohort-body { padding: 0 10px 10px; }

.creative {
  display: grid; grid-template-columns: 1fr auto; gap: 8px 18px; align-items: center;
  padding: 11px 12px; border-radius: var(--r-sm); cursor: pointer; border: 1px solid transparent;
}
.creative:hover { background: var(--panel-2); border-color: var(--line); }
.creative-metrics { display: flex; gap: 22px; flex-wrap: wrap; }
.metric { text-align: right; min-width: 62px; }
.metric b { display: block; font-family: var(--mono); font-size: 12.5px; font-weight: 600; font-variant-numeric: tabular-nums; }
.metric i { font-style: normal; font-size: 10.5px; color: var(--ink-3); }
.metric b.pos { color: var(--pos); } .metric b.hot { color: var(--brand-2); }

/* ---------- MODAL ---------- */
.scrim {
  position: fixed; inset: 0; z-index: 120; padding: 28px;
  background: rgba(4,5,10,.72); backdrop-filter: blur(6px);
  display: flex; align-items: flex-start; justify-content: center; overflow-y: auto;
  opacity: 0; visibility: hidden; transition: opacity .2s ease, visibility .2s ease;
}
.scrim.on { opacity: 1; visibility: visible; }
.sheet {
  background: var(--panel); border: 1px solid var(--line-2); border-radius: var(--r-lg);
  width: min(960px, 100%); padding: 30px; position: relative; margin: auto;
  box-shadow: 0 32px 80px -24px rgba(0,0,0,.7);
}
.sheet-x {
  position: absolute; top: 16px; right: 16px; width: 30px; height: 30px;
  display: grid; place-items: center; border-radius: 50%; cursor: pointer;
  background: var(--panel-2); border: 1px solid var(--line); color: var(--ink-2); font-size: 14px;
}
.sheet-x:hover { color: var(--ink-1); background: var(--panel-3); }
.sheet-head { display: flex; gap: 18px; align-items: flex-start; flex-wrap: wrap; margin-bottom: 20px; padding-right: 34px; }
.sheet-head h3 { font-size: 17px; font-weight: 650; letter-spacing: -.02em; }
.sheet-head .meta { font-size: 12px; color: var(--ink-3); margin-bottom: 5px; }
.score-badge { margin-left: auto; text-align: right; padding: 10px 14px; border-radius: var(--r-sm); background: var(--panel-2); border: 1px solid var(--line); }
.score-badge b { font-family: var(--mono); font-size: 22px; font-weight: 600; letter-spacing: -.03em; }
.score-badge b s { text-decoration: none; font-size: 12px; color: var(--ink-3); }
.score-badge i { font-style: normal; display: block; font-size: 11.5px; color: var(--ink-2); margin-top: 2px; }

.stat-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(132px, 1fr)); gap: 1px; background: var(--line); border: 1px solid var(--line); border-radius: var(--r-sm); overflow: hidden; }
.stat-cell { background: var(--panel); padding: 12px 13px; }
.stat-cell i { font-style: normal; font-size: 11.5px; color: var(--ink-3); display: block; }
.stat-cell b { font-family: var(--mono); font-size: 15px; font-weight: 600; letter-spacing: -.02em; display: block; margin-top: 4px; }
.stat-cell b.pos { color: var(--pos); } .stat-cell b.hot { color: var(--brand-2); }

.sheet-label { font-size: 12.5px; color: var(--ink-3); font-weight: 550; margin: 24px 0 10px; }
.cmp-row { display: flex; justify-content: space-between; align-items: center; gap: 14px; padding: 10px 13px; border-radius: var(--r-xs); background: var(--panel-2); margin-bottom: 5px; font-size: 13px; }
.player-frame { border-radius: var(--r-md); overflow: hidden; background: #000; border: 1px solid var(--line-2); max-width: 620px; margin: 0 auto 22px; }

/* ---------- A/B ---------- */
.ab-head { display: grid; grid-template-columns: 1fr auto 1fr auto; gap: 14px; align-items: flex-end; }
.sig-panel { display: grid; grid-template-columns: repeat(auto-fit, minmax(238px, 1fr)); gap: 12px; }
.sig-card { padding: 17px 18px; border-radius: var(--r-md); background: var(--panel); border: 1px solid var(--line); border-top: 2px solid var(--line-2); }
.sig-card.win { border-top-color: var(--pos); }
.sig-card.lose { border-top-color: var(--neg); }
.sig-card.wait { border-top-color: var(--warn); }
.sig-metric { font-size: 13px; font-weight: 650; }
.sig-uplift { font-family: var(--mono); font-size: 25px; font-weight: 600; letter-spacing: -.035em; margin: 8px 0 3px; }
.sig-uplift.pos { color: var(--pos); } .sig-uplift.neg { color: var(--neg); }
.sig-rates { font-family: var(--mono); font-size: 12px; color: var(--ink-3); }
.conf-track { height: 5px; border-radius: 3px; background: var(--panel-3); overflow: hidden; margin: 13px 0 7px; position: relative; }
.conf-fill { height: 100%; border-radius: 3px; background: var(--warn); }
.conf-track::after { content: ""; position: absolute; top: -3px; bottom: -3px; left: 95%; width: 1px; background: var(--ink-3); }
.sig-card.win .conf-fill { background: var(--pos); }
.sig-card.lose .conf-fill { background: var(--neg); }
.sig-foot { font-size: 12px; color: var(--ink-2); line-height: 1.55; }
.sig-foot b { color: var(--ink-1); font-weight: 600; }

/* ---------- COMANDOS (⌘K) ---------- */
#palette {
  position: fixed; inset: 0; z-index: 150; padding: 12vh 20px 20px;
  background: rgba(4,5,10,.6); backdrop-filter: blur(5px);
  display: none; justify-content: center; align-items: flex-start;
}
#palette.on { display: flex; }
.palette-box { width: min(600px, 100%); background: var(--panel); border: 1px solid var(--line-2); border-radius: var(--r-md); box-shadow: 0 30px 70px -20px rgba(0,0,0,.75); overflow: hidden; }
.palette-box input {
  width: 100%; border: 0; border-bottom: 1px solid var(--line); background: transparent;
  padding: 15px 18px; font-family: var(--sans); font-size: 15px; color: var(--ink-1); outline: none;
}
.palette-list { max-height: 46vh; overflow-y: auto; padding: 6px; }
.palette-item {
  display: flex; align-items: center; gap: 11px; padding: 9px 12px; border-radius: var(--r-xs);
  cursor: pointer; font-size: 13.5px; width: 100%; border: 0; background: none;
  color: var(--ink-1); font-family: var(--sans); text-align: left;
}
.palette-item[data-active="true"] { background: var(--brand-wash); }
.palette-item .p-kind { font-size: 11.5px; color: var(--ink-3); margin-left: auto; flex: none; }
.palette-empty { padding: 26px; text-align: center; color: var(--ink-3); font-size: 13px; }

/* ---------- TOASTS ---------- */
#toasts { position: fixed; bottom: 20px; right: 20px; z-index: 250; display: flex; flex-direction: column; gap: 8px; }
.toast {
  padding: 11px 15px; border-radius: var(--r-sm); font-size: 13px; font-weight: 500;
  background: var(--panel-3); border: 1px solid var(--line-2); box-shadow: var(--lift);
  animation: toast-in .22s ease; max-width: 330px;
}
.toast.err { border-color: var(--neg); color: var(--neg); }
.toast.ok { border-color: var(--pos); color: var(--pos); }
@keyframes toast-in { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }

/* ---------- ESTADOS ---------- */
.blank { padding: 34px 20px; text-align: center; color: var(--ink-3); font-size: 13.5px; border: 1px dashed var(--line-2); border-radius: var(--r-md); }
.blank b { display: block; color: var(--ink-2); font-size: 14px; font-weight: 600; margin-bottom: 5px; }
.skel { background: linear-gradient(90deg, var(--panel-2) 25%, var(--panel-3) 50%, var(--panel-2) 75%); background-size: 300% 100%; animation: skel 1.3s ease-in-out infinite; border-radius: var(--r-xs); }
@keyframes skel { 0% { background-position: 150% 0; } 100% { background-position: -50% 0; } }

.banner {
  display: flex; align-items: center; gap: 11px; padding: 11px 16px; font-size: 13px;
  background: var(--warn-wash); color: var(--warn); border-bottom: 1px solid color-mix(in srgb, var(--warn) 30%, transparent);
}

/* ---------- FLATPICKR ---------- */
.flatpickr-calendar {
  background: var(--panel) !important; border: 1px solid var(--line-2) !important;
  border-radius: var(--r-md) !important; box-shadow: var(--lift) !important;
  font-family: var(--sans) !important;
}
.flatpickr-calendar.arrowTop::before, .flatpickr-calendar.arrowTop::after,
.flatpickr-calendar.arrowBottom::before, .flatpickr-calendar.arrowBottom::after { display: none !important; }
.flatpickr-months .flatpickr-month, .flatpickr-current-month, .flatpickr-weekday { color: var(--ink-2) !important; fill: var(--ink-2) !important; background: transparent !important; }
.flatpickr-months .flatpickr-prev-month svg, .flatpickr-months .flatpickr-next-month svg { fill: var(--ink-2) !important; }
.flatpickr-day { color: var(--ink-1) !important; border-radius: var(--r-xs) !important; }
.flatpickr-day:hover { background: var(--panel-2) !important; border-color: var(--panel-2) !important; }
.flatpickr-day.prevMonthDay, .flatpickr-day.nextMonthDay, .flatpickr-day.flatpickr-disabled { color: var(--ink-3) !important; }
.flatpickr-day.selected, .flatpickr-day.startRange, .flatpickr-day.endRange {
  background: var(--brand) !important; border-color: var(--brand) !important; color: #fff !important;
}
.flatpickr-day.inRange { background: var(--brand-wash) !important; border-color: var(--brand-wash) !important; box-shadow: -5px 0 0 var(--brand-wash), 5px 0 0 var(--brand-wash) !important; }
.flatpickr-day.today { border-color: var(--line-2) !important; }
.numInputWrapper span { border-color: var(--line) !important; }
.numInputWrapper span:hover { background: var(--panel-2) !important; }
.flatpickr-monthDropdown-months, .flatpickr-monthDropdown-month { background: var(--panel) !important; color: var(--ink-1) !important; }
.flatpickr-current-month input.cur-year { color: var(--ink-1) !important; }

/* ---------- RESPONSIVO ---------- */
.rail-toggle { display: none; }
@media (max-width: 1380px) {
  table.grid thead th:nth-child(8), table.grid tbody td:nth-child(8) { display: none; }
}
@media (max-width: 1080px) {
  .rail { transform: translateX(-100%); transition: transform .25s ease; }
  body.rail-open .rail { transform: none; }
  body.rail-open::after { content: ""; position: fixed; inset: 0; background: rgba(4,5,10,.6); z-index: 55; }
  .stage { margin-left: 0; }
  .wrap, .masthead-inner { padding-left: 20px; padding-right: 20px; }
  .rail-toggle { display: inline-flex; }
  .stage-row { grid-template-columns: 1fr; gap: 8px; }
  .stage-drop, .stage-cmp { text-align: left; }
  .ab-head { grid-template-columns: 1fr; }
  .sheet { padding: 22px; }
  .cohort-stats { width: 100%; justify-content: space-between; gap: 12px; margin-left: 0; }
  .creative { grid-template-columns: 1fr; }
}
@media (max-width: 640px) {
  .ticker { grid-template-columns: repeat(2, 1fr); }
  .tick-v { font-size: 21px; }
  .verdict { grid-template-columns: 1fr; gap: 12px; }
  .field input[type="text"], .field select { min-width: 0; width: 100%; }
  .filters { width: 100%; }
  .field { flex: 1 1 100%; }
}

/* ---------- MOTOR DE TESTES (Em teste / Maturidade / Leitura) ---------- */
.test-bar { display: grid; grid-template-columns: minmax(220px, 1.4fr) auto 1fr; gap: 14px; align-items: flex-end; }
.test-bar .ref { font-size: 12.5px; color: var(--ink-3); line-height: 1.5; padding-bottom: 9px; }
.test-bar .ref b { color: var(--ink-2); font-weight: 600; }

.focus-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(262px, 1fr)); gap: 12px; }
.focus-card { padding: 17px 18px; border-radius: var(--r-md); background: var(--panel); border: 1px solid var(--line); border-left: 3px solid var(--line-2); }
.focus-card.win { border-left-color: var(--pos); }
.focus-card.lose { border-left-color: var(--neg); }
.focus-card.wait { border-left-color: var(--warn); }
.focus-k { font-size: 11.5px; color: var(--ink-3); font-weight: 600; letter-spacing: .04em; text-transform: uppercase; }
.focus-v { font-family: var(--mono); font-size: 26px; font-weight: 600; letter-spacing: -.035em; margin: 7px 0 1px; }
.focus-v.pos { color: var(--pos); } .focus-v.neg { color: var(--neg); }
.focus-base { font-family: var(--mono); font-size: 12px; color: var(--ink-3); }
.focus-who { display: block; font-size: 13px; font-weight: 600; margin: 11px 0 5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.focus-sub { font-size: 12.2px; color: var(--ink-2); line-height: 1.55; }
.focus-sub b { color: var(--ink-1); font-weight: 600; }

.cell-delta { font-family: var(--mono); font-size: 11.5px; display: block; margin-top: 2px; }
.cell-delta.up { color: var(--pos); } .cell-delta.down { color: var(--neg); } .cell-delta.flat { color: var(--ink-3); }

/* decomposição do RPV */
.wf { display: grid; grid-template-columns: repeat(auto-fill, minmax(330px, 1fr)); gap: 12px; }
.wf-card { padding: 15px 17px; border-radius: var(--r-md); background: var(--panel); border: 1px solid var(--line); }
.wf-head { display: flex; align-items: baseline; gap: 10px; margin-bottom: 13px; }
.wf-name { font-size: 13px; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.wf-total { font-family: var(--mono); font-size: 15px; font-weight: 600; margin-left: auto; flex: none; }
.wf-total.pos { color: var(--pos); } .wf-total.neg { color: var(--neg); }
.wf-row { display: grid; grid-template-columns: 96px 1fr 68px; gap: 9px; align-items: center; margin-bottom: 7px; }
.wf-row span:first-child { font-size: 12px; color: var(--ink-2); }
.wf-row em { font-style: normal; font-family: var(--mono); font-size: 11.5px; text-align: right; }
.wf-track { position: relative; height: 13px; border-radius: 3px; background: var(--panel-2); overflow: hidden; }
.wf-track::before { content: ""; position: absolute; left: 50%; top: 0; bottom: 0; width: 1px; background: var(--line-2); }
.wf-fill { position: absolute; top: 3px; bottom: 3px; border-radius: 2px; }
.wf-fill.pos { background: var(--pos); } .wf-fill.neg { background: var(--neg); }
.wf-foot { font-size: 12px; color: var(--ink-3); margin-top: 10px; line-height: 1.5; }

/* maturidade */
.bucket-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(238px, 1fr)); gap: 12px; }
.bucket { padding: 16px 18px; border-radius: var(--r-md); background: var(--panel); border: 1px solid var(--line); border-top: 2px solid var(--line-2); }
.bucket.good { border-top-color: var(--pos); } .bucket.mid { border-top-color: var(--warn); }
.bucket.info { border-top-color: var(--brand); } .bucket.bad { border-top-color: var(--neg); }
.bucket-n { font-family: var(--mono); font-size: 30px; font-weight: 600; letter-spacing: -.04em; line-height: 1.1; }
.bucket-k { font-size: 13px; font-weight: 650; margin-top: 2px; }
.bucket-p { font-size: 12.2px; color: var(--ink-2); margin-top: 7px; line-height: 1.55; }
.bucket-list { font-size: 12px; color: var(--ink-3); margin-top: 9px; line-height: 1.6; word-break: break-word; }

.prog { height: 6px; border-radius: 3px; background: var(--panel-3); overflow: hidden; margin-top: 5px; min-width: 74px; }
.prog i { display: block; height: 100%; border-radius: 3px; background: var(--brand); }
.prog i.done { background: var(--pos); }

/* faixa cega do MDE */
.blind-row { display: grid; grid-template-columns: minmax(150px, 1fr) minmax(220px, 2.4fr) 120px; gap: 13px; align-items: center; padding: 9px 0; border-bottom: 1px solid var(--line); }
.blind-row:last-child { border-bottom: 0; }
.blind-name { font-size: 12.8px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.blind-track { position: relative; height: 28px; border-radius: var(--r-xs); background: var(--panel-2); overflow: hidden; }
.blind-band { position: absolute; top: 0; bottom: 0; background: var(--panel-3); }
.blind-zero { position: absolute; top: 0; bottom: 0; width: 1px; background: var(--line-2); }
.blind-dot { position: absolute; top: 50%; width: 11px; height: 11px; border-radius: 50%; transform: translate(-50%, -50%); border: 2px solid var(--panel); }
.blind-dot.pos { background: var(--pos); } .blind-dot.neg { background: var(--neg); } .blind-dot.mute { background: var(--ink-3); }
.blind-tag { font-family: var(--mono); font-size: 11.5px; color: var(--ink-2); text-align: right; }
.blind-scale { display: flex; justify-content: space-between; font-family: var(--mono); font-size: 11px; color: var(--ink-3); margin-top: 6px; }

/* régua e placar da leitura */
.rule-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 1px; background: var(--line); border: 1px solid var(--line); border-radius: var(--r-sm); overflow: hidden; }
.rule { background: var(--panel); padding: 15px 17px; }
.rule-k { font-size: 11.5px; color: var(--ink-3); font-weight: 600; letter-spacing: .03em; text-transform: uppercase; }
.rule-v { font-family: var(--mono); font-size: 17px; font-weight: 600; margin: 6px 0 5px; letter-spacing: -.02em; }
.rule-p { font-size: 12.2px; color: var(--ink-2); line-height: 1.55; }

.verd { display: inline-flex; align-items: center; gap: 6px; font-size: 11.5px; font-weight: 600; padding: 3px 8px; border-radius: 999px; border: 1px solid var(--line-2); color: var(--ink-2); white-space: nowrap; }
.verd::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; flex: none; }
.verd.good { color: var(--pos); border-color: color-mix(in srgb, var(--pos) 35%, transparent); background: var(--pos-wash); }
.verd.bad { color: var(--neg); border-color: color-mix(in srgb, var(--neg) 35%, transparent); background: var(--neg-wash); }
.verd.mid { color: var(--warn); border-color: color-mix(in srgb, var(--warn) 35%, transparent); background: var(--warn-wash); }
.verd.info { color: var(--brand-2); border-color: color-mix(in srgb, var(--brand) 40%, transparent); background: var(--brand-wash); }

.queue { display: grid; gap: 10px; }
.queue-item { display: grid; grid-template-columns: 34px 1fr auto; gap: 13px; align-items: flex-start; padding: 14px 16px; border-radius: var(--r-md); background: var(--panel); border: 1px solid var(--line); }
.queue-idx { font-family: var(--mono); font-size: 12px; color: var(--ink-3); padding-top: 2px; }
.queue-title { font-size: 13.2px; font-weight: 600; }
.queue-body { font-size: 12.4px; color: var(--ink-2); line-height: 1.6; margin-top: 4px; }
.queue-body b { color: var(--ink-1); font-weight: 600; }
.queue-when { font-family: var(--mono); font-size: 11.5px; color: var(--ink-3); text-align: right; flex: none; padding-top: 2px; }

.summary-box { font-family: var(--mono); font-size: 12.3px; line-height: 1.75; color: var(--ink-2); white-space: pre-wrap; background: var(--panel-2); border: 1px solid var(--line); border-radius: var(--r-md); padding: 18px 20px; max-height: 460px; overflow-y: auto; }

@media (max-width: 1080px) {
  .test-bar { grid-template-columns: 1fr; }
  .test-bar .ref { padding-bottom: 0; }
  .blind-row { grid-template-columns: 1fr; gap: 7px; }
  .blind-tag { text-align: left; }
  .queue-item { grid-template-columns: 1fr; }
  .queue-when { text-align: left; }
}
"""


# ==========================================================
# 7. PÁGINAS DE ENTRADA
# ==========================================================

def _casca(titulo, corpo, extra_css=""):
    return f"""<!DOCTYPE html>
<html lang="pt-BR" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{titulo}</title>
{_HEAD_ASSETS}
<style>
{_TOKENS}
body {{ display: grid; place-items: center; min-height: 100vh; padding: 24px; }}
.gate {{
  width: min(400px, 100%); background: var(--panel);
  border: 1px solid var(--line); border-radius: var(--r-lg); padding: 36px 34px;
  box-shadow: 0 30px 70px -30px rgba(0,0,0,.8);
}}
.gate-mark {{ display: flex; justify-content: center; margin-bottom: 26px; }}
.gate-mark img {{ max-width: 150px; height: auto; }}
.gate h1 {{ font-size: 19px; font-weight: 650; letter-spacing: -.025em; margin-bottom: 8px; }}
.gate p {{ font-size: 13.5px; color: var(--ink-2); line-height: 1.6; }}
.gate .go {{
  display: flex; align-items: center; justify-content: center; gap: 10px;
  margin-top: 26px; padding: 12px 18px; border-radius: var(--r-sm);
  background: var(--panel-2); border: 1px solid var(--line-2);
  font-size: 14px; font-weight: 600; cursor: pointer;
}}
.gate .go:hover {{ border-color: var(--brand); background: var(--brand-wash); }}
.gate .tag {{
  display: inline-block; margin-top: 18px; padding: 6px 11px; border-radius: var(--r-xs);
  font-family: var(--mono); font-size: 12px; background: var(--neg-wash); color: var(--neg);
  border: 1px solid color-mix(in srgb, var(--neg) 30%, transparent);
}}
.gate ul {{ margin: 18px 0 0; padding-left: 18px; }}
.gate li {{ font-size: 13px; color: var(--ink-2); margin-bottom: 7px; }}
.gate code {{ font-family: var(--mono); font-size: 12.5px; color: var(--brand-2); }}
{extra_css}
</style>
</head>
<body>{corpo}</body>
</html>"""


_SVG_GOOGLE = (
    '<svg width="17" height="17" viewBox="0 0 24 24" aria-hidden="true">'
    '<path fill="#EA4335" d="M12 5c1.6 0 3 .6 4.1 1.6l3.1-3.1C17.3 1.7 14.8 1 12 1 7.5 1 3.7 3.6 1.9 7.3l3.7 2.9C6.5 7.3 9 5 12 5z"/>'
    '<path fill="#4285F4" d="M23.5 12.3c0-.8-.1-1.6-.2-2.3H12v4.5h6.5c-.3 1.5-1.1 2.8-2.4 3.7l3.7 2.9c2.2-2 3.7-5 3.7-8.8z"/>'
    '<path fill="#FBBC05" d="M5.6 14.8c-.2-.7-.4-1.5-.4-2.3s.2-1.6.4-2.3L1.9 7.3C.7 9.2 0 10.5 0 12s.7 2.8 1.9 4.7l3.7-2.9z"/>'
    '<path fill="#34A853" d="M12 23c3.2 0 6-1.1 8-3l-3.7-2.9c-1.1.7-2.5 1.2-4.3 1.2-3 0-5.5-2.3-6.4-5.2L1.9 16c1.8 3.7 5.6 7 10.1 7z"/>'
    "</svg>"
)


def pagina_login(origem, aviso=""):
    url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode({
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": f"{origem}/api/auth/callback",
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "online",
        "prompt": "select_account",
    })
    nota = f'<p style="margin-top:14px;color:var(--brand-2)">{aviso}</p>' if aviso else ""
    corpo = f"""
<main class="gate">
  <div class="gate-mark"><img src="/logo.png?v=4m" alt=""></div>
  <h1>Entrar no painel</h1>
  <p>Este painel é restrito ao time. Use a conta Google que já tem acesso liberado.</p>
  {nota}
  <a class="go" href="{url}">{_SVG_GOOGLE} Continuar com o Google</a>
</main>"""
    return _casca("Entrar — Painel VSL", corpo)


def pagina_negada(email, origem):
    corpo = f"""
<main class="gate">
  <h1>Essa conta não tem acesso</h1>
  <p>O login funcionou, mas este e-mail não está na lista de liberados do painel.
     Peça a liberação a quem administra o projeto ou entre com outra conta.</p>
  <span class="tag">{email}</span>
  <a class="go" href="{origem}/">Entrar com outra conta</a>
</main>"""
    return _casca("Sem acesso — Painel VSL", corpo)


def pagina_configuracao(pendencias):
    itens = "".join(
        f"<li><code>{chave}</code> — {desc}</li>" for chave, desc in pendencias
    )
    corpo = f"""
<main class="gate">
  <h1>Falta configurar o ambiente</h1>
  <p>O painel não sobe sem estas variáveis de ambiente. Defina-as no seu deploy e
     recarregue a página.</p>
  <ul>{itens}</ul>
  <p style="margin-top:18px;font-size:12.5px;color:var(--ink-3)">
     Nunca deixe esses valores escritos no código: qualquer chave que já tenha
     circulado fora do cofre precisa ser rotacionada antes de voltar ao ar.</p>
</main>"""
    return _casca("Configuração — Painel VSL", corpo)


# ==========================================================
# 8. MARCAÇÃO DO PAINEL
# ==========================================================

_ICONS = {
    "overview": '<path d="M3 13h5l2 5 4-13 2 8h5"/>',
    "creatives": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M10 9l5 3-5 3z"/>',
    "retention": '<path d="M3 5v14h18"/><path d="M6 8c4 0 5 8 12 9"/>',
    "ab": '<path d="M4 4h6v6H4zM14 14h6v6h-6z"/><path d="M10 7h4a3 3 0 0 1 3 3v4"/>',
    "tracking": '<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="3.5"/>'
                '<path d="M12 1.5V4M12 20v2.5M1.5 12H4M20 12h2.5"/>',
    "maturity": '<rect x="3" y="8" width="18" height="8" rx="2.5"/><path d="M8 8v8"/><path d="M13 8v8"/>',
    "readout": '<rect x="3.5" y="3.5" width="17" height="17" rx="3"/><path d="M8 12.5l2.6 2.6L16 9.5"/>',
    "tg": '<path d="M4 20V10M10 20V4M16 20v-7"/><path d="M3 7l6-3 6 5 6-4"/>',
}


def _nav_link(view, rotulo, atalho, ativo=False):
    marca = ' aria-current="page"' if ativo else ""
    alvo = f"v-{view}"
    return (
        f'<a href="#{alvo}" data-view="{alvo}"{marca}>'
        f'<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        f'stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">{_ICONS[view]}</svg>'
        f"{rotulo}<span class=\"kbd\">{atalho}</span></a>"
    )


_VIEWS = """
<!-- ============ VISÃO GERAL ============ -->
<section id="v-overview" class="view on">

  <div class="block" style="padding-top:28px">
    <div id="verdict"></div>
  </div>

  <div class="block">
    <div class="block-head">
      <div>
        <h2>Números do período</h2>
        <p id="baselineNote">Escolha um período de comparação para ver a variação de cada número.</p>
      </div>
    </div>
    <div class="ticker" id="ticker"></div>
  </div>

  <div class="block">
    <div class="block-head">
      <div>
        <h2>O que o painel está vendo</h2>
        <p>Leituras geradas a partir dos dados do período, não de regras fixas de mercado.</p>
      </div>
    </div>
    <div class="notes" id="notes"></div>
  </div>

  <div class="block">
    <div class="block-head">
      <div>
        <h2>Onde o público some</h2>
        <p>Cada etapa mostra quanto sobrou da anterior. A maior queda fica destacada.</p>
      </div>
    </div>
    <div class="panel panel-pad"><div class="funnel" id="funnel"></div></div>
  </div>

  <div class="block">
    <div class="block-head">
      <div>
        <h2>Evolução por semana de criativo</h2>
        <p>Compara as coortes entre si e, se houver base, com o mesmo recorte do período anterior.</p>
      </div>
      <div class="spacer"></div>
      <div class="segmented" id="trendPicker" role="group" aria-label="Métrica do gráfico">
        <button data-metric="play_rate" aria-pressed="true">Play rate</button>
        <button data-metric="ctr" aria-pressed="false">Cliques no CTA</button>
        <button data-metric="conversion_rate" aria-pressed="false">Conversão</button>
        <button data-metric="retention" aria-pressed="false">Retenção</button>
        <button data-metric="aov" aria-pressed="false">Ticket médio</button>
        <button data-metric="revenue" aria-pressed="false">Faturamento</button>
      </div>
    </div>
    <div class="panel panel-pad" id="trend"></div>
  </div>
</section>

<!-- ============ CRIATIVOS ============ -->
<section id="v-creatives" class="view">
  <div class="block" style="padding-top:28px">
    <div class="block-head">
      <div>
        <h2>Ranking de criativos</h2>
        <p>Clique num cabeçalho para reordenar, ou numa linha para abrir o criativo.</p>
      </div>
      <div class="spacer"></div>
      <button class="btn btn-sm" data-act="export-csv">Baixar CSV</button>
    </div>
    <div class="grid-wrap">
      <div class="scroll-x">
        <table class="grid">
          <thead id="rankHead">
            <tr>
              <th style="width:34px"></th>
              <th>Criativo</th>
              <th class="r" data-sort="unique_views" title="Visitas únicas">Visitas<span class="caret"></span></th>
              <th class="r" data-sort="play_rate" title="Quantos de quem abriu a página deram play">Play<span class="caret"></span></th>
              <th class="r" data-sort="retention" title="Quantos de quem deu play chegaram na oferta">Na oferta<span class="caret"></span></th>
              <th class="r" data-sort="ctr" title="Quantos de quem deu play clicaram no CTA">CTA<span class="caret"></span></th>
              <th class="r" data-sort="conversion_rate" title="Quantos de quem deu play compraram">Converte<span class="caret"></span></th>
              <th class="r" data-sort="aov" title="Ticket médio por venda">Ticket<span class="caret"></span></th>
              <th class="r" data-sort="epv" title="Receita por visita única">Por visita<span class="caret"></span></th>
              <th class="r" data-sort="health" title="Nota de 0 a 100 comparando o criativo com a média do período">Saúde<span class="caret"></span></th>
              <th class="r" data-sort="revenue">Faturamento<span class="caret"></span></th>
            </tr>
          </thead>
          <tbody id="rankBody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <div class="block">
    <div class="block-head">
      <div>
        <h2>Quem prende e quem converte</h2>
        <p>Play rate no eixo horizontal, clique no CTA no vertical. As linhas cortam nas médias do período; o tamanho do ponto acompanha o faturamento.</p>
      </div>
    </div>
    <div class="panel panel-pad" id="matrix"></div>
  </div>

  <div class="block">
    <div class="block-head">
      <div>
        <h2>Criativos por semana</h2>
        <p>Abra uma semana para ver os vídeos dela.</p>
      </div>
      <div class="spacer"></div>
      <div class="field">
        <input type="text" id="search" placeholder="Buscar por nome, produto ou ID" autocomplete="off">
      </div>
    </div>
    <div id="cohorts"></div>
  </div>
</section>

<!-- ============ TG BRANDS ============ -->
<section id="v-tg" class="view">
  <div class="block" style="padding-top:28px">
    <div class="block-head">
      <div>
        <h2>TG Brands: tráfego x faturamento</h2>
        <p id="tgNote">Todos os brands do TG somados, dia a dia. As variações comparam com o mesmo número de dias imediatamente antes.</p>
      </div>
      <div class="spacer"></div>
      <div class="field">
        <label for="tgBrand">Recorte</label>
        <select id="tgBrand"><option value="">Todos os brands</option></select>
      </div>
    </div>
    <div class="ticker" id="tgTicker"></div>
  </div>

  <div class="block">
    <div class="block-head">
      <div>
        <h2 id="tgVslTitle">VSLs do brand</h2>
        <p>Como o tráfego do brand se divide entre as VSLs e quanto cada uma devolve em faturamento.
           "Configurado" é a divisão do teste na vTurb, digitada aqui.</p>
      </div>
    </div>
    <div id="tgVslSummary"></div>
    <div class="grid-wrap" id="tgVslWrap"><div class="scroll-x">
      <table class="grid tg-grid">
        <thead><tr>
          <th>VSL</th>
          <th class="r" title="Divisão configurada no teste A/B da vTurb. Digite e salve: fica guardada para todo o time">Configurado</th>
          <th class="r" id="tgVslUltimo" title="Parte das visitas do brand no último dia completo: é o mais perto da divisão configurada hoje">Último dia</th>
          <th class="r">Visitas únicas</th>
          <th class="r">Vendas</th>
          <th title="Faturamento da VSL e quanto ele representa do faturamento do brand">Faturamento</th>
          <th class="r" title="Faturamento / visitas únicas">Por visita</th>
        </tr></thead>
        <tbody id="tgVsls"></tbody>
      </table>
    </div></div>
    <div class="tg-savebar" id="tgSaveBar"></div>
  </div>

  <div class="block">
    <div class="block-head">
      <div>
        <h2>O que os números dizem</h2>
        <p>Faturamento = visitas x receita por visita. Separar os dois mostra se o resultado veio de volume ou de eficiência.</p>
      </div>
    </div>
    <div class="notes" id="tgNotes"></div>
  </div>

  <div class="block">
    <div class="block-head">
      <div>
        <h2>Tráfego e faturamento por dia</h2>
        <p>Barras: visitas únicas (eixo da esquerda). Linha: faturamento (eixo da direita).</p>
      </div>
    </div>
    <div class="panel panel-pad" id="tgChart"></div>
  </div>

  <div class="block">
    <div class="block-head">
      <div>
        <h2>Receita por visita, dia a dia</h2>
        <p>Quanto cada visita rendeu. Se o tráfego sobe e essa linha cai, o volume novo está entrando mais frio.</p>
      </div>
    </div>
    <div class="panel panel-pad" id="tgRpv"></div>
  </div>

  <div class="block">
    <div class="block-head">
      <div>
        <h2>Dia a dia</h2>
      </div>
      <div class="spacer"></div>
      <button class="btn btn-sm" data-act="export-tg">Baixar CSV</button>
    </div>
    <div class="grid-wrap"><div class="scroll-x">
      <table class="grid tg-grid">
        <thead><tr>
          <th>Dia</th>
          <th class="r">Visitas únicas</th>
          <th class="r">Plays únicos</th>
          <th class="r">Play rate</th>
          <th class="r">Vendas</th>
          <th class="r" title="Vendas / plays únicos">Conversão</th>
          <th class="r">Ticket</th>
          <th class="r" title="Faturamento / visitas únicas">Por visita</th>
          <th class="r">Faturamento</th>
        </tr></thead>
        <tbody id="tgDays"></tbody>
      </table>
    </div></div>
  </div>

  <div class="block">
    <div class="block-head">
      <div>
        <h2>Por brand</h2>
        <p id="tgBrandNote">Clique num brand para ver só ele nos gráficos.</p>
      </div>
    </div>
    <div class="grid-wrap"><div class="scroll-x">
      <table class="grid tg-grid">
        <thead><tr>
          <th>Brand</th>
          <th class="r">Visitas únicas</th>
          <th class="r">Vendas</th>
          <th class="r" title="Faturamento / visitas únicas">Por visita</th>
          <th class="r">Faturamento</th>
          <th class="r">vs anterior</th>
          <th>Faturamento por dia</th>
        </tr></thead>
        <tbody id="tgBrands"></tbody>
      </table>
    </div></div>
  </div>
</section>
"""

_OVERLAYS = """
<div id="scrim" class="scrim" role="dialog" aria-modal="true" aria-label="Detalhe do criativo">
  <div class="sheet"><button class="sheet-x" data-act="close-sheet" aria-label="Fechar">&#10005;</button><div id="sheetBody"></div></div>
</div>

<div id="palette" role="dialog" aria-modal="true" aria-label="Buscar e navegar">
  <div class="palette-box">
    <input type="text" id="paletteInput" placeholder="Buscar criativo, seção ou período" autocomplete="off" spellcheck="false">
    <div class="palette-list" id="paletteList"></div>
  </div>
</div>

<div id="tip" role="tooltip"></div>
<div id="toasts" aria-live="polite"></div>
<div id="loadbar"></div>
"""


# ==========================================================
# 9. COMPORTAMENTO DO PAINEL (JS)
# ==========================================================

_JS = r"""
'use strict';

/* =========================================================
   ESTADO
   ========================================================= */
const S = {
  current: [], previous: [],
  videos: [], prevById: new Map(), byId: new Map(),
  agg: {}, prevAgg: {}, avgs: {}, champion: null,
  hasBase: false,
  weeksNow: [], weeksWas: [],
  sortKey: 'revenue', sortDir: 'desc',
  trendMetric: 'play_rate',
  retention: [], retentionHidden: new Set(),
  view: 'v-overview',
  teste: null,
  tg: null, tgKey: null, tgBrand: '',
  inflight: null
};

const SERIES_COLORS = ['#6e5bff','#22d3ee','#2dd4a7','#ffb020','#ff5c7a','#a78bfa','#38bdf8','#f472b6','#84cc16','#fb923c','#4ade80','#c084fc'];

const $  = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

/* =========================================================
   FORMATAÇÃO
   ========================================================= */
const _int   = new Intl.NumberFormat('pt-BR', { maximumFractionDigits: 0 });
const _short = new Intl.NumberFormat('pt-BR', { notation: 'compact', maximumFractionDigits: 1 });
const _money = new Intl.NumberFormat('pt-BR', { style: 'currency', currency: 'BRL' });
const _moneyShort = new Intl.NumberFormat('pt-BR', { style: 'currency', currency: 'BRL', notation: 'compact', maximumFractionDigits: 1 });

const fInt   = v => _int.format(Math.round(v || 0));
const fShort = v => Math.abs(v || 0) >= 10000 ? _short.format(v || 0) : _int.format(Math.round(v || 0));
const fMoney = v => _money.format(v || 0);
const fMoneyShort = v => Math.abs(v || 0) >= 10000 ? _moneyShort.format(v || 0) : _money.format(v || 0);
const fPct   = (v, d) => (v || 0).toFixed(d === undefined ? 2 : d).replace('.', ',') + '%';
const fPP    = v => (v > 0 ? '+' : '') + (v || 0).toFixed(1).replace('.', ',') + ' p.p.';
const fRel   = v => (v > 0 ? '+' : '') + (v || 0).toFixed(1).replace('.', ',') + '%';

function fTime(sec) {
  sec = Math.max(0, Math.round(sec || 0));
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
  const p = n => String(n).padStart(2, '0');
  return h > 0 ? h + ':' + p(m) + ':' + p(s) : m + ':' + p(s);
}

function esc(txt) {
  return String(txt == null ? '' : txt)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/* =========================================================
   DATAS
   ========================================================= */
const iso = d => d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
const parseISO = s => { const [y, m, d] = String(s).split('-').map(Number); return new Date(y, m - 1, d); };
const brDate = s => s ? String(s).split('-').reverse().join('/') : '';
const shiftDays = (d, n) => { const x = new Date(d); x.setDate(x.getDate() + n); return x; };
const daysBetween = (a, b) => Math.round((parseISO(b) - parseISO(a)) / 86400000) + 1;

function rangePreset(key) {
  const hoje = new Date();
  const first = new Date(hoje.getFullYear(), hoje.getMonth(), 1);
  switch (key) {
    case 'hoje':     return [iso(hoje), iso(hoje)];
    case 'ontem':    { const o = shiftDays(hoje, -1); return [iso(o), iso(o)]; }
    case '7':        return [iso(shiftDays(hoje, -6)), iso(hoje)];
    case '14':       return [iso(shiftDays(hoje, -13)), iso(hoje)];
    case '30':       return [iso(shiftDays(hoje, -29)), iso(hoje)];
    case 'mes':      return [iso(first), iso(hoje)];
    case 'mes-1':    { const a = new Date(hoje.getFullYear(), hoje.getMonth() - 1, 1);
                       const b = new Date(hoje.getFullYear(), hoje.getMonth(), 0);
                       return [iso(a), iso(b)]; }
    case 'ano':      return [hoje.getFullYear() + '-01-01', iso(hoje)];
    default:         return null;
  }
}

/** Período anterior de mesmo tamanho, terminando na véspera do início. */
function autoBaseline(inicio, fim) {
  const dias = daysBetween(inicio, fim);
  const bFim = shiftDays(parseISO(inicio), -1);
  const bIni = shiftDays(bFim, -(dias - 1));
  return [iso(bIni), iso(bFim)];
}

/* =========================================================
   TEMA
   ========================================================= */
function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  try { localStorage.setItem('vsl.theme', t); } catch (e) {}
  const btn = $('#themeBtn');
  if (btn) {
    btn.textContent = t === 'light' ? 'Escuro' : 'Claro';
    btn.setAttribute('aria-label', t === 'light' ? 'Mudar para o tema escuro' : 'Mudar para o tema claro');
  }
  if (S.retention.length) drawRetention();
  if (S.weeksNow.length) drawTrend();
}

function toggleTheme() {
  applyTheme(document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light');
}

/* =========================================================
   NAVEGAÇÃO, AVISOS, PROGRESSO
   ========================================================= */
function goView(id, push) {
  if (!$('#' + id)) return;
  S.view = id;
  $$('.view').forEach(v => v.classList.toggle('on', v.id === id));
  $$('.nav a').forEach(a => {
    if (a.dataset.view === id) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  });
  document.body.classList.remove('rail-open');
  if (push !== false && location.hash !== '#' + id) history.replaceState(null, '', '#' + id);
  if (id === 'v-tg') loadTg();
  window.scrollTo({ top: 0, behavior: 'instant' in window ? 'instant' : 'auto' });
}

function toast(msg, kind) {
  const box = $('#toasts');
  const el = document.createElement('div');
  el.className = 'toast' + (kind ? ' ' + kind : '');
  el.textContent = msg;
  box.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 250); }, 4200);
}

let barTimer = null;
function loadbar(on) {
  const bar = $('#loadbar');
  clearInterval(barTimer);
  if (on) {
    let p = 8;
    bar.classList.add('on'); bar.style.width = p + '%';
    barTimer = setInterval(() => { p += (92 - p) * 0.12; bar.style.width = p + '%'; }, 220);
  } else {
    bar.style.width = '100%';
    setTimeout(() => { bar.classList.remove('on'); bar.style.width = '0'; }, 260);
  }
}

/* =========================================================
   TOOLTIP DE GRÁFICO
   ========================================================= */
function showTip(evt, html) {
  const tip = $('#tip');
  tip.innerHTML = html;
  tip.style.display = 'block';
  const r = tip.getBoundingClientRect();
  let x = evt.clientX + 14, y = evt.clientY - 12;
  if (x + r.width > window.innerWidth - 12) x = evt.clientX - r.width - 14;
  if (y + r.height > window.innerHeight - 12) y = window.innerHeight - r.height - 12;
  tip.style.left = Math.max(8, x) + 'px';
  tip.style.top = Math.max(8, y) + 'px';
}
function hideTip() { $('#tip').style.display = 'none'; }

/* =========================================================
   FILTROS E CARREGAMENTO
   ========================================================= */
function readFilters() {
  return {
    start: $('#fStart').value,
    end: $('#fEnd').value,
    baseStart: $('#fBaseStart').value,
    baseEnd: $('#fBaseEnd').value,
    campaign: $('#fCampaign').value.trim(),
    auto: $('#fAuto').checked
  };
}

function syncBaselineFields() {
  const f = readFilters();
  if (f.auto && f.start && f.end) {
    const [bi, bf] = autoBaseline(f.start, f.end);
    $('#fBaseStart').value = bi;
    $('#fBaseEnd').value = bf;
    const picker = $('#baseRange')._flatpickr;
    if (picker) picker.setDate([parseISO(bi), parseISO(bf)], false);
  }
  // O campo de comparação fica sempre liberado: a base automática só preenche
  // as datas sugeridas, e escolher outras na mão desliga o automático.
  $('#baseRange').disabled = false;
}

function setRange(inicio, fim) {
  $('#fStart').value = inicio;
  $('#fEnd').value = fim;
  const picker = $('#mainRange')._flatpickr;
  if (picker) picker.setDate([parseISO(inicio), parseISO(fim)], false);
  syncBaselineFields();
  markPreset(inicio, fim);
}

function markPreset(inicio, fim) {
  $$('#presets button').forEach(b => {
    const r = rangePreset(b.dataset.range);
    b.setAttribute('aria-pressed', String(!!r && r[0] === inicio && r[1] === fim));
  });
}

function pushUrl() {
  const f = readFilters();
  const q = new URLSearchParams({ start: f.start, end: f.end });
  if (f.baseStart && f.baseEnd) { q.set('comp_start', f.baseStart); q.set('comp_end', f.baseEnd); }
  if (f.campaign) q.set('campanha', f.campaign);
  history.replaceState(null, '', '/?' + q.toString() + (location.hash || ''));
}

function skeletons() {
  $('#ticker').innerHTML = Array.from({ length: 8 }, () =>
    '<div class="tick"><div class="skel" style="height:12px;width:60%"></div>' +
    '<div class="skel" style="height:26px;width:78%;margin:9px 0 6px"></div>' +
    '<div class="skel" style="height:11px;width:44%"></div></div>').join('');
  $('#verdict').innerHTML = '<div class="skel" style="height:88px;border-radius:13px"></div>';
  $('#notes').innerHTML = Array.from({ length: 3 }, () =>
    '<div class="skel" style="height:110px;border-radius:9px"></div>').join('');
  $('#rankBody').innerHTML = '<tr><td colspan="11" style="padding:0"><div class="skel" style="height:220px"></div></td></tr>';
}

/** Lê a resposta sem estourar um erro de parse quando vem HTML.
 *  Se o servidor devolver uma página, a mensagem diz isso em vez de
 *  "Unexpected token '<'", que não ajuda ninguém a consertar nada. */
async function lerJson(res, rota) {
  const bruto = await res.text();
  let dados = null;
  try { dados = JSON.parse(bruto); } catch (e) { dados = null; }

  if (dados === null) {
    const pagina = bruto.trim().slice(0, 15).toLowerCase().includes('<!doctype');
    throw new Error(pagina
      ? 'A rota ' + rota + ' devolveu uma página HTML em vez de dados. ' +
        'O deploy provavelmente não está encaminhando essa rota para a função.'
      : 'Resposta ilegível de ' + rota + ' (HTTP ' + res.status + ').');
  }
  if (!res.ok) throw new Error(dados.error || ('Erro ' + res.status + ' em ' + rota));
  return dados;
}

async function loadData(opts) {
  opts = opts || {};
  const f = readFilters();
  if (!f.start || !f.end) { toast('Escolha um período para consultar.', 'err'); return; }

  if (S.inflight) S.inflight.abort();
  const ctrl = new AbortController();
  S.inflight = ctrl;

  if (opts.skeleton !== false) skeletons();
  loadbar(true);
  pushUrl();
  if (S.view === 'v-tg') loadTg();

  // is_api=true é o que faz a rota ser reconhecida mesmo quando o deploy
  // reescreve o caminho antes de entregar à função.
  const q = new URLSearchParams({ start: f.start, end: f.end, is_api: 'true' });
  if (f.baseStart && f.baseEnd) { q.set('comp_start', f.baseStart); q.set('comp_end', f.baseEnd); }
  if (f.campaign) q.set('campanha', f.campaign);

  try {
    const res = await fetch('/api/data?' + q.toString(), { credentials: 'include', signal: ctrl.signal });
    if (res.status === 401) { location.href = '/'; return; }

    const data = await lerJson(res, '/api/data');
    S.current = data.estrutura || [];
    S.previous = data.estrutura_anterior || [];
    S.hasBase = !!(f.baseStart && f.baseEnd) && S.previous.length > 0;

    $('#periodLabel').textContent = brDate(f.start) + ' a ' + brDate(f.end);
    $('#baselineNote').textContent = S.hasBase
      ? 'Comparando com ' + brDate(f.baseStart) + ' a ' + brDate(f.baseEnd) + '.'
      : 'Sem período de comparação: as variações ficam ocultas.';

    renderAll();
    loadbar(false);
  } catch (err) {
    if (err.name === 'AbortError') return;
    loadbar(false);
    console.error(err);
    $('#verdict').innerHTML = '<div class="blank"><b>Não deu para carregar os dados</b>' +
      esc(err.message) + '<br><br><a href="/?diag=1" target="_blank" style="color:var(--brand-2)">' +
      'Abrir o diagnóstico do servidor</a></div>';
    $('#ticker').innerHTML = '';
    $('#notes').innerHTML = '';
    $('#rankBody').innerHTML = '';
    toast('Falha ao carregar. Tente novamente.', 'err');
  } finally {
    S.inflight = null;
  }
}
"""

_JS += r"""
/* =========================================================
   MÉTRICAS
   ========================================================= */
function rates(s) {
  s = s || {};
  const views       = s.views || 0;
  const uViews      = s.unique_views || 0;
  const plays       = s.plays || 0;
  const uPlays      = s.unique_plays || 0;
  const pitch       = s.pitch_audience || 0;
  const clicks      = s.button_clicks || 0;
  const conv        = s.conversions || 0;
  const revenue     = s.revenue || 0;

  return {
    views, unique_views: uViews, plays, unique_plays: uPlays,
    pitch_audience: pitch, button_clicks: clicks, conversions: conv, revenue,
    engagement: s.engagement || 0,
    play_rate:       uViews  > 0 ? (uPlays / uViews) * 100 : 0,
    retention:       uPlays  > 0 ? (pitch / uPlays) * 100 : 0,
    ctr:             uPlays  > 0 ? (clicks / uPlays) * 100 : 0,
    cta_efficiency:  pitch   > 0 ? (clicks / pitch) * 100 : 0,
    conversion_rate: uPlays  > 0 ? (conv / uPlays) * 100 : 0,
    checkout_rate:   clicks  > 0 ? (conv / clicks) * 100 : 0,
    aov:             conv    > 0 ? revenue / conv : 0,
    epc:             clicks  > 0 ? revenue / clicks : 0,
    epv:             uViews  > 0 ? revenue / uViews : 0
  };
}

function aggregate(videos) {
  const t = (videos || []).reduce((a, v) => {
    const s = v.stats || {};
    a.views += s.views || 0;
    a.unique_views += s.unique_views || 0;
    a.plays += s.plays || 0;
    a.unique_plays += s.unique_plays || 0;
    a.pitch_audience += s.pitch_audience || 0;
    a.button_clicks += s.button_clicks || 0;
    a.conversions += s.conversions || 0;
    a.revenue += s.revenue || 0;
    return a;
  }, { views: 0, unique_views: 0, plays: 0, unique_plays: 0, pitch_audience: 0, button_clicks: 0, conversions: 0, revenue: 0 });
  return rates(t);
}

function median(arr) {
  if (!arr.length) return 0;
  const s = [...arr].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

/** Médias por criativo — usadas como referência para saúde e quadrantes.
 *  Só entram criativos com volume mínimo, senão um vídeo com 3 views
 *  distorce a régua de todos os outros. */
function averages(videos) {
  const base = { play_rate: 0, ctr: 0, retention: 0, conversion_rate: 0, aov: 0, epv: 0, epc: 0, n: 0, medianViews: 0 };
  const validos = (videos || []).filter(v => (v.stats.unique_views || 0) >= 30);
  if (!validos.length) return base;

  const acc = validos.reduce((a, v) => {
    const r = rates(v.stats);
    a.play_rate += r.play_rate; a.ctr += r.ctr; a.retention += r.retention;
    a.conversion_rate += r.conversion_rate; a.aov += r.aov; a.epv += r.epv; a.epc += r.epc;
    return a;
  }, { play_rate: 0, ctr: 0, retention: 0, conversion_rate: 0, aov: 0, epv: 0, epc: 0 });

  const n = validos.length;
  Object.keys(acc).forEach(k => { acc[k] = acc[k] / n; });
  acc.n = n;
  acc.medianViews = median(validos.map(v => v.stats.unique_views || 0));
  return acc;
}

/** Saúde: quanto o criativo entrega em relação à média do próprio período.
 *  100 = o dobro da média em tudo. Devolve as partes para poder explicar. */
const HEALTH_PARTS = [
  { key: 'play_rate',       ref: 'play_rate',       weight: 0.20, label: 'Play rate' },
  { key: 'retention',       ref: 'retention',       weight: 0.15, label: 'Chega na oferta' },
  { key: 'ctr',             ref: 'ctr',             weight: 0.20, label: 'Clica no CTA' },
  { key: 'conversion_rate', ref: 'conversion_rate', weight: 0.25, label: 'Converte' },
  { key: 'epv',             ref: 'epv',             weight: 0.20, label: 'Receita por visita' }
];

function health(r, avgs) {
  avgs = avgs || S.avgs;
  let score = 0;
  const parts = HEALTH_PARTS.map(p => {
    const ref = avgs[p.ref] || 0;
    const ratio = ref > 0 ? (r[p.key] || 0) / ref : 0;
    const pts = Math.min(ratio, 2) / 2 * 100;
    score += p.weight * pts;
    return { label: p.label, ratio, weight: p.weight };
  });
  return { score: Math.round(Math.max(0, Math.min(100, score))), parts };
}

function healthTier(score) {
  if (score >= 80) return { label: 'Escalar', cls: 'good' };
  if (score >= 60) return { label: 'Saudável', cls: 'info' };
  if (score >= 40) return { label: 'Observar', cls: 'mid' };
  return { label: 'Rever', cls: 'bad' };
}

/* =========================================================
   ESTATÍSTICA
   ========================================================= */
function erf(x) {
  const sign = x < 0 ? -1 : 1;
  x = Math.abs(x);
  const a1 = 0.254829592, a2 = -0.284496736, a3 = 1.421413741,
        a4 = -1.453152027, a5 = 1.061405429, p = 0.3275911;
  const t = 1 / (1 + p * x);
  const y = 1 - ((((a5 * t + a4) * t + a3) * t + a2) * t + a1) * t * Math.exp(-x * x);
  return sign * y;
}
const normalCdf = z => 0.5 * (1 + erf(z / Math.SQRT2));

/** Teste z de duas proporções + probabilidade de B superar A. */
function compareProportions(xA, nA, xB, nB) {
  if (!nA || !nB) return null;
  const pA = xA / nA, pB = xB / nB;
  const pool = (xA + xB) / (nA + nB);
  const se = Math.sqrt(pool * (1 - pool) * (1 / nA + 1 / nB));
  const z = se > 0 ? (pB - pA) / se : 0;
  const pValue = 2 * (1 - normalCdf(Math.abs(z)));

  const seDiff = Math.sqrt((pA * (1 - pA)) / nA + (pB * (1 - pB)) / nB);
  const probB = seDiff > 0 ? normalCdf((pB - pA) / seDiff) : 0.5;

  return {
    pA, pB, z, pValue,
    confidence: (1 - pValue) * 100,
    probB: probB * 100,
    uplift: pA > 0 ? ((pB - pA) / pA) * 100 : (pB > 0 ? 100 : 0),
    absDiff: (pB - pA) * 100,
    significant: pValue < 0.05,
    nA, nB, xA, xB
  };
}

/** Amostra necessária por braço para detectar o efeito observado
 *  com 95% de confiança e 80% de poder. */
function requiredPerArm(pA, pB) {
  if (!(pA > 0) || !(pB > 0) || pA === pB) return null;
  const zA = 1.959964, zB = 0.8416212;
  const pbar = (pA + pB) / 2;
  const termo = zA * Math.sqrt(2 * pbar * (1 - pbar)) + zB * Math.sqrt(pA * (1 - pA) + pB * (1 - pB));
  const n = Math.pow(termo, 2) / Math.pow(pB - pA, 2);
  return Math.ceil(n);
}

/* =========================================================
   MOTOR DE LEITURAS
   ========================================================= */
const FUNNEL_ADVICE = {
  'plays': { causa: 'a thumbnail e os primeiros segundos', acao: 'Teste outra abertura, outro frame de capa e revise a promessa da página.' },
  'pitch': { causa: 'o meio do vídeo', acao: 'Encurte o trecho anterior à oferta e reforce a curiosidade nos minutos de maior queda.' },
  'clicks': { causa: 'a oferta e o CTA', acao: 'Reveja preço, garantia e a insistência do botão logo após o pitch.' },
  'conversions': { causa: 'a página de checkout', acao: 'O criativo entregou o clique. Investigue preço na página, métodos de pagamento e velocidade do checkout.' }
};

function buildInsights() {
  const out = [];
  const vids = S.videos.filter(v => (v.stats.unique_views || 0) > 0);
  const a = S.agg, avgs = S.avgs;
  if (!vids.length) return out;

  const comVolume = vids.filter(v => (v.stats.unique_views || 0) >= Math.max(100, avgs.medianViews * 0.3));

  /* 1. Gargalo do funil */
  const etapas = [
    { key: 'views', nome: 'visitas', valor: a.views },
    { key: 'plays', nome: 'plays', valor: a.plays },
    { key: 'pitch', nome: 'público na oferta', valor: a.pitch_audience },
    { key: 'clicks', nome: 'cliques no CTA', valor: a.button_clicks },
    { key: 'conversions', nome: 'vendas', valor: a.conversions }
  ];
  let pior = null;
  for (let i = 1; i < etapas.length; i++) {
    const antes = etapas[i - 1].valor;
    if (!antes) continue;
    const perda = (1 - etapas[i].valor / antes) * 100;
    if (!pior || perda > pior.perda) pior = { perda, de: etapas[i - 1], para: etapas[i] };
  }
  if (pior) {
    const dica = FUNNEL_ADVICE[pior.para.key] || {};
    out.push({
      sev: pior.perda > 80 ? 'crit' : 'warn',
      hero: true,
      title: 'A maior perda está entre ' + pior.de.nome + ' e ' + pior.para.nome,
      body: 'De cada 100 pessoas que chegam em "' + pior.de.nome + '", ' + Math.round(pior.perda) +
            ' não avançam. O ponto a atacar é ' + (dica.causa || 'essa transição') + '.',
      todo: dica.acao || ''
    });
  }

  /* 2. Concentração de faturamento */
  const porReceita = [...vids].sort((x, y) => (y.stats.revenue || 0) - (x.stats.revenue || 0));
  const receitaTotal = a.revenue;
  if (receitaTotal > 0 && porReceita.length >= 4) {
    let soma = 0, quantos = 0;
    for (const v of porReceita) { soma += v.stats.revenue || 0; quantos++; if (soma / receitaTotal >= 0.8) break; }
    const fatia = quantos / porReceita.length;
    if (fatia <= 0.25) {
      out.push({
        sev: 'warn',
        title: 'O faturamento depende de poucos criativos',
        body: quantos + ' de ' + porReceita.length + ' vídeos respondem por 80% da receita do período. ' +
              'Se um deles saturar, a operação sente na mesma semana.',
        todo: 'Coloque variações do vencedor em teste antes de precisar delas.',
        videoId: porReceita[0].id,
        linkText: 'Ver ' + porReceita[0].name
      });
    }
  }

  /* 3. Prende bem, mas não vende */
  const semOferta = comVolume
    .map(v => ({ v, r: rates(v.stats) }))
    .filter(x => avgs.play_rate > 0 && avgs.ctr > 0 &&
                 x.r.play_rate >= avgs.play_rate * 1.15 &&
                 x.r.ctr <= avgs.ctr * 0.7 &&
                 x.r.unique_plays >= 150)
    .sort((x, y) => y.r.unique_plays - x.r.unique_plays);

  semOferta.slice(0, 2).forEach(x => {
    out.push({
      sev: 'warn',
      title: 'Abertura forte, oferta fraca',
      body: esc(x.v.name) + ' tem play rate ' + fPct(x.r.play_rate, 1) + ' contra ' + fPct(avgs.play_rate, 1) +
            ' da média, mas só ' + fPct(x.r.ctr, 1) + ' clicam no CTA. O gancho não é o problema.' +
            (semOferta.length > 2 ? ' Outros ' + (semOferta.length - 2) + ' criativos estão no mesmo caso.' : ''),
      todo: 'Reaproveite essa abertura em outro pitch em vez de mexer no início.',
      videoId: x.v.id, linkText: 'Abrir criativo'
    });
  });

  /* 4. Clica mas não compra — a régua é a média de fechamento do próprio período */
  const mediaFechamento = a.checkout_rate || 0;
  const vazando = comVolume
    .map(v => ({ v, r: rates(v.stats) }))
    .filter(x => x.r.button_clicks >= 40 && mediaFechamento > 0 &&
                 x.r.checkout_rate < mediaFechamento * 0.6)
    .sort((x, y) => y.r.button_clicks - x.r.button_clicks);

  vazando.slice(0, 2).forEach(x => {
    out.push({
      sev: 'crit',
      title: 'O clique acontece, a compra não',
      body: esc(x.v.name) + ' fecha ' + fPct(x.r.checkout_rate, 1) + ' de quem clica, contra ' +
            fPct(mediaFechamento, 1) + ' da operação. São ' + fInt(x.r.button_clicks) + ' cliques para ' +
            fInt(x.r.conversions) + ' vendas: a perda está depois do vídeo.' +
            (vazando.length > 2 ? ' Outros ' + (vazando.length - 2) + ' criativos vazam do mesmo jeito.' : ''),
      todo: 'Compare o preço prometido no vídeo com o da página e teste o checkout em conexão lenta.',
      videoId: x.v.id, linkText: 'Abrir criativo'
    });
  });

  /* 5. Candidatos a escalar */
  const escalar = comVolume
    .map(v => ({ v, r: rates(v.stats) }))
    .filter(x => avgs.epv > 0 && x.r.epv >= avgs.epv * 1.3 && x.r.conversions >= 5)
    .sort((x, y) => y.r.epv - x.r.epv).slice(0, 2);
  escalar.forEach(x => {
    out.push({
      sev: 'good',
      title: 'Pronto para receber mais tráfego',
      body: esc(x.v.name) + ' rende ' + fMoney(x.r.epv) + ' por visita, contra ' + fMoney(avgs.epv) +
            ' da média, com ' + fInt(x.r.conversions) + ' vendas no período.',
      todo: 'Suba o orçamento em degraus e acompanhe se o ticket se mantém.',
      videoId: x.v.id, linkText: 'Abrir criativo'
    });
  });

  /* 6. Queima de tráfego */
  const queimando = comVolume
    .map(v => ({ v, r: rates(v.stats) }))
    .filter(x => x.r.unique_views >= Math.max(400, avgs.medianViews) && x.r.revenue === 0)
    .sort((x, y) => y.r.unique_views - x.r.unique_views).slice(0, 2);
  queimando.forEach(x => {
    out.push({
      sev: 'crit',
      title: 'Recebe tráfego e não devolve nada',
      body: esc(x.v.name) + ' teve ' + fInt(x.r.unique_views) + ' visitas únicas e nenhuma venda no período.',
      todo: 'Pause enquanto reescreve, ou realoque essa verba para o topo do ranking.',
      videoId: x.v.id, linkText: 'Abrir criativo'
    });
  });

  /* 7. Movimentos contra a base */
  if (S.hasBase) {
    const movs = vids.map(v => {
      const p = S.prevById.get(v.id);
      if (!p) return null;
      const agora = v.stats.revenue || 0, antes = p.stats.revenue || 0;
      if (antes < 200) return null;
      return { v, delta: agora - antes, rel: ((agora - antes) / antes) * 100 };
    }).filter(Boolean).sort((x, y) => x.delta - y.delta);

    if (movs.length) {
      const caiu = movs[0], subiu = movs[movs.length - 1];
      if (caiu && caiu.rel < -20) {
        out.push({
          sev: 'warn',
          title: 'Perdeu força em relação à base',
          body: esc(caiu.v.name) + ' faturou ' + fMoney(Math.abs(caiu.delta)) + ' a menos (' + fRel(caiu.rel) + ').',
          todo: 'Confira se o público saturou antes de mexer no criativo.',
          videoId: caiu.v.id, linkText: 'Abrir criativo'
        });
      }
      if (subiu && subiu.rel > 20 && subiu !== caiu) {
        out.push({
          sev: 'good',
          title: 'Ganhou tração em relação à base',
          body: esc(subiu.v.name) + ' faturou ' + fMoney(subiu.delta) + ' a mais (' + fRel(subiu.rel) + ').',
          todo: 'Vale identificar o que mudou e replicar nos irmãos da mesma semana.',
          videoId: subiu.v.id, linkText: 'Abrir criativo'
        });
      }
    }
  }

  /* 8. Amostra pequena */
  if (a.conversions > 0 && a.conversions < 30) {
    out.push({
      sev: 'info',
      title: 'Amostra ainda curta para decidir',
      body: 'São ' + fInt(a.conversions) + ' vendas no período inteiro. Diferenças entre criativos desse tamanho ' +
            'costumam ser ruído.',
      todo: 'Amplie a janela de datas antes de matar ou escalar qualquer coisa.'
    });
  }

  const ordem = { crit: 0, warn: 1, good: 2, info: 3 };
  return out.sort((x, y) => ordem[x.sev] - ordem[y.sev]);
}
"""

_JS += r"""
/* =========================================================
   RENDERIZAÇÃO
   ========================================================= */
function flatten(estrutura) {
  const out = [];
  (estrutura || []).forEach(p => (p.videos || []).forEach(v => out.push(Object.assign({}, v, { folder: p.folder }))));
  return out;
}

function change(agora, antes, tipo) {
  if (!S.hasBase) return '<span class="chg none">&mdash;</span>';
  if (antes === null || antes === undefined) return '<span class="chg none">novo</span>';
  if (tipo === 'rate') {
    const d = (agora || 0) - (antes || 0);
    const cls = Math.abs(d) < 0.3 ? 'flat' : (d > 0 ? 'up' : 'down');
    return '<span class="chg ' + cls + '">' + fPP(d) + '</span>';
  }
  if (!antes) {
    if (!agora) return '<span class="chg flat">0,0%</span>';
    return '<span class="chg up">novo</span>';
  }
  const d = ((agora - antes) / antes) * 100;
  const cls = Math.abs(d) < 1 ? 'flat' : (d > 0 ? 'up' : 'down');
  return '<span class="chg ' + cls + '">' + fRel(d) + '</span>';
}

function renderAll() {
  S.videos = flatten(S.current);
  const anteriores = flatten(S.previous);
  S.prevById = new Map(anteriores.map(v => [v.id, v]));
  S.byId = new Map(S.videos.map(v => [v.id, v]));

  S.agg = aggregate(S.videos);
  S.prevAgg = aggregate(anteriores);
  S.avgs = averages(S.videos);
  S.champion = [...S.videos].sort((a, b) => (b.stats.revenue || 0) - (a.stats.revenue || 0))[0] || null;

  S.weeksNow = weekSeries(S.videos);
  S.weeksWas = weekSeries(anteriores);

  renderTicker();
  renderVerdict();
  renderFunnel();
  drawTrend();
  renderRanking();
  drawMatrix();
  renderCohorts();
}

/* ---------- Faixa de números ---------- */
function renderTicker() {
  const a = S.agg, p = S.prevAgg;
  const itens = [
    { k: 'Faturamento', v: fMoneyShort(a.revenue), c: change(a.revenue, p.revenue), lead: true },
    { k: 'Receita por visita', v: fMoney(a.epv), c: change(a.epv, p.epv), lead: true },
    { k: 'Vendas', v: fInt(a.conversions), c: change(a.conversions, p.conversions) },
    { k: 'Ticket médio', v: fMoney(a.aov), c: change(a.aov, p.aov) },
    { k: 'Visitas únicas', v: fShort(a.unique_views), c: change(a.unique_views, p.unique_views) },
    { k: 'Play rate', v: fPct(a.play_rate, 1), c: change(a.play_rate, p.play_rate, 'rate') },
    { k: 'Chega na oferta', v: fPct(a.retention, 1), c: change(a.retention, p.retention, 'rate') },
    { k: 'Clica no CTA', v: fPct(a.ctr, 1), c: change(a.ctr, p.ctr, 'rate') },
    { k: 'Converte', v: fPct(a.conversion_rate, 2), c: change(a.conversion_rate, p.conversion_rate, 'rate') },
    { k: 'Fecha após clicar', v: fPct(a.checkout_rate, 1), c: change(a.checkout_rate, p.checkout_rate, 'rate') }
  ];
  $('#ticker').innerHTML = itens.map(i =>
    '<div class="tick' + (i.lead ? ' lead' : '') + '">' +
      '<div class="tick-k">' + i.k + '</div>' +
      '<div class="tick-v num">' + i.v + '</div>' + i.c +
    '</div>').join('');
}

/* ---------- Diagnóstico e leituras ---------- */
function renderVerdict() {
  const leituras = buildInsights();
  const heroIdx = leituras.findIndex(l => l.hero);
  const hero = heroIdx >= 0 ? leituras.splice(heroIdx, 1)[0] : leituras.shift();

  if (!hero) {
    $('#verdict').innerHTML = '<div class="blank"><b>Nenhum dado no período</b>' +
      'Amplie as datas ou limpe o filtro de campanha.</div>';
    $('#notes').innerHTML = '';
    return;
  }

  const glifos = { crit: '&#9888;', warn: '&#9679;', good: '&#9650;', info: '&#8505;' };
  $('#verdict').innerHTML =
    '<div class="verdict sev-' + hero.sev + '">' +
      '<div class="verdict-glyph">' + (glifos[hero.sev] || '&#9679;') + '</div>' +
      '<div><h3>' + hero.title + '</h3><p>' + hero.body +
        (hero.todo ? ' <b style="color:var(--ink-1);font-weight:600">' + hero.todo + '</b>' : '') + '</p></div>' +
      (S.champion ? '<div style="text-align:right">' +
        '<div style="font-size:11.5px;color:var(--ink-3)">Maior faturamento</div>' +
        '<button class="note-link" data-open="' + esc(S.champion.id) + '" style="font-size:13.5px">' +
        esc(S.champion.name) + '</button></div>' : '') +
    '</div>';

  $('#notes').innerHTML = leituras.length
    ? leituras.slice(0, 8).map(l =>
        '<article class="note sev-' + l.sev + '">' +
          '<h4>' + l.title + '</h4><p>' + l.body + '</p>' +
          (l.todo ? '<p class="note-do">' + l.todo + '</p>' : '') +
          (l.videoId ? '<button class="note-link" data-open="' + esc(l.videoId) + '">' + esc(l.linkText || 'Abrir') + '</button>' : '') +
        '</article>').join('')
    : '<div class="blank">Nada fora do esperado neste período.</div>';
}

/* ---------- Funil ---------- */
function renderFunnel() {
  const a = S.agg, p = S.prevAgg;
  const etapas = [
    { nome: 'Visitas', desc: 'Carregaram a página', agora: a.views, antes: p.views },
    { nome: 'Deram play', desc: 'Iniciaram o vídeo', agora: a.plays, antes: p.plays },
    { nome: 'Chegaram na oferta', desc: 'Passaram do pitch', agora: a.pitch_audience, antes: p.pitch_audience },
    { nome: 'Clicaram no CTA', desc: 'Foram para o checkout', agora: a.button_clicks, antes: p.button_clicks },
    { nome: 'Compraram', desc: 'Pedido concluído', agora: a.conversions, antes: p.conversions }
  ];

  const topo = etapas[0].agora || 1;
  let piorIdx = -1, piorPerda = -1;
  etapas.forEach((e, i) => {
    if (i === 0) return;
    const antes = etapas[i - 1].agora;
    if (!antes) return;
    const perda = (1 - e.agora / antes) * 100;
    if (perda > piorPerda) { piorPerda = perda; piorIdx = i; }
  });

  $('#funnel').innerHTML = etapas.map((e, i) => {
    const share = topo ? (e.agora / topo) * 100 : 0;
    const anterior = i === 0 ? null : etapas[i - 1].agora;
    const passa = anterior ? (e.agora / anterior) * 100 : 100;
    const perdaTxt = i === 0 ? '<span style="color:var(--ink-3)">ponto de partida</span>'
      : (fPct(passa, 1) + ' seguem');
    return '<div class="stage-row">' +
      '<div><div class="stage-name">' + e.nome + '</div><div class="stage-desc">' + e.desc + '</div></div>' +
      '<div class="stage-bar"><div class="stage-fill" style="width:' + Math.max(share, 0.6).toFixed(2) + '%"></div></div>' +
      '<div class="stage-num">' + fInt(e.agora) + '<em>' + fPct(share, 1) + ' do topo</em></div>' +
      '<div class="stage-drop' + (i === piorIdx ? ' worst' : '') + '">' + perdaTxt + '</div>' +
      '<div class="stage-cmp">' + change(e.agora, e.antes) + '</div>' +
    '</div>';
  }).join('');
}

/* ---------- Tendência por semana ---------- */
function weekSeries(videos) {
  const mapa = new Map();
  (videos || []).forEach(v => {
    if (!/^Semana \d{2}$/.test(v.folder || '')) return;
    if (!mapa.has(v.folder)) mapa.set(v.folder, []);
    mapa.get(v.folder).push(v);
  });
  return Array.from(mapa.keys()).sort().map(w => Object.assign({ week: w }, aggregate(mapa.get(w))));
}

const TREND_META = {
  play_rate:       { label: 'Play rate', money: false },
  ctr:             { label: 'Clica no CTA', money: false },
  conversion_rate: { label: 'Converte', money: false },
  retention:       { label: 'Chega na oferta', money: false },
  aov:             { label: 'Ticket médio', money: true },
  revenue:         { label: 'Faturamento', money: true }
};

function drawTrend() {
  const box = $('#trend');
  const meta = TREND_META[S.trendMetric];
  const mapaNow = new Map(S.weeksNow.map(w => [w.week, w]));
  const mapaWas = new Map(S.weeksWas.map(w => [w.week, w]));
  const semanas = Array.from(new Set([...mapaNow.keys(), ...mapaWas.keys()])).sort();

  if (!semanas.length) {
    box.innerHTML = '<div class="blank"><b>Sem semanas identificadas</b>' +
      'Os nomes precisam seguir o padrão <code>v1s13</code> para o painel montar as coortes.</div>';
    return;
  }

  const comBase = S.hasBase && S.weeksWas.length > 0;
  const fmtV = v => meta.money ? fMoneyShort(v) : fPct(v, 1);

  const W = Math.max(760, semanas.length * (comBase ? 96 : 62));
  const H = 260, padL = 52, padR = 10, padT = 34, padB = 30;
  const alturaUtil = H - padT - padB;

  const valores = [];
  semanas.forEach(s => {
    if (mapaNow.has(s)) valores.push(mapaNow.get(s)[S.trendMetric] || 0);
    if (comBase && mapaWas.has(s)) valores.push(mapaWas.get(s)[S.trendMetric] || 0);
  });
  const teto = Math.max(...valores, 0.0001) * 1.22;
  const y = v => padT + alturaUtil * (1 - v / teto);

  const grade = [0, 0.25, 0.5, 0.75, 1].map(f => {
    const gy = padT + alturaUtil * f;
    const valor = teto * (1 - f);
    return '<line x1="' + padL + '" y1="' + gy.toFixed(1) + '" x2="' + (W - padR) + '" y2="' + gy.toFixed(1) + '" class="g-dash"/>' +
           '<text x="' + (padL - 8) + '" y="' + (gy + 4).toFixed(1) + '" text-anchor="end" class="g-text">' + fmtV(valor) + '</text>';
  }).join('');

  const larguraGrupo = (W - padL - padR) / semanas.length;
  const vao = 5;
  const larguraBarra = comBase ? (larguraGrupo - vao * 3) / 2 : Math.min(larguraGrupo - vao * 2, 40);

  let barras = '', rotulos = '', deltas = '';
  semanas.forEach((s, i) => {
    const gx = padL + i * larguraGrupo;
    const centro = gx + larguraGrupo / 2;
    rotulos += '<text x="' + centro.toFixed(1) + '" y="' + (H - 9) + '" text-anchor="middle" class="g-text">' +
               s.replace('Semana ', 'S') + '</text>';

    const xWas = gx + vao;
    const xNow = comBase ? xWas + larguraBarra + vao : gx + (larguraGrupo - larguraBarra) / 2;

    if (comBase && mapaWas.has(s)) {
      const v = mapaWas.get(s)[S.trendMetric] || 0;
      barras += '<rect class="bar-was" x="' + xWas.toFixed(1) + '" y="' + y(v).toFixed(1) +
        '" width="' + larguraBarra.toFixed(1) + '" height="' + Math.max(alturaUtil - (y(v) - padT), 1).toFixed(1) +
        '" rx="3" data-tip="' + esc(s + '|base|' + fmtV(v)) + '"/>';
    }
    if (mapaNow.has(s)) {
      const v = mapaNow.get(s)[S.trendMetric] || 0;
      barras += '<rect class="bar-now" x="' + xNow.toFixed(1) + '" y="' + y(v).toFixed(1) +
        '" width="' + larguraBarra.toFixed(1) + '" height="' + Math.max(alturaUtil - (y(v) - padT), 1).toFixed(1) +
        '" rx="3" data-tip="' + esc(s + '|atual|' + fmtV(v)) + '"/>';
    }
    if (comBase && mapaNow.has(s) && mapaWas.has(s)) {
      const vn = mapaNow.get(s)[S.trendMetric] || 0, vw = mapaWas.get(s)[S.trendMetric] || 0;
      let texto, cor;
      if (meta.money) {
        const rel = vw ? ((vn - vw) / vw) * 100 : (vn ? 100 : 0);
        texto = fRel(rel);
        cor = Math.abs(rel) < 1 ? 'var(--ink-3)' : (rel > 0 ? 'var(--pos)' : 'var(--neg)');
      } else {
        const pp = vn - vw;
        texto = fPP(pp);
        cor = Math.abs(pp) < 0.3 ? 'var(--ink-3)' : (pp > 0 ? 'var(--pos)' : 'var(--neg)');
      }
      deltas += '<text x="' + centro.toFixed(1) + '" y="' + Math.max(y(Math.max(vn, vw)) - 8, 14).toFixed(1) +
        '" text-anchor="middle" class="g-text" style="fill:' + cor + ';font-weight:600">' + texto + '</text>';
    }
  });

  const legenda = comBase
    ? '<div class="legend"><span class="legend-item" style="cursor:default"><span class="swatch" style="background:var(--brand)"></span>Período atual</span>' +
      '<span class="legend-item" style="cursor:default"><span class="swatch" style="background:var(--ink-3);opacity:.5"></span>Comparação</span></div>'
    : '<div class="legend"><span class="legend-item" style="cursor:default"><span class="swatch" style="background:var(--brand)"></span>' +
      meta.label + ' por semana</span></div>';

  box.innerHTML = legenda + '<svg viewBox="0 0 ' + W + ' ' + H + '" class="chart" preserveAspectRatio="xMidYMid meet">' +
    grade + barras + deltas + rotulos + '</svg>';

  $$('#trend rect[data-tip]').forEach(r => {
    r.addEventListener('mousemove', ev => {
      const [semana, tipo, valor] = r.dataset.tip.split('|');
      showTip(ev, '<div class="tip-h">' + esc(semana) + ' &middot; ' + esc(tipo) + '</div>' +
        '<div class="tip-row"><span>' + meta.label + '</span><b>' + esc(valor) + '</b></div>');
    });
    r.addEventListener('mouseleave', hideTip);
  });
}
"""

_JS += r"""
/* ---------- Ranking ---------- */
function rankedVideos() {
  const linhas = S.videos.map(v => {
    const r = rates(v.stats);
    const h = health(r);
    return Object.assign({}, v, { r, health: h.score, healthParts: h.parts });
  });
  const chave = S.sortKey;
  return linhas.sort((a, b) => {
    const va = chave === 'health' ? a.health : (a.r[chave] || 0);
    const vb = chave === 'health' ? b.health : (b.r[chave] || 0);
    return S.sortDir === 'desc' ? vb - va : va - vb;
  });
}

function renderRanking() {
  const linhas = rankedVideos();
  const maxReceita = Math.max(...linhas.map(l => l.r.revenue), 1);

  $$('#rankHead th[data-sort]').forEach(th => {
    const ativo = th.dataset.sort === S.sortKey;
    if (ativo) th.setAttribute('aria-sort', S.sortDir === 'desc' ? 'descending' : 'ascending');
    else th.removeAttribute('aria-sort');
    th.querySelector('.caret').textContent = ativo ? (S.sortDir === 'desc' ? '\u25BC' : '\u25B2') : '';
  });

  if (!linhas.length) {
    $('#rankBody').innerHTML = '<tr><td colspan="11"><div class="blank"><b>Nenhum criativo com movimento</b>' +
      'Amplie o período ou revise o filtro de campanha.</div></td></tr>';
    return;
  }

  const destaque = k => S.sortKey === k ? ' hot' : '';
  $('#rankBody').innerHTML = linhas.map((l, i) => {
    const r = l.r, t = healthTier(l.health);
    return '<tr data-open="' + esc(l.id) + '">' +
      '<td><span class="pos-idx' + (i < 3 ? ' podium' : '') + '">' + (i + 1) + '</span></td>' +
      '<td title="' + esc(l.name) + '"><div class="cell-title">' + esc(l.name) + '</div>' +
        '<div class="cell-sub"><span>' + esc(l.folder) + '</span>' +
        (l.pitch_at ? '<span>oferta em ' + fTime(l.pitch_at) + '</span>' : '') + '</div>' +
        '<span class="share" style="width:' + ((r.revenue / maxReceita) * 100).toFixed(1) + '%"></span></td>' +
      '<td class="r">' + fShort(r.unique_views) + '</td>' +
      '<td class="r' + destaque('play_rate') + '">' + fPct(r.play_rate, 1) + '</td>' +
      '<td class="r' + destaque('retention') + '">' + fPct(r.retention, 1) + '</td>' +
      '<td class="r' + destaque('ctr') + '">' + fPct(r.ctr, 1) + '</td>' +
      '<td class="r' + destaque('conversion_rate') + '">' + fPct(r.conversion_rate, 2) + '</td>' +
      '<td class="r' + destaque('aov') + '">' + fMoney(r.aov) + '</td>' +
      '<td class="r' + destaque('epv') + '">' + fMoney(r.epv) + '</td>' +
      '<td class="r"><span class="pill ' + t.cls + '">' + l.health + ' &middot; ' + t.label + '</span></td>' +
      '<td class="r pos">' + fMoneyShort(r.revenue) + '</td>' +
    '</tr>';
  }).join('');
}

function exportCsv() {
  const linhas = rankedVideos();
  if (!linhas.length) { toast('Não há dados para exportar.', 'err'); return; }

  const cab = ['Semana', 'Criativo', 'Produto', 'ID', 'Visitas', 'Visitas únicas', 'Plays', 'Plays únicos',
               'Play rate (%)', 'Chega na oferta (%)', 'Clica no CTA (%)', 'Converte (%)',
               'Fecha após clicar (%)', 'Ticket (R$)', 'Por clique (R$)', 'Por visita (R$)',
               'Saúde', 'Vendas', 'Faturamento (R$)'];

  const cel = v => {
    const s = String(v == null ? '' : v);
    return /[;"\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const dec = n => (n || 0).toFixed(2).replace('.', ',');

  const corpo = linhas.map(l => {
    const r = l.r;
    return [l.folder, l.name, l.product, l.id, r.views, r.unique_views, r.plays, r.unique_plays,
            dec(r.play_rate), dec(r.retention), dec(r.ctr), dec(r.conversion_rate),
            dec(r.checkout_rate), dec(r.aov), dec(r.epc), dec(r.epv),
            l.health, r.conversions, dec(r.revenue)].map(cel).join(';');
  });

  const csv = '\uFEFF' + cab.join(';') + '\n' + corpo.join('\n');
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8;' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = 'criativos-' + $('#fStart').value + '-a-' + $('#fEnd').value + '.csv';
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
  toast('CSV baixado.', 'ok');
}

/* ---------- Quadrantes ---------- */
function drawMatrix() {
  const box = $('#matrix');
  const pontos = S.videos
    .filter(v => (v.stats.unique_views || 0) >= 30)
    .map(v => Object.assign({}, v, { r: rates(v.stats) }));

  if (pontos.length < 2) {
    box.innerHTML = '<div class="blank"><b>Poucos criativos com volume</b>' +
      'São necessários ao menos dois vídeos com 30 visitas únicas para desenhar o mapa.</div>';
    return;
  }

  const W = 860, H = 430, pad = 46;
  const maxX = Math.max(...pontos.map(p => p.r.play_rate), 1) * 1.14;
  const maxY = Math.max(...pontos.map(p => p.r.ctr), 1) * 1.14;
  const maxRev = Math.max(...pontos.map(p => p.r.revenue), 1);
  const mX = S.avgs.play_rate, mY = S.avgs.ctr;

  const px = v => pad + (v / maxX) * (W - pad * 2);
  const py = v => H - pad - (v / maxY) * (H - pad * 2);
  const raio = rev => 4.5 + Math.sqrt(rev / maxRev) * 10;

  const bolhas = pontos.map(p => {
    let q = 'q-cut';
    if (p.r.play_rate >= mX && p.r.ctr >= mY) q = 'q-scale';
    else if (p.r.play_rate >= mX) q = 'q-cta';
    else if (p.r.ctr >= mY) q = 'q-hook';
    return '<circle class="dot ' + q + '" cx="' + px(p.r.play_rate).toFixed(1) + '" cy="' + py(p.r.ctr).toFixed(1) +
      '" r="' + raio(p.r.revenue).toFixed(1) + '" data-id="' + esc(p.id) + '" data-tip="' +
      esc(p.name + '|' + fPct(p.r.play_rate, 1) + '|' + fPct(p.r.ctr, 1) + '|' + fMoney(p.r.revenue)) + '"/>';
  }).join('');

  const qx = px(mX), qy = py(mY);
  box.innerHTML =
    '<div class="legend">' +
      '<span class="legend-item" style="cursor:default"><span class="swatch" style="background:var(--pos)"></span>Prende e converte</span>' +
      '<span class="legend-item" style="cursor:default"><span class="swatch" style="background:var(--cyan)"></span>Prende, mas não clica</span>' +
      '<span class="legend-item" style="cursor:default"><span class="swatch" style="background:var(--warn)"></span>Clica, mas não prende</span>' +
      '<span class="legend-item" style="cursor:default"><span class="swatch" style="background:var(--neg)"></span>Abaixo nos dois</span>' +
    '</div>' +
    '<svg viewBox="0 0 ' + W + ' ' + H + '" class="chart" preserveAspectRatio="xMidYMid meet">' +
      '<line x1="' + pad + '" y1="' + qy.toFixed(1) + '" x2="' + (W - pad) + '" y2="' + qy.toFixed(1) + '" class="g-dash"/>' +
      '<line x1="' + qx.toFixed(1) + '" y1="' + pad + '" x2="' + qx.toFixed(1) + '" y2="' + (H - pad) + '" class="g-dash"/>' +
      '<text x="' + (qx + 6).toFixed(1) + '" y="' + (pad - 8) + '" class="g-text">média de play rate ' + fPct(mX, 1) + '</text>' +
      '<text x="' + (W - pad) + '" y="' + (qy - 8).toFixed(1) + '" text-anchor="end" class="g-text">média de cliques ' + fPct(mY, 1) + '</text>' +
      bolhas +
      '<text x="' + (W / 2) + '" y="' + (H - 10) + '" text-anchor="middle" class="g-title">Play rate</text>' +
      '<text x="14" y="' + (H / 2) + '" text-anchor="middle" class="g-title" transform="rotate(-90 14 ' + (H / 2) + ')">Clica no CTA</text>' +
    '</svg>';

  $$('#matrix circle[data-tip]').forEach(c => {
    c.addEventListener('mousemove', ev => {
      const [nome, pr, ctr, rev] = c.dataset.tip.split('|');
      showTip(ev, '<div class="tip-h">' + esc(nome) + '</div>' +
        '<div class="tip-row"><span>Play rate</span><b>' + esc(pr) + '</b></div>' +
        '<div class="tip-row"><span>Clica no CTA</span><b>' + esc(ctr) + '</b></div>' +
        '<div class="tip-row"><span>Faturamento</span><b>' + esc(rev) + '</b></div>');
    });
    c.addEventListener('mouseleave', hideTip);
    c.addEventListener('click', () => openSheet(c.dataset.id));
  });
}

/* ---------- Coortes por semana ---------- */
function renderCohorts() {
  const box = $('#cohorts');
  if (!S.current.length) { box.innerHTML = '<div class="blank">Nenhuma semana com dados no período.</div>'; return; }

  box.innerHTML = S.current.map((pasta, idx) => {
    const a = aggregate(pasta.videos);
    const anterior = S.current.slice(0, idx).reverse().find(p => /^Semana \d{2}$/.test(p.folder));
    const cmp = anterior
      ? change(a.revenue, aggregate(anterior.videos).revenue)
      : '<span class="chg none">&mdash;</span>';

    const criativos = pasta.videos.map(v => {
      const r = rates(v.stats);
      const alvo = [v.name, v.id, v.product].join(' ').toLowerCase();
      return '<div class="creative" data-open="' + esc(v.id) + '" data-find="' + esc(alvo) + '">' +
        '<div><div class="cell-title">' + esc(v.name) + '</div>' +
          '<div class="cell-sub"><span>ID ' + esc(v.id) + '</span>' +
          (v.pitch_at ? '<span>oferta em ' + fTime(v.pitch_at) + '</span>' : '') + '</div></div>' +
        '<div class="creative-metrics">' +
          '<div class="metric"><b>' + fShort(r.unique_views) + '</b><i>visitas</i></div>' +
          '<div class="metric"><b class="hot">' + fPct(r.play_rate, 1) + '</b><i>play</i></div>' +
          '<div class="metric"><b>' + fPct(r.ctr, 1) + '</b><i>CTA</i></div>' +
          '<div class="metric"><b>' + fPct(r.conversion_rate, 2) + '</b><i>converte</i></div>' +
          '<div class="metric"><b>' + fMoney(r.epv) + '</b><i>por visita</i></div>' +
          '<div class="metric"><b class="pos">' + fMoneyShort(r.revenue) + '</b><i>receita</i></div>' +
        '</div></div>';
    }).join('');

    return '<details class="cohort"' + (idx === 0 ? ' open' : '') + ' data-folder="' + esc(pasta.folder.toLowerCase()) + '">' +
      '<summary><span class="twist">&#9654;</span>' +
        '<span class="cohort-name">' + esc(pasta.folder) + '</span>' +
        '<span class="pill">' + pasta.videos.length + ' vídeos</span>' +
        '<span class="cohort-stats">' +
          '<span class="cohort-stat"><b>' + fPct(a.play_rate, 1) + '</b><i>play rate</i></span>' +
          '<span class="cohort-stat"><b>' + fPct(a.ctr, 1) + '</b><i>clica no CTA</i></span>' +
          '<span class="cohort-stat"><b>' + fMoney(a.epv) + '</b><i>por visita</i></span>' +
          '<span class="cohort-stat"><b>' + fMoneyShort(a.revenue) + '</b><i>faturamento</i></span>' +
          '<span class="cohort-stat">' + cmp + '<i>vs. semana anterior</i></span>' +
        '</span></summary>' +
      '<div class="cohort-body">' + criativos + '</div></details>';
  }).join('');
}

function filterCohorts() {
  const termo = $('#search').value.trim().toLowerCase();
  $$('#cohorts .cohort').forEach(det => {
    const itens = $$('.creative', det);
    let visiveis = 0;
    itens.forEach(el => {
      const bate = !termo || el.dataset.find.includes(termo) || det.dataset.folder.includes(termo);
      el.style.display = bate ? '' : 'none';
      if (bate) visiveis++;
    });
    det.style.display = visiveis ? '' : 'none';
    if (termo && visiveis) det.open = true;
  });
}
"""

_JS += r"""
/* =========================================================
   DETALHE DO CRIATIVO
   ========================================================= */
function openSheet(id) {
  const v = S.byId.get(id);
  if (!v) return;
  const r = rates(v.stats);
  const h = health(r);
  const t = healthTier(h.score);
  const antes = S.prevById.get(id);

  const celulas = [
    ['Visitas', fInt(r.views)], ['Visitas únicas', fInt(r.unique_views)],
    ['Plays', fInt(r.plays)], ['Plays únicos', fInt(r.unique_plays)],
    ['Play rate', fPct(r.play_rate, 1), 'hot'],
    ['Chega na oferta', fPct(r.retention, 1)],
    ['Público na oferta', fInt(r.pitch_audience)],
    ['Engajamento', fPct(r.engagement, 1)],
    ['Cliques no CTA', fInt(r.button_clicks)],
    ['Clica no CTA', fPct(r.ctr, 1)],
    ['Clica após a oferta', fPct(r.cta_efficiency, 1)],
    ['Vendas', fInt(r.conversions)],
    ['Converte', fPct(r.conversion_rate, 2)],
    ['Fecha após clicar', fPct(r.checkout_rate, 1)],
    ['Ticket médio', fMoney(r.aov)],
    ['Por clique', fMoney(r.epc)],
    ['Por visita', fMoney(r.epv)],
    ['Faturamento', fMoney(r.revenue), 'pos']
  ];

  const explicacao = h.parts.map(p => {
    const dif = (p.ratio - 1) * 100;
    const cls = Math.abs(dif) < 5 ? 'flat' : (dif > 0 ? 'up' : 'down');
    return '<div class="cmp-row"><span>' + p.label + '</span>' +
      '<span class="chg ' + cls + '">' + fRel(dif) + ' vs. média</span></div>';
  }).join('');

  const etapas = [
    ['Visitas', r.views], ['Plays', r.plays], ['Chegou na oferta', r.pitch_audience],
    ['Clicou', r.button_clicks], ['Comprou', r.conversions]
  ];
  const topo = etapas[0][1] || 1;
  const funil = etapas.map(([nome, val], i) => {
    const anterior = i === 0 ? null : etapas[i - 1][1];
    const passa = anterior ? (val / anterior) * 100 : 100;
    return '<div class="stage-row" style="grid-template-columns:150px 1fr 96px 108px">' +
      '<div class="stage-name">' + nome + '</div>' +
      '<div class="stage-bar"><div class="stage-fill" style="width:' + Math.max((val / topo) * 100, 0.6).toFixed(2) + '%"></div></div>' +
      '<div class="stage-num">' + fInt(val) + '</div>' +
      '<div class="stage-drop">' + (i === 0 ? '&mdash;' : fPct(passa, 1) + ' seguem') + '</div></div>';
  }).join('');

  const cmpBase = S.hasBase
    ? (antes
        ? change(r.revenue, rates(antes.stats).revenue)
        : '<span class="chg none">não existia na base</span>')
    : '<span class="chg none">sem base</span>';

  const champ = (S.champion && S.champion.id !== id)
    ? '<div class="cmp-row"><span>Converte vs. ' + esc(S.champion.name) + '</span>' +
      change(r.conversion_rate, rates(S.champion.stats).conversion_rate, 'rate') + '</div>'
    : '';

  $('#sheetBody').innerHTML =
    '<div class="sheet-head"><div>' +
      '<div class="meta">' + esc(v.folder) + ' &middot; ' + esc(v.product || '') + ' &middot; ID ' + esc(v.id) +
      (v.pitch_at ? ' &middot; oferta em ' + fTime(v.pitch_at) : '') + '</div>' +
      '<h3>' + esc(v.name) + '</h3></div>' +
      '<div class="score-badge"><b class="num">' + h.score + '<s>/100</s></b><i>' + t.label + '</i></div>' +
    '</div>' +
    (VTURB_HASH ? '<div class="player-frame" id="playerFrame">' +
      '<vturb-smartplayer id="vid-' + esc(v.id) + '" style="display:block;width:100%"></vturb-smartplayer></div>' : '') +
    '<div class="sheet-label">Números do período</div>' +
    '<div class="stat-grid">' + celulas.map(c =>
      '<div class="stat-cell"><i>' + c[0] + '</i><b class="' + (c[2] || '') + '">' + c[1] + '</b></div>').join('') + '</div>' +
    '<div class="sheet-label">Como o criativo chegou nessa nota</div>' + explicacao +
    '<div class="sheet-label">Comparações</div>' +
    '<div class="cmp-row"><span>Faturamento vs. período de comparação</span>' + cmpBase + '</div>' +
    '<div class="cmp-row"><span>Converte vs. média do período</span>' + change(r.conversion_rate, S.avgs.conversion_rate, 'rate') + '</div>' +
    champ +
    '<div class="sheet-label">Funil deste criativo</div><div class="funnel">' + funil + '</div>';

  $('#scrim').classList.add('on');
  document.body.style.overflow = 'hidden';
  if (VTURB_HASH) mountPlayer(v.id);
}

function closeSheet() {
  $('#scrim').classList.remove('on');
  document.body.style.overflow = '';
  const s = $('#vturbScript'); if (s) s.remove();
  const f = $('#playerFrame'); if (f) f.innerHTML = '';
}

function mountPlayer(id) {
  const antigo = $('#vturbScript'); if (antigo) antigo.remove();
  const s = document.createElement('script');
  s.id = 'vturbScript'; s.async = true;
  s.src = 'https://scripts.converteai.net/' + VTURB_HASH + '/players/' + id + '/v4/player.js';
  document.head.appendChild(s);
}

/* =========================================================
   RETENÇÃO
   ========================================================= */
async function loadRetention() {
  const box = $('#retentionChart');
  const f = readFilters();
  box.innerHTML = '<div class="skel" style="height:300px;border-radius:9px"></div>';
  $('#retentionLegend').innerHTML = '';
  $('#dropoffs').innerHTML = '';
  $('#retentionList').innerHTML = '';
  loadbar(true);

  const q = new URLSearchParams({ start: f.start, end: f.end, route: 'retention',
                                  filtro: $('#retentionFilter').value.trim() });
  try {
    const res = await fetch('/api/retention?' + q.toString(), { credentials: 'include' });
    if (res.status === 401) { location.href = '/'; return; }
    const data = await lerJson(res, '/api/retention');
    S.retention = data.videos || [];
    S.retentionHidden = new Set();
    loadbar(false);

    if (!S.retention.length) {
      box.innerHTML = '<div class="blank"><b>Nenhum criativo encontrado</b>' +
        'Ajuste o grupo de criativos e carregue de novo.</div>';
      return;
    }
    drawRetention();
    renderDropoffs();
    renderRetentionList();
  } catch (err) {
    loadbar(false);
    console.error(err);
    box.innerHTML = '<div class="blank"><b>Não deu para carregar as curvas</b>' + esc(err.message) + '.</div>';
  }
}

/** Trechos em que a curva perde público bem mais rápido que o normal dela.
 *  O corte é relativo ao próprio vídeo: toda curva cai o tempo todo, então
 *  um limiar fixo acusaria o decaimento natural como se fosse um problema. */
function biggestDrops(curva, quantos) {
  if (!curva || curva.length < 12) return [];
  const janela = Math.max(2, Math.round(curva.length * 0.03));

  const candidatos = [];
  for (let i = 0; i + janela < curva.length; i++) {
    candidatos.push({
      de: curva[i].t, ate: curva[i + janela].t,
      queda: curva[i].pct - curva[i + janela].pct,
      idx: i
    });
  }
  if (!candidatos.length) return [];

  const tipico = median(candidatos.map(c => c.queda));
  const corte = Math.max(1.5, tipico * 3);

  candidatos.sort((a, b) => b.queda - a.queda);
  const escolhidos = [];
  for (const c of candidatos) {
    if (c.queda < corte) break;
    if (escolhidos.some(e => Math.abs(e.idx - c.idx) < janela * 3)) continue;
    escolhidos.push(c);
    if (escolhidos.length >= (quantos || 3)) break;
  }
  return escolhidos.sort((a, b) => a.de - b.de);
}

function retentionAt(curva, t) {
  if (!curva || !curva.length) return null;
  let melhor = curva[0];
  for (const p of curva) { if (p.t <= t) melhor = p; else break; }
  return melhor.pct;
}

function drawRetention() {
  const box = $('#retentionChart');
  const visiveis = S.retention.filter((v, i) => !S.retentionHidden.has(v.id) && v.curve && v.curve.length);

  $('#retentionLegend').innerHTML = S.retention.map((v, i) => {
    const cor = SERIES_COLORS[i % SERIES_COLORS.length];
    const on = !S.retentionHidden.has(v.id);
    return '<button class="legend-item" data-series="' + esc(v.id) + '" aria-pressed="' + on + '">' +
      '<span class="swatch" style="background:' + cor + '"></span>' + esc(v.name) + '</button>';
  }).join('');

  if (!visiveis.length) {
    box.innerHTML = '<div class="blank">Todas as séries estão ocultas. Clique na legenda para trazer alguma de volta.</div>';
    return;
  }

  const duracaoMax = Math.max(...S.retention.map(v => v.duration || 0), ...visiveis.map(v => v.curve[v.curve.length - 1].t), 60);
  const W = 940, H = 360, padL = 44, padR = 16, padT = 18, padB = 34;
  const larg = W - padL - padR, alt = H - padT - padB;
  const px = t => padL + Math.min(t / duracaoMax, 1) * larg;
  const py = p => padT + alt * (1 - Math.max(0, Math.min(p, 100)) / 100);

  const grade = [0, 25, 50, 75, 100].map(p =>
    '<line x1="' + padL + '" y1="' + py(p).toFixed(1) + '" x2="' + (W - padR) + '" y2="' + py(p).toFixed(1) + '" class="g-dash"/>' +
    '<text x="' + (padL - 8) + '" y="' + (py(p) + 4).toFixed(1) + '" text-anchor="end" class="g-text">' + p + '%</text>'
  ).join('');

  const marcasX = [0, .2, .4, .6, .8, 1].map(f => {
    const t = duracaoMax * f;
    return '<text x="' + px(t).toFixed(1) + '" y="' + (H - 10) + '" text-anchor="middle" class="g-text">' + fTime(t) + '</text>';
  }).join('');

  let defs = '<defs>', areas = '', linhas = '', pitches = '';

  S.retention.forEach((v, i) => {
    if (S.retentionHidden.has(v.id) || !v.curve || !v.curve.length) return;
    const cor = SERIES_COLORS[i % SERIES_COLORS.length];
    const gid = 'gr' + i;
    defs += '<linearGradient id="' + gid + '" x1="0" y1="0" x2="0" y2="1">' +
            '<stop offset="0%" stop-color="' + cor + '" stop-opacity=".26"/>' +
            '<stop offset="100%" stop-color="' + cor + '" stop-opacity="0"/></linearGradient>';

    const d = v.curve.map((p, j) => (j ? 'L' : 'M') + px(p.t).toFixed(1) + ',' + py(p.pct).toFixed(1)).join(' ');
    const ult = v.curve[v.curve.length - 1], pri = v.curve[0];
    areas += '<path d="' + d + ' L' + px(ult.t).toFixed(1) + ',' + (H - padB) + ' L' + px(pri.t).toFixed(1) + ',' + (H - padB) + ' Z" fill="url(#' + gid + ')"/>';
    linhas += '<path d="' + d + '" fill="none" stroke="' + cor + '" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>';

    if (v.pitch_at && v.pitch_at <= duracaoMax) {
      const x = px(v.pitch_at);
      pitches += '<line x1="' + x.toFixed(1) + '" y1="' + padT + '" x2="' + x.toFixed(1) + '" y2="' + (H - padB) +
        '" stroke="' + cor + '" stroke-width="1" stroke-dasharray="3 4" opacity=".65"/>' +
        '<circle cx="' + x.toFixed(1) + '" cy="' + padT + '" r="2.5" fill="' + cor + '"/>';
    }
  });
  defs += '</defs>';

  box.innerHTML = '<svg id="retSvg" viewBox="0 0 ' + W + ' ' + H + '" class="chart" preserveAspectRatio="xMidYMid meet">' +
    defs + grade + areas + linhas + pitches +
    '<line id="retCross" x1="0" y1="' + padT + '" x2="0" y2="' + (H - padB) + '" class="g-line" style="display:none"/>' +
    '<g id="retDots"></g>' +
    '<rect x="' + padL + '" y="' + padT + '" width="' + larg + '" height="' + alt + '" fill="transparent" id="retHit"/>' +
    marcasX + '</svg>' +
    '<p style="font-size:12px;color:var(--ink-3);margin-top:10px">A linha tracejada de cada cor marca o instante da oferta lido do nome do criativo.</p>';

  const svg = $('#retSvg'), hit = $('#retHit'), cross = $('#retCross'), dots = $('#retDots');
  hit.addEventListener('mousemove', ev => {
    const caixa = svg.getBoundingClientRect();
    const escala = W / caixa.width;
    const xSvg = (ev.clientX - caixa.left) * escala;
    const t = Math.max(0, Math.min(((xSvg - padL) / larg) * duracaoMax, duracaoMax));

    cross.style.display = '';
    cross.setAttribute('x1', xSvg.toFixed(1));
    cross.setAttribute('x2', xSvg.toFixed(1));

    let marcadores = '', linhasTip = '';
    S.retention.forEach((v, i) => {
      if (S.retentionHidden.has(v.id) || !v.curve || !v.curve.length) return;
      const pct = retentionAt(v.curve, t);
      if (pct === null) return;
      const cor = SERIES_COLORS[i % SERIES_COLORS.length];
      marcadores += '<circle cx="' + xSvg.toFixed(1) + '" cy="' + py(pct).toFixed(1) + '" r="3.5" fill="' + cor + '" stroke="var(--panel)" stroke-width="1.5"/>';
      linhasTip += '<div class="tip-row"><span><span class="swatch" style="background:' + cor + '"></span>' +
        esc(v.name.length > 26 ? v.name.slice(0, 26) + '…' : v.name) + '</span><b>' + fPct(pct, 1) + '</b></div>';
    });
    dots.innerHTML = marcadores;
    showTip(ev, '<div class="tip-h">' + fTime(t) + '</div>' + linhasTip);
  });
  hit.addEventListener('mouseleave', () => { cross.style.display = 'none'; dots.innerHTML = ''; hideTip(); });

  $$('#retentionLegend .legend-item').forEach(b => b.addEventListener('click', () => {
    const id = b.dataset.series;
    if (S.retentionHidden.has(id)) S.retentionHidden.delete(id); else S.retentionHidden.add(id);
    drawRetention();
  }));
}

function renderDropoffs() {
  const comCurva = S.retention.filter(v => v.curve && v.curve.length > 6);
  if (!comCurva.length) { $('#dropoffs').innerHTML = '<div class="blank">Sem curvas para analisar.</div>'; return; }

  $('#dropoffs').innerHTML = comCurva.map((v, i) => {
    const cor = SERIES_COLORS[S.retention.indexOf(v) % SERIES_COLORS.length];
    const quedas = biggestDrops(v.curve, 3);
    const noPitch = v.pitch_at ? retentionAt(v.curve, v.pitch_at) : null;

    const chips = quedas.length
      ? quedas.map(q => '<span class="pill bad">' + fTime(q.de) + '&ndash;' + fTime(q.ate) +
          ' &middot; &minus;' + q.queda.toFixed(1).replace('.', ',') + ' p.p.</span>').join(' ')
      : '<span class="pill">queda distribuída, sem trecho crítico</span>';

    return '<div class="creative" data-open="' + esc(v.id) + '" style="border:1px solid var(--line);margin-bottom:6px">' +
      '<div><div class="cell-title"><span class="swatch" style="display:inline-block;width:9px;height:9px;border-radius:3px;background:' +
        cor + ';margin-right:8px"></span>' + esc(v.name) + '</div>' +
      '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:7px">' + chips + '</div></div>' +
      '<div class="creative-metrics">' +
        (noPitch !== null ? '<div class="metric"><b>' + fPct(noPitch, 1) + '</b><i>na oferta</i></div>' : '') +
        '<div class="metric"><b>' + fTime(v.average_watched_time) + '</b><i>tempo médio</i></div>' +
        '<div class="metric"><b>' + fPct(v.engagement_rate, 1) + '</b><i>engajamento</i></div>' +
      '</div></div>';
  }).join('');
}

function renderRetentionList() {
  $('#retentionList').innerHTML = S.retention.map((v, i) => {
    const r = rates(v.stats);
    const cor = SERIES_COLORS[i % SERIES_COLORS.length];
    return '<div class="creative" data-open="' + esc(v.id) + '" style="border:1px solid var(--line);margin-bottom:6px">' +
      '<div><div class="cell-title"><span style="display:inline-block;width:9px;height:9px;border-radius:3px;background:' +
        cor + ';margin-right:8px"></span>' + esc(v.name) + '</div>' +
      '<div class="cell-sub"><span>ID ' + esc(v.id) + '</span><span>' + fPct(v.traffic, 1) + ' do tráfego do grupo</span></div></div>' +
      '<div class="creative-metrics">' +
        '<div class="metric"><b>' + fShort(r.unique_views) + '</b><i>visitas</i></div>' +
        '<div class="metric"><b class="hot">' + fPct(r.play_rate, 1) + '</b><i>play</i></div>' +
        '<div class="metric"><b>' + fPct(r.retention, 1) + '</b><i>na oferta</i></div>' +
        '<div class="metric"><b>' + fPct(r.ctr, 1) + '</b><i>CTA</i></div>' +
        '<div class="metric"><b class="pos">' + fMoneyShort(r.revenue) + '</b><i>receita</i></div>' +
      '</div></div>';
  }).join('');
}
"""

_JS += r"""
/* =========================================================
   TESTE A/B
   ========================================================= */
function fillAbSelects() {
  const a = $('#abA'), b = $('#abB');
  if (!a || !b) return;

  const validos = S.videos.filter(v => (v.stats.unique_views || 0) > 0)
    .sort((x, y) => (y.stats.revenue || 0) - (x.stats.revenue || 0));

  const grupos = new Map();
  validos.forEach(v => {
    const g = v.ab_test ? 'Teste ' + v.ab_test : (v.product || 'Sem produto');
    if (!grupos.has(g)) grupos.set(g, []);
    grupos.get(g).push(v);
  });

  let html = '<option value="">Escolher criativo</option>';
  Array.from(grupos.keys()).sort().forEach(g => {
    html += '<optgroup label="' + esc(g) + '">';
    grupos.get(g).forEach(v => { html += '<option value="' + esc(v.id) + '">' + esc(v.name) + '</option>'; });
    html += '</optgroup>';
  });

  const antesA = a.value, antesB = b.value;
  a.innerHTML = html; b.innerHTML = html;
  if (antesA && S.byId.has(antesA)) a.value = antesA;
  if (antesB && S.byId.has(antesB)) b.value = antesB;
}

const AB_TESTS = [
  { label: 'Play rate', sucesso: 'unique_plays', base: 'unique_views',
    nota: 'Quantos de quem abriu a página deram play.' },
  { label: 'Clica no CTA', sucesso: 'button_clicks', base: 'unique_plays',
    nota: 'Quantos de quem deu play clicaram no botão.' },
  { label: 'Converte', sucesso: 'conversions', base: 'unique_plays',
    nota: 'Quantos de quem deu play compraram.' }
];

function renderAb() {
  const box = $('#abResult');
  const idA = $('#abA').value, idB = $('#abB').value;

  if (!idA || !idB) {
    box.innerHTML = '<div class="blank"><b>Escolha os dois criativos</b>' +
      'O painel calcula a diferença e o quanto ela é confiável.</div>';
    return;
  }
  if (idA === idB) {
    box.innerHTML = '<div class="blank"><b>São o mesmo criativo</b>Escolha dois diferentes.</div>';
    return;
  }

  const vA = S.byId.get(idA), vB = S.byId.get(idB);
  if (!vA || !vB) return;
  const rA = rates(vA.stats), rB = rates(vB.stats);
  const dias = Math.max(1, daysBetween($('#fStart').value, $('#fEnd').value));

  const cartoes = AB_TESTS.map(t => {
    const nA = rA[t.base] || 0, nB = rB[t.base] || 0;
    const xA = rA[t.sucesso] || 0, xB = rB[t.sucesso] || 0;
    const res = compareProportions(xA, nA, xB, nB);

    if (!res || nA < 1 || nB < 1) {
      return '<div class="sig-card"><div class="sig-metric">' + t.label + '</div>' +
        '<div class="sig-uplift">&mdash;</div><div class="sig-foot">Sem tráfego suficiente para calcular.</div></div>';
    }

    // A aproximação normal satura em 100%; nenhum teste devolve certeza absoluta.
    const confTxt = res.confidence >= 99.9 ? 'mais de 99,9%' : res.confidence.toFixed(1).replace('.', ',') + '%';
    let classe = 'wait', veredito;
    if (res.significant && res.uplift > 0) { classe = 'win'; veredito = '<b>A variação ganha.</b> A diferença tem ' + confTxt + ' de confiança.'; }
    else if (res.significant && res.uplift < 0) { classe = 'lose'; veredito = '<b>O controle ganha.</b> A variação está atrás com ' + confTxt + ' de confiança.'; }
    else {
      const precisa = requiredPerArm(res.pA, res.pB);
      const falta = precisa ? Math.max(0, precisa - Math.min(nA, nB)) : null;
      const diasFalta = falta && nB > 0 ? Math.ceil(falta / (nB / dias)) : null;
      veredito = '<b>Ainda é ruído.</b> ' + (precisa
        ? 'Para confirmar um efeito desse tamanho seriam necessárias ' + fInt(precisa) + ' amostras por lado' +
          (diasFalta && diasFalta > 0 ? ', cerca de ' + diasFalta + (diasFalta === 1 ? ' dia' : ' dias') + ' no ritmo atual' : '') + '.'
        : 'As duas taxas estão praticamente empatadas.');
    }

    const conf = Math.max(0, Math.min(res.confidence, 100));
    return '<div class="sig-card ' + classe + '">' +
      '<div class="sig-metric">' + t.label + '</div>' +
      '<div class="sig-uplift ' + (res.uplift > 0 ? 'pos' : res.uplift < 0 ? 'neg' : '') + '">' + fRel(res.uplift) + '</div>' +
      '<div class="sig-rates">' + fPct(res.pA * 100, 2) + ' &rarr; ' + fPct(res.pB * 100, 2) +
        ' &middot; ' + fInt(nA) + ' vs ' + fInt(nB) + ' amostras</div>' +
      '<div class="conf-track"><div class="conf-fill" style="width:' + conf.toFixed(1) + '%"></div></div>' +
      '<div class="sig-rates" style="margin-bottom:9px">confiança ' + confTxt +
        ' &middot; chance de a variação ser melhor ' + Math.min(res.probB, 99.9).toFixed(0) + '%</div>' +
      '<div class="sig-foot">' + veredito + '</div></div>';
  }).join('');

  const linha = (rotulo, va, vb, fmt, maiorMelhor) => {
    const melhorA = maiorMelhor !== false ? va > vb : va < vb;
    const melhorB = maiorMelhor !== false ? vb > va : vb < va;
    const marca = ok => ok ? ' style="color:var(--pos);font-weight:600"' : '';
    return '<tr><td>' + rotulo + '</td>' +
      '<td class="r"' + marca(melhorA && va !== vb) + '>' + fmt(va) + '</td>' +
      '<td class="r"' + marca(melhorB && va !== vb) + '>' + fmt(vb) + '</td></tr>';
  };

  box.innerHTML =
    '<div class="sig-panel" style="margin-bottom:20px">' + cartoes + '</div>' +
    '<div class="grid-wrap"><div class="scroll-x"><table class="grid">' +
      '<thead><tr><th>Métrica</th>' +
      '<th class="r" style="width:30%"><span style="color:var(--ink-3);font-weight:400">Controle</span><br>' + esc(vA.name) + '</th>' +
      '<th class="r" style="width:30%"><span style="color:var(--ink-3);font-weight:400">Variação</span><br>' + esc(vB.name) + '</th>' +
      '</tr></thead><tbody>' +
      linha('Visitas únicas', rA.unique_views, rB.unique_views, fInt) +
      linha('Play rate', rA.play_rate, rB.play_rate, v => fPct(v, 1)) +
      linha('Chega na oferta', rA.retention, rB.retention, v => fPct(v, 1)) +
      linha('Clica no CTA', rA.ctr, rB.ctr, v => fPct(v, 1)) +
      linha('Clica após a oferta', rA.cta_efficiency, rB.cta_efficiency, v => fPct(v, 1)) +
      linha('Converte', rA.conversion_rate, rB.conversion_rate, v => fPct(v, 2)) +
      linha('Fecha após clicar', rA.checkout_rate, rB.checkout_rate, v => fPct(v, 1)) +
      linha('Ticket médio', rA.aov, rB.aov, fMoney) +
      linha('Receita por visita', rA.epv, rB.epv, fMoney) +
      linha('Faturamento', rA.revenue, rB.revenue, fMoney) +
    '</tbody></table></div></div>' +
    '<p style="font-size:12px;color:var(--ink-3);margin-top:12px;max-width:80ch">' +
      'Os cálculos usam teste z de duas proporções, confiança de 95% e poder de 80%. ' +
      'O resultado vale se os dois criativos receberam tráfego do mesmo público e no mesmo período.</p>';
}

/* =========================================================
   BUSCA RÁPIDA (⌘K)
   ========================================================= */
const PALETTE_ACTIONS = [
  { kind: 'Seção', label: 'Visão geral', run: () => goView('v-overview') },
  { kind: 'Seção', label: 'Criativos', run: () => goView('v-creatives') },
  { kind: 'Seção', label: 'TG Brands: tráfego x faturamento', run: () => goView('v-tg') },
  { kind: 'Ação', label: 'Copiar resumo dos testes', run: copiarResumo },
  { kind: 'Ação', label: 'Baixar CSV dos testes', run: exportTesteCsv },
  { kind: 'Período', label: 'Hoje', run: () => { const [a, b] = rangePreset('hoje'); setRange(a, b); loadData(); } },
  { kind: 'Período', label: 'Últimos 7 dias', run: () => { const [a, b] = rangePreset('7'); setRange(a, b); loadData(); } },
  { kind: 'Período', label: 'Últimos 30 dias', run: () => { const [a, b] = rangePreset('30'); setRange(a, b); loadData(); } },
  { kind: 'Período', label: 'Este mês', run: () => { const [a, b] = rangePreset('mes'); setRange(a, b); loadData(); } },
  { kind: 'Ação', label: 'Baixar CSV do ranking', run: exportCsv },
  { kind: 'Ação', label: 'Alternar tema claro e escuro', run: toggleTheme }
];

let paletteItems = [], paletteIdx = 0;

function openPalette() {
  $('#palette').classList.add('on');
  const inp = $('#paletteInput');
  inp.value = ''; inp.focus();
  buildPalette('');
}
function closePalette() { $('#palette').classList.remove('on'); }

function buildPalette(termo) {
  termo = termo.trim().toLowerCase();
  const acoes = PALETTE_ACTIONS.filter(a => !termo || a.label.toLowerCase().includes(termo));
  const videos = S.videos
    .filter(v => !termo || (v.name + ' ' + v.id).toLowerCase().includes(termo))
    .slice(0, 8)
    .map(v => ({ kind: 'Criativo', label: v.name, run: () => { goView('v-creatives'); openSheet(v.id); } }));

  paletteItems = acoes.concat(videos).slice(0, 14);
  paletteIdx = 0;
  const lista = $('#paletteList');
  lista.innerHTML = paletteItems.length
    ? paletteItems.map((it, i) =>
        '<button class="palette-item" data-idx="' + i + '" data-active="' + (i === 0) + '">' +
        esc(it.label) + '<span class="p-kind">' + it.kind + '</span></button>').join('')
    : '<div class="palette-empty">Nada encontrado para essa busca.</div>';
}

function movePalette(passo) {
  if (!paletteItems.length) return;
  paletteIdx = (paletteIdx + passo + paletteItems.length) % paletteItems.length;
  $$('#paletteList .palette-item').forEach((el, i) => el.dataset.active = String(i === paletteIdx));
  const ativo = $('#paletteList .palette-item[data-active="true"]');
  if (ativo) ativo.scrollIntoView({ block: 'nearest' });
}

function runPalette(i) {
  const it = paletteItems[i];
  if (!it) return;
  closePalette();
  it.run();
}
"""

_JS += r"""
/* =========================================================
   MOTOR DE TESTES
   Base comum das abas Em teste, Maturidade e Leitura.
   Uma variação é lida sempre contra um controle, com a mesma
   régua nas três telas — o que muda é o recorte, não o critério.
   ========================================================= */

const TESTE = {
  controlId: '',      // vazio = controle automático
  minPlays: 100,      // plays únicos mínimos por braço para haver veredito
  horizonte: 21       // dias que ainda vale esperar dentro do ciclo normal
};

const ESTADOS = {
  ganha:    { rotulo: 'Promover',       pill: 'good', ordem: 0 },
  perde:    { rotulo: 'Descartar',      pill: 'bad',  ordem: 1 },
  seguir:   { rotulo: 'Seguir rodando', pill: 'mid',  ordem: 2 },
  longo:    { rotulo: 'Prazo longo',    pill: 'info', ordem: 3 },
  encerrar: { rotulo: 'Fora de alcance', pill: '',    ordem: 4 },
  sem:      { rotulo: 'Sem leitura',    pill: '',     ordem: 5 }
};

/** Plural curto: plural(2, 'variação', 'variações') -> '2 variações'. */
function plural(n, um, muitos) {
  return fInt(n) + ' ' + (Math.abs(n) === 1 ? um : muitos);
}

/** Amostras astronômicas viram ruído visual: acima de 1 milhão, arredonda. */
function fAmostra(n) {
  if (!n) return '&mdash;';
  if (n >= 1e6) return 'mais de 1 mi';
  return fInt(n);
}

/** Percentil simples para escalas de gráfico resistentes a outlier. */
function percentil(arr, q) {
  if (!arr.length) return 0;
  const s = [...arr].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.max(0, Math.floor(q * (s.length - 1))))];
}

function testeDias() {
  return Math.max(1, daysBetween($('#fStart').value, $('#fEnd').value));
}

/** Menor diferença relativa que uma amostra de n por braço consegue separar
 *  do ruído a 95% de confiança e 80% de poder. É o inverso de requiredPerArm:
 *  em vez de "quanta amostra falta", responde "o que essa amostra enxerga". */
function mdeRelativo(pBase, n) {
  if (!(pBase > 0) || !(n > 0) || pBase >= 1) return null;
  const cabe = up => {
    const pB = pBase * (1 + up);
    if (!(pB > 0) || pB >= 1) return false;
    const precisa = requiredPerArm(pBase, pB);
    return precisa !== null && precisa <= n;
  };
  let lo = 0.0005, hi = 4;
  if (!cabe(hi)) return null;
  for (let i = 0; i < 44; i++) {
    const meio = (lo + hi) / 2;
    if (cabe(meio)) hi = meio; else lo = meio;
  }
  return hi * 100;
}

/** Amostra efetiva de um teste com braços desiguais. A média harmônica é o
 *  que entra na conta de poder: 8.000 de um lado e 300 do outro valem ~578,
 *  não 4.150. É por isso que split torto trava teste. */
function amostraEfetiva(nA, nB) {
  if (!(nA > 0) || !(nB > 0)) return 0;
  return 2 / (1 / nA + 1 / nB);
}

const PRIOR_PLAYS = 200;   // proporções: 200 plays de evidência valem o controle
const PRIOR_VENDAS = 15;   // RPV: 15 vendas de evidência valem o controle

/** Quanta amostra o controle vale no ranking de cada métrica. Conversão e
 *  retenção são proporções sobre plays, então um número fixo serve. RPV não:
 *  ele é dominado por venda isolada — uma venda em 6 visitas vira R$ 33 por
 *  visita —, então ali o peso é medido em vendas e convertido para visitas pelo
 *  ritmo do próprio controle. */
function pesoPrior(c, porVenda) {
  if (!porVenda) return PRIOR_PLAYS;
  const visitasPorVenda = c.conversions > 0 ? (c.unique_views || 0) / c.conversions : 0;
  return Math.max(PRIOR_PLAYS, PRIOR_VENDAS * visitasPorVenda);
}

/** Valor encolhido na direção do controle. É o que entrou no lugar do corte de
 *  visitas mínimas: em vez de barrar criativo por volume, cada um recebe o
 *  benefício da dúvida proporcional ao tráfego que teve. 2 vendas em 4 plays
 *  não viram 50% de conversão no ranking — voltam para perto do controle;
 *  8% em 5.000 plays ficam praticamente onde estão. O número exibido continua
 *  sendo o observado: o que muda é quem sobe para o card. */
function ajustadoAoControle(x, n, base, peso) {
  base = base || 0;
  peso = peso > 0 ? peso : PRIOR_PLAYS;
  if (!(n > 0)) return base;
  return ((x || 0) + base * peso) / (n + peso);
}

function poolTeste() {
  // Sem corte de volume: quem recebeu tráfego na janela filtrada entra.
  // O que separa sinal de ruído é a régua estatística, não um piso de visitas.
  const comTrafego = S.videos.filter(v => (v.stats.unique_views || 0) > 0);

  let controle = (TESTE.controlId && S.byId.has(TESTE.controlId)) ? S.byId.get(TESTE.controlId) : null;
  if (!controle) {
    controle = [...comTrafego].sort((a, b) =>
      (b.stats.unique_plays || 0) - (a.stats.unique_plays || 0) ||
      (b.stats.revenue || 0) - (a.stats.revenue || 0))[0] || null;
  }

  const candidatos = controle ? comTrafego.filter(v => v.id !== controle.id) : [];
  return {
    controle: controle,
    candidatos: candidatos,
    comTrafego: comTrafego.length
  };
}

function avaliarVariacao(v, controle) {
  const c = rates(controle.stats), t = rates(v.stats);
  const dias = testeDias();

  const conv = compareProportions(c.conversions, c.unique_plays, t.conversions, t.unique_plays);
  const ret  = compareProportions(c.pitch_audience, c.unique_plays, t.pitch_audience, t.unique_plays);
  const play = compareProportions(c.unique_plays, c.unique_views, t.unique_plays, t.unique_views);
  const cta  = compareProportions(c.button_clicks, c.unique_plays, t.button_clicks, t.unique_plays);

  const rpvUplift = c.epv > 0 ? ((t.epv - c.epv) / c.epv) * 100 : (t.epv > 0 ? 100 : 0);
  const impacto = (t.epv - c.epv) * (t.unique_views || 0);
  const projecao = (t.epv - c.epv) * (S.agg.unique_views || 0);

  // RPV = play rate x conversão x ticket. Em logaritmo os três viram parcelas
  // que somam exatamente a variação total: dá para dizer de onde veio o ganho.
  const lg = (x, y) => (x > 0 && y > 0) ? Math.log(x / y) : 0;
  const bruto = { play: lg(t.play_rate, c.play_rate), conv: lg(t.conversion_rate, c.conversion_rate), tick: lg(t.aov, c.aov) };
  const soma = Math.abs(bruto.play) + Math.abs(bruto.conv) + Math.abs(bruto.tick);
  const ROTULO_FATOR = { play: 'Play rate', conv: 'Conversão', tick: 'Ticket médio' };
  const decomp = ['play', 'conv', 'tick'].map(k => ({
    key: k,
    label: ROTULO_FATOR[k],
    pct: (Math.exp(bruto[k]) - 1) * 100,
    share: soma > 0 ? Math.abs(bruto[k]) / soma : 0
  }));

  const nEff = amostraEfetiva(c.unique_plays, t.unique_plays);
  const precisa = conv ? requiredPerArm(conv.pA, conv.pB) : null;
  const mde = conv ? mdeRelativo(conv.pA, nEff) : null;
  const ritmo = (t.unique_plays || 0) / dias;
  const faltam = (precisa && nEff < precisa && ritmo > 0) ? Math.ceil((precisa - nEff) / ritmo) : 0;
  const progresso = precisa ? Math.min(100, (nEff / precisa) * 100) : (nEff > 0 ? 100 : 0);
  const split = (c.unique_views + t.unique_views) > 0 ? t.unique_views / (c.unique_views + t.unique_views) * 100 : 0;

  // A régua é sempre a mesma: significância decide primeiro; o que sobra é
  // classificado pelo prazo que faltaria para decidir no ritmo atual.
  let estado = 'sem';
  if (conv && t.unique_plays >= TESTE.minPlays && c.unique_plays >= TESTE.minPlays) {
    if (conv.significant && conv.uplift > 0) estado = 'ganha';
    else if (conv.significant && conv.uplift < 0) estado = 'perde';
    else if (faltam > 0 && faltam <= TESTE.horizonte) estado = 'seguir';
    else if (faltam > 0 && faltam <= TESTE.horizonte * 3) estado = 'longo';
    else estado = 'encerrar';
  }

  // O mesmo sinal apareceu no período de comparação? Repetição vale mais que
  // significância isolada — é o que separa achado de coincidência.
  let sustentou = null;
  const antesV = S.prevById.get(v.id), antesC = S.prevById.get(controle.id);
  if (S.hasBase && antesV && antesC && conv) {
    const av = rates(antesV.stats), ac = rates(antesC.stats);
    const gapAntes = av.conversion_rate - ac.conversion_rate;
    const gapAgora = t.conversion_rate - c.conversion_rate;
    const relevante = ac.conversion_rate > 0 && c.conversion_rate > 0 &&
      Math.abs(gapAntes / ac.conversion_rate) >= 0.1 && Math.abs(gapAgora / c.conversion_rate) >= 0.1;
    if (av.unique_plays >= 30 && ac.unique_plays >= 30 && relevante) {
      sustentou = (gapAntes >= 0) === (gapAgora >= 0);
    }
  }

  return {
    v: v, c: c, t: t, conv: conv, ret: ret, play: play, cta: cta,
    rpvUplift: rpvUplift, impacto: impacto, projecao: projecao, decomp: decomp,
    nEff: nEff, precisa: precisa, mde: mde, faltam: faltam, progresso: progresso,
    ritmo: ritmo, split: split, estado: estado, sustentou: sustentou
  };
}

/** Avaliação única, guardada em S para as três abas lerem o mesmo número. */
function avaliarTestes() {
  const p = poolTeste();
  const linhas = p.controle ? p.candidatos.map(v => avaliarVariacao(v, p.controle)) : [];
  linhas.sort((a, b) => b.impacto - a.impacto);
  // Ninguém fica de fora da tela; quem ainda não tem amostra é contado à parte
  // para o painel poder dizer isso em voz alta.
  const semLeitura = linhas.filter(l => l.estado === 'sem').length;
  S.teste = Object.assign({}, p, { linhas: linhas, semLeitura: semLeitura, dias: testeDias() });
  return S.teste;
}

function testeVazio(msg, dica) {
  return '<div class="blank"><b>' + msg + '</b>' + (dica || '') + '</div>';
}

/* =========================================================
   ABA 1 — EM TESTE
   ========================================================= */
function fillTesteControls() {
  const sel = $('#testControl');
  if (!sel) return;
  const vids = S.videos.filter(v => (v.stats.unique_views || 0) > 0)
    .sort((a, b) => (b.stats.unique_plays || 0) - (a.stats.unique_plays || 0));
  sel.innerHTML = '<option value="">Automático — o criativo que mais roda</option>' +
    vids.map(v => '<option value="' + esc(v.id) + '">' + esc(v.name) + '</option>').join('');
  sel.value = (TESTE.controlId && S.byId.has(TESTE.controlId)) ? TESTE.controlId : '';
}

const FOCOS = [
  { key: 'conversion_rate', teste: 'conv', label: 'Conversão', fmt: v => fPct(v, 2),
    nota: 'de quem deu play, quantos compraram',
    rank: l => ajustadoAoControle(l.t.conversions, l.t.unique_plays, l.c.conversion_rate / 100, pesoPrior(l.c)) },
  { key: 'epv', teste: null, label: 'Receita por visita', fmt: fMoney,
    nota: 'quanto cada visita única rendeu',
    rank: l => ajustadoAoControle(l.t.revenue, l.t.unique_views, l.c.epv, pesoPrior(l.c, true)) },
  { key: 'retention', teste: 'ret', label: 'Retenção até a oferta', fmt: v => fPct(v, 1),
    nota: 'de quem deu play, quantos chegaram no pitch',
    rank: l => ajustadoAoControle(l.t.pitch_audience, l.t.unique_plays, l.c.retention / 100, pesoPrior(l.c)) }
];

function renderTrackFocus(T) {
  const box = $('#trackFocus');
  if (!box) return;
  if (!T.controle || !T.linhas.length) {
    box.innerHTML = testeVazio('Sem variações para acompanhar',
      'Nenhum criativo além do controle recebeu tráfego nas datas escolhidas. Amplie a janela ou revise o filtro de campanha.');
    return;
  }

  box.innerHTML = FOCOS.map(f => {
    // Ordena pelo valor encolhido, não pelo número cru: mantém o card útil
    // agora que criativo nenhum é barrado por volume.
    const ordenado = [...T.linhas].sort((a, b) =>
      (f.rank(b) - f.rank(a)) || ((b.t[f.key] || 0) - (a.t[f.key] || 0)));
    const melhor = ordenado[0];
    const valorC = T.linhas[0].c[f.key] || 0;
    const valorV = melhor.t[f.key] || 0;
    const rel = valorC > 0 ? ((valorV - valorC) / valorC) * 100 : (valorV > 0 ? 100 : 0);
    const acima = T.linhas.filter(l => (l.t[f.key] || 0) > valorC).length;

    let classe = 'wait', leitura;
    const res = f.teste ? melhor[f.teste] : null;
    if (res && res.significant && rel > 0) { classe = 'win'; leitura = '<b>Passa a régua.</b> Diferença com ' + (res.confidence >= 99.9 ? 'mais de 99,9%' : fPct(res.confidence, 1)) + ' de confiança.'; }
    else if (res && res.significant && rel < 0) { classe = 'lose'; leitura = '<b>O controle segue melhor.</b> Nenhuma variação passa dele aqui.'; }
    else if (!f.teste) { classe = rel > 0 ? 'win' : (rel < 0 ? 'lose' : 'wait'); leitura = 'Métrica de valor, não de proporção: use a conversão ao lado para decidir se a diferença é real.'; }
    else { leitura = '<b>Ainda dentro do ruído.</b> A diferença existe no número, mas não se sustenta estatisticamente.'; }

    const magro = melhor.t.unique_views < 1000 || melhor.t.unique_views < (melhor.c.unique_views || 1) * 0.1;
    const alerta = magro
      ? ' <b style="color:var(--warn)">Amostra pequena: ' + fInt(melhor.t.unique_views) +
        ' visitas contra ' + fInt(melhor.c.unique_views) + ' do controle.</b>'
      : '';

    return '<div class="focus-card ' + classe + '">' +
      '<div class="focus-k">' + f.label + '</div>' +
      '<div class="focus-v ' + (rel > 0 ? 'pos' : rel < 0 ? 'neg' : '') + '">' + f.fmt(valorV) + '</div>' +
      '<div class="focus-base">controle ' + f.fmt(valorC) + ' &middot; ' + fRel(rel) + '</div>' +
      '<button class="focus-who note-link" data-open="' + esc(melhor.v.id) + '" style="text-align:left">' + esc(melhor.v.name) + '</button>' +
      '<div class="focus-sub">' + leitura + alerta + ' <span style="color:var(--ink-3)">' + acima + ' de ' + T.linhas.length +
      ' variações estão acima do controle nesta métrica (' + f.nota + ').</span></div>' +
    '</div>';
  }).join('');
}

function deltaCel(valor, delta, fmt, tipo) {
  const sinal = Math.abs(delta) < (tipo === 'pp' ? 0.15 : 1) ? 'flat' : (delta > 0 ? 'up' : 'down');
  const txt = tipo === 'pp' ? fPP(delta) : fRel(delta);
  return '<td class="r">' + fmt(valor) + '<span class="cell-delta ' + sinal + '">' + txt + '</span></td>';
}

function renderTrackTable(T) {
  const tab = $('#trackTable');
  if (!tab) return;
  if (!T.controle || !T.linhas.length) {
    tab.innerHTML = '<tbody><tr><td>' + testeVazio('Nada para comparar',
      'Nenhuma variação com tráfego além do controle nesta janela. Amplie o período nas datas lá em cima.') + '</td></tr></tbody>';
    return;
  }

  const cabecalho = '<thead><tr>' +
    '<th>Criativo</th>' +
    '<th class="r">Visitas</th>' +
    '<th class="r">Split</th>' +
    '<th class="r">Retenção</th>' +
    '<th class="r">Conversão</th>' +
    '<th class="r">RPV</th>' +
    '<th class="r">Impacto no período</th>' +
    '<th class="r">Confiança</th>' +
    '<th class="r">Leitura</th>' +
  '</tr></thead>';

  const c = T.linhas[0].c;
  const linhaControle = '<tr style="background:var(--panel-2)">' +
    '<td><div class="cell-title">' + esc(T.controle.name) + '</div>' +
      '<div class="cell-sub">controle &middot; ' + fMoney(c.revenue) + ' no período</div></td>' +
    '<td class="r">' + fInt(c.unique_views) + '</td>' +
    '<td class="r">&mdash;</td>' +
    '<td class="r">' + fPct(c.retention, 1) + '</td>' +
    '<td class="r">' + fPct(c.conversion_rate, 2) + '</td>' +
    '<td class="r">' + fMoney(c.epv) + '</td>' +
    '<td class="r">&mdash;</td>' +
    '<td class="r">&mdash;</td>' +
    '<td class="r"><span class="verd">referência</span></td>' +
  '</tr>';

  const corpo = T.linhas.map(l => {
    const est = ESTADOS[l.estado];
    // Em amostra minúscula a aproximação normal devolve confiança altíssima
    // para nada: sem veredito, a coluna fica em branco em vez de mentir.
    const conf = (l.conv && l.estado !== 'sem')
      ? (l.conv.confidence >= 99.9 ? '&gt;99,9%' : fPct(l.conv.confidence, 1))
      : '&mdash;';
    const dRet = l.t.retention - l.c.retention;
    const dConv = l.t.conversion_rate - l.c.conversion_rate;
    return '<tr data-open="' + esc(l.v.id) + '">' +
      '<td><div class="cell-title">' + esc(l.v.name) + '</div>' +
        '<div class="cell-sub">' + esc(l.v.folder || '') + (l.v.product ? ' &middot; ' + esc(l.v.product) : '') +
        (l.sustentou === true ? ' &middot; <span style="color:var(--pos)">sinal repetido no período anterior</span>' : '') +
        (l.sustentou === false ? ' &middot; <span style="color:var(--warn)">sinal invertido no período anterior</span>' : '') +
        '</div></td>' +
      '<td class="r">' + fInt(l.t.unique_views) + '</td>' +
      '<td class="r">' + fPct(l.split, 0) + '</td>' +
      deltaCel(l.t.retention, dRet, v => fPct(v, 1), 'pp') +
      deltaCel(l.t.conversion_rate, dConv, v => fPct(v, 2), 'pp') +
      deltaCel(l.t.epv, l.rpvUplift, fMoney, 'rel') +
      '<td class="r" style="color:' + (l.impacto > 0 ? 'var(--pos)' : l.impacto < 0 ? 'var(--neg)' : 'inherit') + '">' +
        (l.impacto > 0 ? '+' : '') + fMoney(l.impacto) + '</td>' +
      '<td class="r">' + conf + '</td>' +
      '<td class="r"><span class="verd ' + est.pill + '">' + est.rotulo + '</span>' +
        (l.estado === 'sem' ? '<div class="cell-sub">amostra ainda fina</div>' : '') + '</td>' +
    '</tr>';
  }).join('');

  tab.innerHTML = cabecalho + '<tbody>' + linhaControle + corpo + '</tbody>';
}

function renderTrackDecomp(T) {
  const box = $('#trackDecomp');
  if (!box) return;
  const alvos = [...T.linhas]
    .filter(l => Math.abs(l.rpvUplift) > 0.5)
    .sort((a, b) => Math.abs(b.impacto) - Math.abs(a.impacto))
    .slice(0, 4);

  if (!alvos.length) {
    box.innerHTML = testeVazio('Nenhuma variação mexeu o RPV',
      'As variações estão rendendo o mesmo que o controle por visita.');
    return;
  }

  box.innerHTML = alvos.map(l => {
    const escala = Math.max.apply(null, l.decomp.map(d => Math.abs(d.pct)).concat([Math.abs(l.rpvUplift), 5]));
    const dominante = [...l.decomp].sort((a, b) => b.share - a.share)[0];

    const linhas = l.decomp.map(d => {
      const larg = Math.min(50, (Math.abs(d.pct) / escala) * 50);
      const estilo = d.pct >= 0
        ? 'left:50%;width:' + larg.toFixed(1) + '%'
        : 'right:50%;width:' + larg.toFixed(1) + '%';
      return '<div class="wf-row"><span>' + d.label + '</span>' +
        '<div class="wf-track"><i class="wf-fill ' + (d.pct >= 0 ? 'pos' : 'neg') + '" style="' + estilo + '"></i></div>' +
        '<em style="color:' + (d.pct >= 0 ? 'var(--pos)' : 'var(--neg)') + '">' + fRel(d.pct) + '</em></div>';
    }).join('');

    const explica = dominante.key === 'tick'
      ? 'O movimento é de ticket. Antes de chamar de vencedor, confira se a oferta, o order bump ou o mix de produto mudaram junto.'
      : dominante.key === 'play'
        ? 'O movimento é de audiência: mais gente dando play, não necessariamente mais gente comprando.'
        : 'O movimento é de conversão, que é o que o teste realmente quer medir.';

    return '<div class="wf-card">' +
      '<div class="wf-head"><span class="wf-name">' + esc(l.v.name) + '</span>' +
        '<span class="wf-total ' + (l.rpvUplift >= 0 ? 'pos' : 'neg') + '">RPV ' + fRel(l.rpvUplift) + '</span></div>' +
      linhas +
      '<div class="wf-foot">' + explica + '</div>' +
    '</div>';
  }).join('');
}

function renderTrackNotes(T) {
  const box = $('#trackNotes');
  if (!box) return;
  const out = [];
  const L = T.linhas;

  if (T.controle && L.length) {
    const c = L[0].c;

    // 1. Prende mais e não vende mais: o meio do vídeo não é o problema.
    const presos = L.filter(l => l.ret && l.ret.significant && l.ret.uplift > 0 &&
                                 !(l.conv && l.conv.significant && l.conv.uplift > 0));
    if (presos.length) {
      const x = presos.sort((a, b) => b.t.unique_plays - a.t.unique_plays)[0];
      out.push({
        sev: 'warn',
        title: 'Retenção sobe, conversão não acompanha',
        body: esc(x.v.name) + ' leva ' + fPct(x.t.retention, 1) + ' do público até a oferta contra ' +
              fPct(c.retention, 1) + ' do controle, com confiança, mas a conversão fica em ' +
              fPct(x.t.conversion_rate, 2) + ' contra ' + fPct(c.conversion_rate, 2) + '. ' +
              'Mais gente chegando na oferta sem mais gente comprando aponta para a oferta, não para o meio do vídeo.' +
              (presos.length > 1 ? ' Outras ' + (presos.length - 1) + ' variações estão no mesmo caso.' : ''),
        todo: 'Mantenha o corpo do vídeo e teste preço, garantia e insistência do CTA.',
        videoId: x.v.id, linkText: 'Abrir criativo'
      });
    }

    // 2. RPV puxado por ticket, não por conversão.
    const porTicket = L.filter(l => l.rpvUplift > 5 &&
      [...l.decomp].sort((a, b) => b.share - a.share)[0].key === 'tick');
    if (porTicket.length) {
      const x = porTicket.sort((a, b) => b.impacto - a.impacto)[0];
      out.push({
        sev: 'info',
        title: 'O ganho de RPV é de ticket, não de conversão',
        body: esc(x.v.name) + ' aparece com RPV ' + fRel(x.rpvUplift) + ', mas o fator que mais pesa é o ticket médio (' +
              fMoney(x.t.aov) + ' contra ' + fMoney(c.aov) + '). Ticket costuma mudar por mix de oferta ou upsell, ' +
              'não pelo criativo — o resultado pode não sobreviver a uma troca de público.',
        todo: 'Confirme se a oferta por trás dos dois braços é idêntica antes de promover.',
        videoId: x.v.id, linkText: 'Abrir criativo'
      });
    }

    // 3. Split torto encarece o teste.
    const torto = L.filter(l => l.split > 0 && (l.split < 20 || l.split > 80));
    if (torto.length >= Math.max(1, Math.ceil(L.length * 0.4))) {
      out.push({
        sev: 'warn',
        title: 'A divisão de tráfego está desequilibrada',
        body: torto.length + ' de ' + L.length + ' variações recebem menos de 20% ou mais de 80% do tráfego do par. ' +
              'O poder do teste é limitado pelo braço menor, então um split torto faz o mesmo teste levar ' +
              'muito mais tempo para dizer qualquer coisa.',
        todo: 'Aproxime a divisão de 50/50 nos testes que você realmente quer decidir.'
      });
    }

    // 4. Sinal que se repetiu.
    const repetidos = L.filter(l => l.sustentou === true && l.conv && l.conv.uplift > 0);
    if (repetidos.length) {
      const x = repetidos.sort((a, b) => b.impacto - a.impacto)[0];
      out.push({
        sev: 'good',
        title: 'O sinal se repetiu no período anterior',
        body: esc(x.v.name) + ' está acima do controle na conversão agora e também estava no período de comparação. ' +
              'Repetição em duas janelas independentes vale mais do que um p-valor isolado.',
        todo: 'É a variação com menor risco de ser coincidência. Comece por ela.',
        videoId: x.v.id, linkText: 'Abrir criativo'
      });
    }

    // 5. Controle imbatível.
    const vencedores = L.filter(l => l.estado === 'ganha');
    if (!vencedores.length) {
      out.push({
        sev: 'info',
        title: 'Nenhuma variação supera o controle com confiança',
        body: 'Das ' + L.length + ' variações em teste, nenhuma bate ' + esc(T.controle.name) +
              ' na conversão com 95% de confiança. Isso não significa que todas são piores: ' +
              L.filter(l => l.estado === 'seguir').length + ' ainda não têm amostra para dizer.',
        todo: 'Segure o tráfego no controle e priorize os testes que estão perto de fechar amostra.'
      });
    } else {
      const x = vencedores.sort((a, b) => b.impacto - a.impacto)[0];
      out.push({
        sev: 'good',
        title: 'Há vencedor pronto para assumir tráfego',
        body: esc(x.v.name) + ' converte ' + fPct(x.t.conversion_rate, 2) + ' contra ' + fPct(c.conversion_rate, 2) +
              ' do controle. Aplicado a todo o tráfego do período, o ganho por visita representaria ' +
              fMoney(Math.abs(x.projecao)) + (x.projecao >= 0 ? ' a mais' : ' a menos') + ' de receita.',
        todo: 'Promova a variação e abra um novo teste contra ela, não contra o controle antigo.',
        videoId: x.v.id, linkText: 'Abrir criativo'
      });
    }

    // 6. Quem está queimando tráfego.
    const perdendo = L.filter(l => l.estado === 'perde');
    if (perdendo.length) {
      const custo = perdendo.reduce((s, l) => s + l.impacto, 0);
      out.push({
        sev: 'crit',
        title: 'Tráfego parado em variações já reprovadas',
        body: perdendo.length + (perdendo.length === 1 ? ' variação está' : ' variações estão') +
              ' abaixo do controle com confiança e continuam recebendo tráfego. ' +
              'No período, isso custou cerca de ' + fMoney(Math.abs(custo)) + ' em relação a rodar só o controle.',
        todo: 'Corte essas variações antes de abrir qualquer teste novo.',
        videoId: perdendo[0].v.id, linkText: 'Abrir ' + perdendo[0].v.name
      });
    }
  }

  if (T.semLeitura > 0) {
    out.push({
      sev: 'info',
      title: T.semLeitura + (T.semLeitura === 1 ? ' variação ainda não' : ' variações ainda não') + ' têm amostra para veredito',
      body: 'Elas aparecem no placar com os números do período, mas com menos de ' + fInt(TESTE.minPlays) +
            ' plays únicos em algum dos braços qualquer diferença ainda cabe dentro do ruído. ' +
            'Nada foi escondido da tela: o painel só não assina uma decisão que a amostra não sustenta.',
      todo: 'Concentre tráfego nas hipóteses que importam em vez de dividir entre muitos braços ao mesmo tempo.'
    });
  }

  box.innerHTML = out.length
    ? out.map(l =>
        '<article class="note sev-' + l.sev + '">' +
          '<h4>' + l.title + '</h4><p>' + l.body + '</p>' +
          (l.todo ? '<p class="note-do">' + l.todo + '</p>' : '') +
          (l.videoId ? '<button class="note-link" data-open="' + esc(l.videoId) + '">' + esc(l.linkText || 'Abrir') + '</button>' : '') +
        '</article>').join('')
    : '<div class="blank">Sem leituras para este recorte.</div>';
}

/* =========================================================
   ABA 2 — MATURIDADE
   ========================================================= */
function renderMatBuckets(T) {
  const box = $('#matBuckets');
  if (!box) return;
  const L = T.linhas;

  const grupos = [
    { estado: ['ganha', 'perde'], cls: 'good', k: 'Prontos para decidir',
      p: 'A amostra já separa a diferença do ruído. Decidir agora não aumenta a certeza, só adia o ganho.' },
    { estado: ['seguir'], cls: 'mid', k: 'Fecham em até ' + TESTE.horizonte + ' dias',
      p: 'O efeito observado é plausível e o tráfego atual confirma ou derruba dentro do ciclo normal.' },
    { estado: ['longo'], cls: 'info', k: 'Prazo longo',
      p: 'Fecham amostra, mas só depois de ' + TESTE.horizonte + ' dias. Valem a espera se a hipótese for prioritária.' },
    { estado: ['encerrar'], cls: 'bad', k: 'Fora de alcance',
      p: 'A diferença é pequena demais para o tráfego disponível. Esperar mais não resolve.' },
    { estado: ['sem'], cls: '', k: 'Sem volume para ler',
      p: 'Menos de ' + fInt(TESTE.minPlays) + ' plays únicos em algum dos braços. Não há leitura possível.' }
  ];

  box.innerHTML = grupos.map(g => {
    const itens = L.filter(l => g.estado.indexOf(l.estado) >= 0);
    const nomes = itens.slice(0, 4).map(l => esc(l.v.name)).join(' &middot; ');
    return '<div class="bucket ' + g.cls + '">' +
      '<div class="bucket-n">' + itens.length + '</div>' +
      '<div class="bucket-k">' + g.k + '</div>' +
      '<div class="bucket-p">' + g.p + '</div>' +
      (itens.length ? '<div class="bucket-list">' + nomes +
        (itens.length > 4 ? ' &middot; e mais ' + (itens.length - 4) : '') + '</div>' : '') +
    '</div>';
  }).join('');
}

function renderMatTable(T) {
  const tab = $('#matTable');
  if (!tab) return;
  if (!T.linhas.length) {
    tab.innerHTML = '<tbody><tr><td>' + testeVazio('Nenhum teste em andamento',
      'Sem variações além do controle no período escolhido.') + '</td></tr></tbody>';
    return;
  }

  const ordenadas = [...T.linhas].sort((a, b) =>
    ESTADOS[a.estado].ordem - ESTADOS[b.estado].ordem || b.progresso - a.progresso);

  const cab = '<thead><tr>' +
    '<th>Criativo</th>' +
    '<th class="r">Plays únicos</th>' +
    '<th class="r">Amostra efetiva</th>' +
    '<th class="r">Necessária</th>' +
    '<th class="r">Progresso</th>' +
    '<th class="r">Ritmo/dia</th>' +
    '<th class="r">Faltam</th>' +
    '<th class="r">Menor efeito visível</th>' +
    '<th class="r">Efeito observado</th>' +
    '<th class="r">Situação</th>' +
  '</tr></thead>';

  const corpo = ordenadas.map(l => {
    const est = ESTADOS[l.estado];
    const pronto = l.progresso >= 100;
    const efeito = l.conv ? fRel(l.conv.uplift) : '&mdash;';
    const corEfeito = l.conv && l.mde !== null && Math.abs(l.conv.uplift) >= l.mde ? 'var(--ink-1)' : 'var(--ink-3)';
    return '<tr data-open="' + esc(l.v.id) + '">' +
      '<td><div class="cell-title">' + esc(l.v.name) + '</div>' +
        '<div class="cell-sub">split ' + fPct(l.split, 0) + ' do par</div></td>' +
      '<td class="r">' + fInt(l.t.unique_plays) + '</td>' +
      '<td class="r">' + fInt(l.nEff) + '</td>' +
      '<td class="r">' + fAmostra(l.precisa) + '</td>' +
      '<td class="r">' + fPct(l.progresso, 0) +
        '<div class="prog"><i class="' + (pronto ? 'done' : '') + '" style="width:' + l.progresso.toFixed(1) + '%"></i></div></td>' +
      '<td class="r">' + fInt(l.ritmo) + '</td>' +
      '<td class="r">' + (l.faltam > 0 ? (l.faltam > 365 ? 'mais de 1 ano' : plural(l.faltam, 'dia', 'dias')) : '&mdash;') + '</td>' +
      '<td class="r">' + (l.mde !== null ? '&plusmn;' + fPct(l.mde, 1) : '&mdash;') + '</td>' +
      '<td class="r" style="color:' + corEfeito + '">' + efeito + '</td>' +
      '<td class="r"><span class="verd ' + est.pill + '">' + est.rotulo + '</span></td>' +
    '</tr>';
  }).join('');

  tab.innerHTML = cab + '<tbody>' + corpo + '</tbody>';
}

function renderMatBlind(T) {
  const box = $('#matBlind');
  if (!box) return;
  const alvos = T.linhas.filter(l => l.conv && l.mde !== null);
  if (!alvos.length) {
    box.innerHTML = testeVazio('Sem amostra para calcular a zona cega',
      'É preciso ao menos uma conversão no controle e tráfego nos dois braços.');
    return;
  }

  // Escala pelo percentil 75, não pelo máximo: um criativo minúsculo com zona
  // cega de 250% achataria todo o resto contra o zero.
  const refs = alvos.map(l => Math.max(Math.abs(l.conv.uplift), l.mde));
  let escala = Math.min(150, Math.max(20, percentil(refs, 0.5) * 1.3));
  const pos = v => Math.max(1.5, Math.min(98.5, 50 + (v / escala) * 50));

  const linhas = alvos
    .sort((a, b) => a.mde - b.mde)
    .map(l => {
      const ini = pos(-l.mde), fim = pos(l.mde);
      const x = pos(l.conv.uplift);
      const decidido = l.conv.significant;
      const visivel = Math.abs(l.conv.uplift) >= l.mde;
      const cor = decidido ? (l.conv.uplift > 0 ? 'pos' : 'neg') : 'mute';
      const tag = decidido
        ? fRel(l.conv.uplift) + ' &middot; já decidido'
        : (visivel ? fRel(l.conv.uplift) + ' &middot; quase lá'
                   : fRel(l.conv.uplift) + ' &middot; dentro da zona cega');
      return '<div class="blind-row">' +
        '<div class="blind-name" title="' + esc(l.v.name) + '">' + esc(l.v.name) + '</div>' +
        '<div><div class="blind-track">' +
          '<span class="blind-band" style="left:' + ini.toFixed(1) + '%;width:' + (fim - ini).toFixed(1) + '%"></span>' +
          '<span class="blind-zero" style="left:50%"></span>' +
          '<span class="blind-dot ' + cor + '" style="left:' + x.toFixed(1) + '%"></span>' +
        '</div></div>' +
        '<div class="blind-tag">' + tag + '</div>' +
      '</div>';
    }).join('');

  box.innerHTML = linhas +
    '<div class="blind-scale"><span>' + fRel(-escala) + '</span><span>0</span><span>' + fRel(escala) + '</span></div>' +
    '<p style="font-size:12px;color:var(--ink-3);margin-top:14px;max-width:80ch">' +
    'A faixa cinza é o menor efeito que a amostra daquele teste detectaria em 8 de cada 10 repetições. ' +
    'Ponto dentro dela quer dizer que, mesmo que a diferença seja real, esse teste provavelmente não vai prová-la ' +
    'sem muito mais tráfego. Pontos coloridos já passaram o corte de 95% e não dependem mais de espera. ' +
    'Escala cortada em ' + fPct(escala, 0) + ': valores maiores encostam na borda.</p>';
}

function renderMatNotes(T) {
  const box = $('#matNotes');
  if (!box) return;
  const L = T.linhas;
  const out = [];

  const prontos = L.filter(l => l.estado === 'ganha' || l.estado === 'perde');
  const rodando = L.filter(l => l.estado === 'seguir');
  const longos = L.filter(l => l.estado === 'longo');
  const parar = L.filter(l => l.estado === 'encerrar');

  if (prontos.length) {
    out.push({
      sev: 'good',
      title: plural(prontos.length, 'teste já tem volume', 'testes já têm volume') + ' para decidir',
      body: 'A amostra desses testes passou do necessário para o efeito que eles mostram. ' +
            'Continuar rodando não aumenta a certeza: só mantém tráfego dividido com um braço que já se sabe pior.',
      todo: 'Feche esses testes primeiro e devolva o tráfego ao vencedor.'
    });
  }

  if (rodando.length) {
    const maior = [...rodando].sort((a, b) => b.faltam - a.faltam)[0];
    const menor = [...rodando].sort((a, b) => a.faltam - b.faltam)[0];
    out.push({
      sev: 'warn',
      title: plural(rodando.length, 'teste fecha', 'testes fecham') + ' dentro do ciclo normal',
      body: 'No ritmo atual de tráfego, o primeiro fecha amostra em cerca de ' + plural(menor.faltam, 'dia', 'dias') +
            ' e o último em ' + plural(maior.faltam, 'dia', 'dias') + '. Decidir antes disso é ler ruído.',
      todo: 'Marque a data de leitura agora e não olhe o resultado antes dela.',
      videoId: menor.v.id, linkText: 'Ver ' + menor.v.name
    });
  }

  if (longos.length) {
    const x = [...longos].sort((a, b) => a.faltam - b.faltam)[0];
    out.push({
      sev: 'warn',
      title: plural(longos.length, 'teste passa', 'testes passam') + ' do prazo de ' + TESTE.horizonte + ' dias',
      body: 'Eles fecham amostra, mas não dentro do ciclo normal: ' + esc(x.v.name) +
            ' precisaria de mais ' + plural(x.faltam, 'dia', 'dias') + ' no ritmo de ' +
            fInt(x.ritmo) + ' plays por dia. O efeito é plausível, o tráfego é que é pouco.',
      todo: 'Vale a espera se a hipótese for prioritária. Senão, concentre tráfego nela para encurtar o prazo.',
      videoId: x.v.id, linkText: 'Abrir criativo'
    });
  }

  if (parar.length) {
    const x = [...parar].sort((a, b) => (b.mde || 0) - (a.mde || 0))[0];
    out.push({
      sev: 'info',
      title: plural(parar.length, 'teste procura', 'testes procuram') + ' um efeito que não cabe no tráfego',
      body: 'Em ' + esc(x.v.name) + ', a amostra atual só enxerga diferenças acima de ' + fPct(x.mde || 0, 1) +
            ', e o efeito observado é ' + (x.conv ? fRel(x.conv.uplift) : 'menor que isso') + '. ' +
            'Para confirmar algo desse tamanho seriam necessárias ' + fAmostra(x.precisa) +
            ' amostras por lado — meses no ritmo atual.',
      todo: 'Encerre e troque por variações mais agressivas: mudanças grandes aparecem com menos tráfego.',
      videoId: x.v.id, linkText: 'Abrir criativo'
    });
  }

  // Quais variações ainda valem a pena explorar.
  const promissoras = L.filter(l => (l.estado === 'seguir' || l.estado === 'longo') && l.conv && l.conv.uplift > 0)
    .sort((a, b) => b.conv.probB - a.conv.probB);
  if (promissoras.length) {
    const x = promissoras[0];
    out.push({
      sev: 'good',
      title: 'A variação com mais chance de virar vencedora',
      body: esc(x.v.name) + ' tem ' + fPct(Math.min(x.conv.probB, 99.9), 0) +
            ' de chance de estar realmente acima do controle, com ' + fPct(x.progresso, 0) +
            ' da amostra necessária. É a que mais compensa manter no ar.' +
            (promissoras.length > 1 ? ' Mais ' + plural(promissoras.length - 1, 'variação continua viva', 'variações continuam vivas') + '.' : ''),
      todo: 'Se precisar cortar braços para acelerar, corte os outros e mantenha este.',
      videoId: x.v.id, linkText: 'Abrir criativo'
    });
  }

  const totalFalta = rodando.concat(longos).reduce((s, l) => s + Math.max(0, (l.precisa || 0) - l.nEff), 0);
  if (totalFalta > 0) {
    out.push({
      sev: 'info',
      title: 'Custo de tráfego para fechar o que está aberto',
      body: 'Faltam cerca de ' + fInt(totalFalta) + ' plays únicos somando todos os testes em andamento. ' +
            'Esse é o preço, em audiência, de transformar as hipóteses de hoje em decisões.',
      todo: 'Rodar menos testes ao mesmo tempo faz cada um fechar antes.'
    });
  }

  box.innerHTML = out.length
    ? out.map(l =>
        '<article class="note sev-' + l.sev + '">' +
          '<h4>' + l.title + '</h4><p>' + l.body + '</p>' +
          (l.todo ? '<p class="note-do">' + l.todo + '</p>' : '') +
          (l.videoId ? '<button class="note-link" data-open="' + esc(l.videoId) + '">' + esc(l.linkText || 'Abrir') + '</button>' : '') +
        '</article>').join('')
    : '<div class="blank">Nenhum teste em andamento neste recorte.</div>';
}

/* =========================================================
   ABA 3 — LEITURA DOS TESTES
   ========================================================= */
function renderReadRule(T) {
  const box = $('#readRule');
  if (!box) return;
  const L = T.linhas;
  const nEffMediana = L.length ? median(L.map(l => l.nEff)) : 0;
  const mdes = L.filter(l => l.mde !== null).map(l => l.mde);

  const regras = [
    { k: 'Métrica primária', v: 'Conversão', p: 'Vendas sobre plays únicos. Retenção e RPV entram como apoio: ' +
      'servem para explicar o resultado, nunca para decidir sozinhas.' },
    { k: 'Corte estatístico', v: '95% / 80%', p: 'Confiança de 95% e poder de 80%, via teste z de duas proporções. ' +
      'O mesmo corte vale para toda variação, ganhando ou perdendo.' },
    { k: 'Volume para veredito', v: fInt(TESTE.minPlays) + ' plays', p: 'Plays únicos por braço. Não é filtro de entrada: ' +
      'a variação continua no placar com os números dela, só sai marcada como sem leitura.' },
    { k: 'Prazo máximo', v: TESTE.horizonte + ' dias', p: 'Teste que precisaria de mais que isso no ritmo atual é encerrado ' +
      'por inviabilidade, não por derrota.' },
    { k: 'Zona cega atual', v: mdes.length ? '&plusmn;' + fPct(median(mdes), 1) : '&mdash;',
      p: 'Menor diferença de conversão que a amostra mediana dos testes de hoje consegue enxergar.' },
    { k: 'Amostra mediana', v: fInt(nEffMediana), p: 'Amostra efetiva por braço, já descontado o desequilíbrio de split.' }
  ];

  box.innerHTML = regras.map(r =>
    '<div class="rule"><div class="rule-k">' + r.k + '</div>' +
    '<div class="rule-v">' + r.v + '</div>' +
    '<div class="rule-p">' + r.p + '</div></div>').join('');
}

function celulaPlacar(res, tipo) {
  if (!res) return '<td class="r" style="color:var(--ink-3)">&mdash;</td>';
  const forte = res.significant;
  const cor = !forte ? 'var(--ink-3)' : (res.uplift > 0 ? 'var(--pos)' : 'var(--neg)');
  const fundo = !forte ? 'transparent' : (res.uplift > 0 ? 'var(--pos-wash)' : 'var(--neg-wash)');
  const conf = res.confidence >= 99.9 ? '&gt;99,9%' : fPct(res.confidence, 0);
  return '<td class="r" style="color:' + cor + ';background:' + fundo + '">' + fRel(res.uplift) +
    '<span class="cell-delta" style="color:var(--ink-3)">' + (forte ? conf : 'ruído') + '</span></td>';
}

function renderReadBoard(T) {
  const tab = $('#readBoard');
  if (!tab) return;
  if (!T.controle || !T.linhas.length) {
    tab.innerHTML = '<tbody><tr><td>' + testeVazio('Nenhum par para ler',
      'Escolha um controle na aba Em teste ou amplie o período.') + '</td></tr></tbody>';
    return;
  }

  const cab = '<thead><tr>' +
    '<th>Variação contra ' + esc(T.controle.name) + '</th>' +
    '<th class="r">Play rate</th>' +
    '<th class="r">Retenção</th>' +
    '<th class="r">Clique no CTA</th>' +
    '<th class="r">Conversão</th>' +
    '<th class="r">RPV</th>' +
    '<th class="r">Chance de ser melhor</th>' +
    '<th class="r">Decisão</th>' +
  '</tr></thead>';

  const ordenadas = [...T.linhas].sort((a, b) =>
    ESTADOS[a.estado].ordem - ESTADOS[b.estado].ordem || b.impacto - a.impacto);

  const corpo = ordenadas.map(l => {
    const est = ESTADOS[l.estado];
    const chance = l.conv ? fPct(Math.min(l.conv.probB, 99.9), 0) : '&mdash;';
    const rpvCor = l.rpvUplift > 0 ? 'var(--pos)' : l.rpvUplift < 0 ? 'var(--neg)' : 'var(--ink-3)';
    return '<tr data-open="' + esc(l.v.id) + '">' +
      '<td><div class="cell-title">' + esc(l.v.name) + '</div>' +
        '<div class="cell-sub">' + fInt(l.t.unique_views) + ' visitas &middot; amostra efetiva ' + fInt(l.nEff) + '</div></td>' +
      celulaPlacar(l.play) +
      celulaPlacar(l.ret) +
      celulaPlacar(l.cta) +
      celulaPlacar(l.conv) +
      '<td class="r" style="color:' + rpvCor + '">' + fRel(l.rpvUplift) +
        '<span class="cell-delta" style="color:var(--ink-3)">' + (l.impacto >= 0 ? '+' : '') + fMoney(l.impacto) + '</span></td>' +
      '<td class="r">' + chance + '</td>' +
      '<td class="r"><span class="verd ' + est.pill + '">' + est.rotulo + '</span></td>' +
    '</tr>';
  }).join('');

  tab.innerHTML = cab + '<tbody>' + corpo + '</tbody>' +
    '<tfoot><tr><td colspan="8" style="padding:12px;font-size:12px;color:var(--ink-3);border:0">' +
    'RPV não é proporção e por isso não recebe teste de significância: a coluna mostra a diferença observada e o ' +
    'dinheiro que ela representou no período. A decisão sai da conversão.</td></tr></tfoot>';
}

function renderReadQueue(T) {
  const box = $('#readQueue');
  if (!box) return;
  const L = [...T.linhas].sort((a, b) =>
    ESTADOS[a.estado].ordem - ESTADOS[b.estado].ordem || b.impacto - a.impacto);

  if (!L.length) {
    box.innerHTML = testeVazio('Fila vazia', 'Nenhuma variação em teste no período.');
    return;
  }

  const hoje = parseISO($('#fEnd').value || iso(new Date()));
  const acoes = {
    ganha: l => ({
      titulo: 'Promover ' + esc(l.v.name),
      corpo: 'Conversão ' + fRel(l.conv.uplift) + ' acima do controle com ' +
             (l.conv.confidence >= 99.9 ? 'mais de 99,9%' : fPct(l.conv.confidence, 1)) + ' de confiança. ' +
             'Mover o tráfego do controle para ela vale <b>' + fMoney(Math.abs(l.projecao)) + '</b> no volume deste período.',
      quando: 'agora'
    }),
    perde: l => ({
      titulo: 'Cortar ' + esc(l.v.name),
      corpo: 'Está ' + fRel(l.conv.uplift) + ' abaixo do controle com confiança. Manter no ar custou <b>' +
             fMoney(Math.abs(l.impacto)) + '</b> no período.',
      quando: 'agora'
    }),
    seguir: l => ({
      titulo: 'Deixar ' + esc(l.v.name) + ' rodando',
      corpo: 'Amostra em ' + fPct(l.progresso, 0) + ' do necessário. No ritmo de ' + fInt(l.ritmo) +
             ' plays por dia, fecha em cerca de ' + plural(l.faltam, 'dia', 'dias') + '. ' +
             'Chance de estar acima do controle hoje: <b>' + fPct(Math.min(l.conv.probB, 99.9), 0) + '</b>.',
      quando: brDate(iso(shiftDays(hoje, l.faltam)))
    }),
    longo: l => ({
      titulo: 'Priorizar ou encurtar ' + esc(l.v.name),
      corpo: 'Amostra em ' + fPct(l.progresso, 0) + ' do necessário, mas o fechamento cai fora do ciclo de ' +
             TESTE.horizonte + ' dias: faltam <b>' + plural(l.faltam, 'dia', 'dias') + '</b> no ritmo de ' +
             fInt(l.ritmo) + ' plays por dia. Chance de estar acima do controle hoje: <b>' +
             fPct(Math.min(l.conv.probB, 99.9), 0) + '</b>. Dobrar o tráfego dela corta o prazo pela metade.',
      quando: brDate(iso(shiftDays(hoje, l.faltam)))
    }),
    encerrar: l => ({
      titulo: 'Encerrar ' + esc(l.v.name),
      corpo: 'O efeito observado (' + (l.conv ? fRel(l.conv.uplift) : 'mínimo') + ') é menor que o que a amostra ' +
             'consegue enxergar (' + (l.mde !== null ? '&plusmn;' + fPct(l.mde, 1) : 'o limite atual') + '). ' +
             'Mais tempo não muda isso; só uma hipótese mais ousada muda.',
      quando: 'agora'
    }),
    sem: l => ({
      titulo: 'Dar tráfego ou arquivar ' + esc(l.v.name),
      corpo: 'Menos de ' + fInt(TESTE.minPlays) + ' plays únicos em um dos braços. Sem leitura possível: ' +
             'ou recebe tráfego de verdade, ou sai do ar.',
      quando: '—'
    })
  };

  box.innerHTML = L.map((l, i) => {
    const a = acoes[l.estado](l);
    const est = ESTADOS[l.estado];
    return '<div class="queue-item">' +
      '<div class="queue-idx">' + String(i + 1).padStart(2, '0') + '</div>' +
      '<div><div class="queue-title">' + a.titulo + ' <span class="verd ' + est.pill + '" style="margin-left:6px">' +
        est.rotulo + '</span></div>' +
        '<div class="queue-body">' + a.corpo + '</div></div>' +
      '<div class="queue-when">' + a.quando + '</div>' +
    '</div>';
  }).join('');
}

function montarResumo(T) {
  const nl = '\n';
  if (!T.controle || !T.linhas.length) return 'Sem testes para reportar no período selecionado.';

  const c = T.linhas[0].c;
  const linhas = [];
  linhas.push('LEITURA DOS TESTES A/B — ' + brDate($('#fStart').value) + ' a ' + brDate($('#fEnd').value));
  linhas.push('Controle: ' + T.controle.name);
  linhas.push('  conversão ' + fPct(c.conversion_rate, 2) + ' | RPV ' + fMoney(c.epv) +
              ' | retenção ' + fPct(c.retention, 1) + ' | ' + fInt(c.unique_views) + ' visitas');
  linhas.push('Régua: conversão como métrica primária, 95% de confiança, 80% de poder, ' +
              fInt(TESTE.minPlays) + ' plays mínimos por braço.');
  linhas.push('');

  const blocos = [
    { estado: 'ganha', t: 'DECIDIR AGORA — PROMOVER' },
    { estado: 'perde', t: 'DECIDIR AGORA — CORTAR' },
    { estado: 'seguir', t: 'SEGUIR RODANDO (fecha em até ' + TESTE.horizonte + ' dias)' },
    { estado: 'longo', t: 'PRAZO LONGO — priorizar ou dar mais tráfego' },
    { estado: 'encerrar', t: 'FORA DE ALCANCE — encerrar' },
    { estado: 'sem', t: 'SEM VOLUME PARA LER' }
  ];

  blocos.forEach(b => {
    const itens = T.linhas.filter(l => l.estado === b.estado);
    if (!itens.length) return;
    linhas.push(b.t);
    itens.forEach(l => {
      let det;
      if (b.estado === 'ganha' || b.estado === 'perde') {
        det = 'conversão ' + fRel(l.conv.uplift) + ' (confiança ' +
              (l.conv.confidence >= 99.9 ? '>99,9%' : fPct(l.conv.confidence, 1)) + '), ' +
              'impacto no período ' + (l.impacto >= 0 ? '+' : '') + fMoney(l.impacto);
      } else if (b.estado === 'seguir' || b.estado === 'longo') {
        det = fPct(l.progresso, 0) + ' da amostra, faltam ~' + plural(l.faltam, 'dia', 'dias') +
              ', chance de ser melhor ' + fPct(Math.min(l.conv.probB, 99.9), 0);
      } else if (b.estado === 'encerrar') {
        det = 'efeito ' + (l.conv ? fRel(l.conv.uplift) : 'mínimo') + ' contra zona cega de ' +
              (l.mde !== null ? '+/-' + fPct(l.mde, 1) : 'amostra insuficiente');
      } else {
        det = fInt(l.t.unique_plays) + ' plays únicos, abaixo do mínimo de leitura';
      }
      linhas.push('  - ' + l.v.name);
      linhas.push('      ' + det);
    });
    linhas.push('');
  });

  const ganha = T.linhas.filter(l => l.estado === 'ganha');
  const perde = T.linhas.filter(l => l.estado === 'perde');
  const ganhoTotal = ganha.reduce((s, l) => s + l.projecao, 0);
  const custoTotal = perde.reduce((s, l) => s + l.impacto, 0);

  linhas.push('EM UMA LINHA');
  if (ganha.length) {
    linhas.push('  ' + plural(ganha.length, 'variação pronta', 'variações prontas') +
                ' para assumir tráfego, valendo ' + fMoney(Math.abs(ganhoTotal)) + ' no volume deste período.');
  } else {
    linhas.push('  Nenhuma variação supera o controle com confiança até aqui.');
  }
  if (perde.length) {
    linhas.push('  ' + plural(perde.length, 'variação reprovada segue', 'variações reprovadas seguem') +
                ' no ar, custando ' + fMoney(Math.abs(custoTotal)) + ' por período.');
  }
  const rodando = T.linhas.filter(l => l.estado === 'seguir');
  if (rodando.length) {
    const prazo = Math.max.apply(null, rodando.map(l => l.faltam));
    linhas.push('  ' + plural(rodando.length, 'teste fecha', 'testes fecham') +
                ' amostra em até ' + plural(prazo, 'dia', 'dias') + ' no ritmo atual.');
  }
  const longos = T.linhas.filter(l => l.estado === 'longo');
  if (longos.length) {
    linhas.push('  ' + plural(longos.length, 'teste precisa', 'testes precisam') +
                ' de mais tráfego para fechar dentro de um ciclo de ' + TESTE.horizonte + ' dias.');
  }

  return linhas.join(nl);
}

function renderReadSummary(T) {
  const box = $('#readSummary');
  if (!box) return;
  box.textContent = montarResumo(T);
}

function copiarResumo() {
  const box = $('#readSummary');
  if (!box) return;
  const txt = box.textContent || '';
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(txt).then(
      () => toast('Resumo copiado.', 'ok'),
      () => toast('Não foi possível copiar.', 'err')
    );
    return;
  }
  const area = document.createElement('textarea');
  area.value = txt;
  document.body.appendChild(area);
  area.select();
  try { document.execCommand('copy'); toast('Resumo copiado.', 'ok'); }
  catch (e) { toast('Não foi possível copiar.', 'err'); }
  area.remove();
}

function exportTesteCsv() {
  const T = S.teste;
  if (!T || !T.linhas.length) { toast('Não há testes para exportar.', 'err'); return; }

  const cab = ['Controle', 'Variação', 'ID', 'Visitas únicas', 'Split (%)', 'Plays únicos',
               'Amostra efetiva', 'Amostra necessária', 'Progresso (%)', 'Faltam (dias)',
               'Retenção (%)', 'Delta retenção (p.p.)', 'Conversão (%)', 'Delta conversão (p.p.)',
               'Uplift conversão (%)', 'Confiança (%)', 'Chance de ser melhor (%)',
               'Menor efeito visível (%)', 'RPV (R$)', 'Uplift RPV (%)', 'Impacto período (R$)',
               'Projeção tráfego total (R$)', 'Situação'];

  const cel = v => {
    const s = String(v == null ? '' : v);
    return /[;"\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const dec = n => (n || 0).toFixed(2).replace('.', ',');

  const corpo = T.linhas.map(l => [
    T.controle.name, l.v.name, l.v.id, l.t.unique_views, dec(l.split), l.t.unique_plays,
    Math.round(l.nEff), l.precisa || '', dec(l.progresso), l.faltam || '',
    dec(l.t.retention), dec(l.t.retention - l.c.retention),
    dec(l.t.conversion_rate), dec(l.t.conversion_rate - l.c.conversion_rate),
    l.conv ? dec(l.conv.uplift) : '', l.conv ? dec(l.conv.confidence) : '',
    l.conv ? dec(l.conv.probB) : '', l.mde !== null ? dec(l.mde) : '',
    dec(l.t.epv), dec(l.rpvUplift), dec(l.impacto), dec(l.projecao),
    ESTADOS[l.estado].rotulo
  ].map(cel).join(';'));

  const csv = '\uFEFF' + cab.join(';') + '\n' + corpo.join('\n');
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8;' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = 'testes-' + $('#fStart').value + '-a-' + $('#fEnd').value + '.csv';
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
  toast('CSV dos testes baixado.', 'ok');
}

/** Ponto único de entrada das três abas. */
function renderTestes() {
  if (!$('#trackFocus')) return;
  const T = avaliarTestes();

  const ref = $('#testRef');
  if (ref) {
    ref.innerHTML = T.controle
      ? 'Controle: <b>' + esc(T.controle.name) + '</b> &middot; ' + T.linhas.length +
        (T.linhas.length === 1 ? ' variação em teste' : ' variações em teste') +
        (T.semLeitura ? ' &middot; ' + T.semLeitura + ' sem amostra para veredito' : '') +
        ' &middot; janela de ' + T.dias + (T.dias === 1 ? ' dia' : ' dias')
      : 'Sem criativos com tráfego no período.';
  }

  renderTrackFocus(T);
  renderTrackTable(T);
  renderTrackDecomp(T);
  renderTrackNotes(T);

  renderMatBuckets(T);
  renderMatTable(T);
  renderMatBlind(T);
  renderMatNotes(T);

  renderReadRule(T);
  renderReadBoard(T);
  renderReadQueue(T);
  renderReadSummary(T);
}

function aplicarFiltrosTeste() {
  const sel = $('#testControl');
  if (sel) TESTE.controlId = sel.value || '';
  try {
    localStorage.setItem('vsl.teste.control', TESTE.controlId);
    localStorage.removeItem('vsl.teste.minvol');
  } catch (e) {}
  renderTestes();
}
"""

_JS += r"""
/* =========================================================
   LIGAÇÕES E INICIALIZAÇÃO
   ========================================================= */
function debounce(fn, ms) {
  let t; return function () { clearTimeout(t); const a = arguments; t = setTimeout(() => fn.apply(null, a), ms); };
}

function initPickers() {
  if (typeof flatpickr === 'undefined') return;
  flatpickr.l10ns.pt.rangeSeparator = ' a ';

  flatpickr('#mainRange', {
    mode: 'range', dateFormat: 'd/m/Y', locale: 'pt', maxDate: 'today',
    onChange(sel, _s, inst) {
      if (sel.length === 2) {
        $('#fStart').value = inst.formatDate(sel[0], 'Y-m-d');
        $('#fEnd').value = inst.formatDate(sel[1], 'Y-m-d');
        syncBaselineFields();
        markPreset($('#fStart').value, $('#fEnd').value);
      }
    }
  });

  flatpickr('#baseRange', {
    mode: 'range', dateFormat: 'd/m/Y', locale: 'pt', maxDate: 'today',
    onChange(sel, _s, inst) {
      if (sel.length === 2) {
        $('#fBaseStart').value = inst.formatDate(sel[0], 'Y-m-d');
        $('#fBaseEnd').value = inst.formatDate(sel[1], 'Y-m-d');
        // Escolha manual: desliga a base automática para ela não sobrescrever
        // as datas na próxima troca de período.
        if ($('#fAuto').checked) { $('#fAuto').checked = false; savePrefs(); }
      } else if (!sel.length) {
        $('#fBaseStart').value = ''; $('#fBaseEnd').value = '';
      }
    }
  });
}

function restorePrefs() {
  try {
    applyTheme(localStorage.getItem('vsl.theme') || 'dark');
    const url = new URLSearchParams(location.search);
    if (!url.has('campanha')) {
      const c = localStorage.getItem('vsl.campaign');
      if (c) $('#fCampaign').value = c;
    }
    const auto = localStorage.getItem('vsl.auto');
    if (auto !== null) $('#fAuto').checked = auto === '1';
    const tc = localStorage.getItem('vsl.teste.control');
    if (tc) TESTE.controlId = tc;
    localStorage.removeItem('vsl.teste.minvol');  // preferência antiga do corte de visitas
  } catch (e) {}
}

function savePrefs() {
  try {
    localStorage.setItem('vsl.campaign', $('#fCampaign').value.trim());
    localStorage.setItem('vsl.auto', $('#fAuto').checked ? '1' : '0');
  } catch (e) {}
}

/* =========================================================
   TG BRANDS — TRÁFEGO x FATURAMENTO
   ========================================================= */
const DIAS_SEMANA = ['dom', 'seg', 'ter', 'qua', 'qui', 'sex', 'sáb'];
const diaSemana = iso => DIAS_SEMANA[parseISO(iso).getDay()];
const hojeISO = () => { const d = new Date(); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); };

function tgMetricas(t) {
  t = t || {};
  return {
    revenue: t.revenue || 0,
    unique_views: t.unique_views || 0,
    unique_plays: t.unique_plays || 0,
    conversions: t.conversions || 0,
    rpv: t.unique_views ? (t.revenue || 0) / t.unique_views : 0,
    play_rate: t.unique_views ? (t.unique_plays / t.unique_views) * 100 : 0,
    conv: t.unique_plays ? (t.conversions / t.unique_plays) * 100 : 0,
    aov: t.conversions ? (t.revenue || 0) / t.conversions : 0
  };
}

/** Variação sempre contra o período anterior: aqui a base é automática. */
function tgChg(agora, antes, tipo) {
  if (tipo === 'rate') {
    const d = (agora || 0) - (antes || 0);
    const cls = Math.abs(d) < 0.3 ? 'flat' : (d > 0 ? 'up' : 'down');
    return '<span class="chg ' + cls + '">' + fPP(d) + '</span>';
  }
  if (!antes) return agora ? '<span class="chg up">novo</span>' : '<span class="chg flat">0,0%</span>';
  const d = ((agora - antes) / antes) * 100;
  const cls = Math.abs(d) < 1 ? 'flat' : (d > 0 ? 'up' : 'down');
  return '<span class="chg ' + cls + '">' + fRel(d) + '</span>';
}

function tgRecorte() {
  const T = S.tg;
  if (S.tgBrand) {
    const b = T.brands.find(x => x.name === S.tgBrand);
    if (b) return { days: b.days, totals: b.totals, prev: b.prev_totals, nome: b.name };
    S.tgBrand = '';
  }
  return { days: T.days, totals: T.totals, prev: T.prev_totals, nome: 'Todos os brands' };
}

async function loadTg() {
  const f = readFilters();
  if (!f.start || !f.end) return;
  const chave = f.start + '|' + f.end;
  if (S.tg && S.tgKey === chave) return;
  S.tgKey = chave;

  ['#tgTicker', '#tgNotes', '#tgChart', '#tgRpv'].forEach(sel => {
    $(sel).innerHTML = '<div class="skel" style="height:' + (sel === '#tgChart' ? 300 : 110) + 'px;border-radius:9px"></div>';
  });
  $('#tgDays').innerHTML = '';
  $('#tgBrands').innerHTML = '';
  loadbar(true);

  const q = new URLSearchParams({ start: f.start, end: f.end, route: 'tg' });
  try {
    const res = await fetch('/api/tg?' + q.toString(), { credentials: 'include' });
    if (res.status === 401) { location.href = '/'; return; }
    const data = await lerJson(res, '/api/tg');
    if (S.tgKey !== chave) return;  // o período mudou no meio do caminho
    S.tg = data;
    loadbar(false);

    $('#tgBrand').innerHTML = '<option value="">Todos os brands</option>' +
      data.brands.map(b => '<option value="' + esc(b.name) + '">' + esc(b.name) + '</option>').join('');
    $('#tgBrand').value = S.tgBrand;

    let nota = data.players + ' VSLs de ' + data.brands.length + ' brands. Variações contra ' +
      brDate(data.prev_start) + ' a ' + brDate(data.prev_end) + ' (mesmo número de dias, imediatamente antes).';
    if (data.missing && data.missing.length) nota += ' ' + data.missing.length + ' VSL(s) do mapa não foram achadas na vTurb.';
    if (data.failed) nota += ' ' + data.failed + ' VSL(s) falharam na consulta: os totais podem estar incompletos.';
    $('#tgNote').textContent = nota;
    renderTg();
  } catch (err) {
    loadbar(false);
    S.tgKey = null;
    console.error(err);
    $('#tgTicker').innerHTML = '<div class="blank" style="grid-column:1/-1"><b>Não deu para carregar a visão TG</b>' + esc(err.message) + '</div>';
    ['#tgNotes', '#tgChart', '#tgRpv'].forEach(sel => { $(sel).innerHTML = ''; });
  }
}

function renderTg() {
  if (!S.tg) return;
  const R = tgRecorte();
  $('#tgBrand').value = S.tgBrand;
  renderTgTicker(R);
  renderTgVsls();
  renderTgNotes(R);
  drawTgChart(R);
  drawTgRpv(R);
  renderTgDays(R);
  renderTgBrands();
}

function renderTgTicker(R) {
  const a = tgMetricas(R.totals), p = tgMetricas(R.prev);
  const n = R.days.length || 1;
  const itens = [
    { k: 'Faturamento', v: fMoneyShort(a.revenue), c: tgChg(a.revenue, p.revenue), lead: true },
    { k: 'Visitas únicas', v: fShort(a.unique_views), c: tgChg(a.unique_views, p.unique_views), lead: true },
    { k: 'Receita por visita', v: fMoney(a.rpv), c: tgChg(a.rpv, p.rpv), lead: true },
    { k: 'Faturamento médio/dia', v: fMoneyShort(a.revenue / n), c: tgChg(a.revenue, p.revenue) },
    { k: 'Visitas médias/dia', v: fShort(a.unique_views / n), c: tgChg(a.unique_views, p.unique_views) },
    { k: 'Vendas', v: fInt(a.conversions), c: tgChg(a.conversions, p.conversions) },
    { k: 'Ticket médio', v: fMoney(a.aov), c: tgChg(a.aov, p.aov) },
    { k: 'Converte (por play)', v: fPct(a.conv, 2), c: tgChg(a.conv, p.conv, 'rate') }
  ];
  $('#tgTicker').innerHTML = itens.map(i =>
    '<div class="tick' + (i.lead ? ' lead' : '') + '">' +
      '<div class="tick-k">' + i.k + '</div>' +
      '<div class="tick-v num">' + i.v + '</div>' + i.c +
    '</div>').join('');
}

function renderTgNotes(R) {
  const a = tgMetricas(R.totals), p = tgMetricas(R.prev);
  if (!a.unique_views) {
    $('#tgNotes').innerHTML = '<div class="blank"><b>Sem tráfego no período</b>Nenhuma visita registrada nas VSLs do TG.</div>';
    return;
  }
  const notas = [];
  const sinal = v => (v >= 0 ? '+' : '−') + fMoneyShort(Math.abs(v));

  // Decomposição: Δfaturamento = efeito volume (tráfego) + efeito eficiência (receita por visita).
  if (p.unique_views) {
    const dRev = a.revenue - p.revenue;
    const efVolume = (a.unique_views - p.unique_views) * p.rpv;
    const efRpv = a.unique_views * (a.rpv - p.rpv);
    const rel = p.revenue ? (dRev / p.revenue) * 100 : 0;
    notas.push({
      sev: rel >= 1 ? 'sev-good' : (rel <= -1 ? 'sev-crit' : 'sev-info'),
      t: 'Faturamento ' + (dRev >= 0 ? 'subiu ' : 'caiu ') + fMoneyShort(Math.abs(dRev)) + ' (' + fRel(rel) + ')',
      p: 'Tráfego explica ' + sinal(efVolume) + ' e receita por visita explica ' + sinal(efRpv) + '.',
      d: Math.abs(efVolume) >= Math.abs(efRpv)
        ? 'O motor da variação foi o volume de tráfego, não a eficiência das VSLs.'
        : 'O motor da variação foi quanto cada visita rendeu, não o volume.'
    });

    const dV = ((a.unique_views - p.unique_views) / p.unique_views) * 100;
    const dR = p.rpv ? ((a.rpv - p.rpv) / p.rpv) * 100 : 0;
    let leitura, sev;
    if (dV > 3 && dR < -3) { leitura = 'Mais tráfego, mas cada visita rendendo menos: o volume novo está entrando mais frio ou caindo em VSLs piores.'; sev = 'sev-warn'; }
    else if (dV < -3 && dR > 3) { leitura = 'Menos tráfego, mas mais eficiente: dá espaço para escalar de novo, a conversão está aguentando.'; sev = 'sev-info'; }
    else if (dV > 3 && dR > 3) { leitura = 'Tráfego e eficiência subindo juntos: o melhor cenário para escalar.'; sev = 'sev-good'; }
    else if (dV < -3 && dR < -3) { leitura = 'Tráfego e eficiência caindo juntos: olhe primeiro os brands com maior queda de receita por visita.'; sev = 'sev-crit'; }
    else { leitura = 'Sem mudança relevante na relação entre tráfego e faturamento.'; sev = 'sev-info'; }
    notas.push({
      sev, t: 'Visitas ' + fRel(dV) + ' · receita por visita ' + fRel(dR),
      p: fMoney(p.rpv) + ' → ' + fMoney(a.rpv) + ' por visita.', d: leitura
    });
  }

  // O dia de hoje ainda está em andamento: fica fora do melhor/pior dia.
  const comVisita = R.days.filter(d => d.unique_views > 0 && d.date !== hojeISO());
  if (comVisita.length >= 2) {
    const rpvDia = d => d.revenue / d.unique_views;
    const melhor = comVisita.reduce((x, y) => rpvDia(y) > rpvDia(x) ? y : x);
    const pior = comVisita.reduce((x, y) => rpvDia(y) < rpvDia(x) ? y : x);
    const topo = comVisita.reduce((x, y) => y.revenue > x.revenue ? y : x);
    const dd = d => brDate(d.date).slice(0, 5) + ' (' + diaSemana(d.date) + ')';
    notas.push({
      sev: 'sev-info', t: 'Melhor dia: ' + dd(topo) + ' com ' + fMoneyShort(topo.revenue),
      p: 'Por visita, o melhor foi ' + dd(melhor) + ' com ' + fMoney(rpvDia(melhor)) + ' e o pior ' +
         dd(pior) + ' com ' + fMoney(rpvDia(pior)) + '.',
      d: 'Diferença de ' + fRel(rpvDia(pior) ? ((rpvDia(melhor) - rpvDia(pior)) / rpvDia(pior)) * 100 : 0) +
         ' entre o melhor e o pior dia, com a mesma estrutura de VSLs.'
    });
  }

  $('#tgNotes').innerHTML = notas.map(n =>
    '<div class="note ' + n.sev + '"><h4>' + esc(n.t) + '</h4><p>' + esc(n.p) + '</p>' +
    '<div class="note-do">' + esc(n.d) + '</div></div>').join('');
}

function tgEixoX(dias, W, padL, padR, H) {
  const passo = (W - padL - padR) / dias.length;
  const cada = Math.max(1, Math.ceil(dias.length / 16));
  const cx = i => padL + passo * (i + 0.5);
  const rotulos = dias.map((d, i) => i % cada ? '' :
    '<text x="' + cx(i).toFixed(1) + '" y="' + (H - 9) + '" text-anchor="middle" class="g-text">' +
    brDate(d.date).slice(0, 5) + '</text>').join('');
  return { passo, cx, rotulos };
}

function tgAlvos(dias, X, padL, padT, util) {
  return dias.map((d, i) =>
    '<rect class="tg-hit" data-i="' + i + '" x="' + (padL + X.passo * i).toFixed(1) + '" y="' + padT +
    '" width="' + X.passo.toFixed(1) + '" height="' + util + '"/>').join('');
}

function drawTgChart(R) {
  const box = $('#tgChart');
  const dias = R.days;
  if (!dias.length) { box.innerHTML = '<div class="blank"><b>Sem dias no período</b></div>'; return; }

  const W = Math.max(760, dias.length * 26), H = 300, padL = 72, padR = 100, padT = 18, padB = 30;
  const util = H - padT - padB;
  const tetoV = Math.max(...dias.map(d => d.unique_views), 1) * 1.15;
  const tetoR = Math.max(...dias.map(d => d.revenue), 1) * 1.15;
  const yV = v => padT + util * (1 - v / tetoV);
  const yR = v => padT + util * (1 - v / tetoR);
  const X = tgEixoX(dias, W, padL, padR, H);

  const grade = [0, 0.25, 0.5, 0.75, 1].map(f => {
    const gy = padT + util * f;
    return '<line x1="' + padL + '" y1="' + gy.toFixed(1) + '" x2="' + (W - padR) + '" y2="' + gy.toFixed(1) + '" class="g-dash"/>' +
      '<text x="' + (padL - 8) + '" y="' + (gy + 4).toFixed(1) + '" text-anchor="end" class="g-text" style="fill:var(--cyan)">' + fShort(tetoV * (1 - f)) + '</text>' +
      '<text x="' + (W - padR + 8) + '" y="' + (gy + 4).toFixed(1) + '" class="g-text" style="fill:var(--brand-2)">' + fMoneyShort(tetoR * (1 - f)) + '</text>';
  }).join('');

  const larg = Math.max(Math.min(X.passo * 0.62, 34), 2);
  const barras = dias.map((d, i) =>
    '<rect class="tg-traffic" x="' + (X.cx(i) - larg / 2).toFixed(1) + '" y="' + yV(d.unique_views).toFixed(1) +
    '" width="' + larg.toFixed(1) + '" height="' + Math.max(padT + util - yV(d.unique_views), 1).toFixed(1) + '" rx="3"/>').join('');
  const linha = '<path class="tg-rev" d="' + dias.map((d, i) => (i ? 'L' : 'M') + X.cx(i).toFixed(1) + ' ' + yR(d.revenue).toFixed(1)).join(' ') + '"/>';
  const pontos = dias.length <= 45 ? dias.map((d, i) =>
    '<circle class="tg-dot" cx="' + X.cx(i).toFixed(1) + '" cy="' + yR(d.revenue).toFixed(1) + '" r="3.5"/>').join('') : '';

  box.innerHTML =
    '<div class="legend">' +
      '<span class="legend-item" style="cursor:default"><span class="swatch" style="background:var(--cyan);opacity:.6"></span>Visitas únicas</span>' +
      '<span class="legend-item" style="cursor:default"><span class="swatch" style="background:var(--brand-2)"></span>Faturamento</span>' +
      '<span class="legend-item" style="cursor:default;color:var(--ink-3)">' + esc(R.nome) + '</span>' +
    '</div>' +
    '<div class="scroll-x"><svg viewBox="0 0 ' + W + ' ' + H + '" class="chart" style="min-width:' + Math.min(W, 760) + 'px" preserveAspectRatio="xMidYMid meet">' +
    grade + barras + linha + pontos + X.rotulos + tgAlvos(dias, X, padL, padT, util) + '</svg></div>';

  $$('#tgChart .tg-hit').forEach(r => {
    r.addEventListener('mousemove', ev => {
      const d = dias[Number(r.dataset.i)];
      showTip(ev, '<div class="tip-h">' + brDate(d.date) + ' &middot; ' + diaSemana(d.date) + '</div>' +
        '<div class="tip-row"><span>Visitas únicas</span><b>' + fInt(d.unique_views) + '</b></div>' +
        '<div class="tip-row"><span>Faturamento</span><b>' + fMoney(d.revenue) + '</b></div>' +
        '<div class="tip-row"><span>Vendas</span><b>' + fInt(d.conversions) + '</b></div>' +
        '<div class="tip-row"><span>Por visita</span><b>' + fMoney(tgMetricas(d).rpv) + '</b></div>');
    });
    r.addEventListener('mouseleave', hideTip);
  });
}

function drawTgRpv(R) {
  const box = $('#tgRpv');
  const dias = R.days;
  const rpv = dias.map(d => d.unique_views ? d.revenue / d.unique_views : null);
  const validos = rpv.filter(v => v !== null);
  if (!validos.length) { box.innerHTML = '<div class="blank"><b>Sem visitas no período</b></div>'; return; }
  const media = tgMetricas(R.totals).rpv;

  const W = Math.max(760, dias.length * 26), H = 200, padL = 72, padR = 100, padT = 16, padB = 30;
  const util = H - padT - padB;
  const teto = Math.max(...validos, media, 0.01) * 1.2;
  const y = v => padT + util * (1 - v / teto);
  const X = tgEixoX(dias, W, padL, padR, H);

  const grade = [0, 0.5, 1].map(f => {
    const gy = padT + util * f;
    return '<line x1="' + padL + '" y1="' + gy.toFixed(1) + '" x2="' + (W - padR) + '" y2="' + gy.toFixed(1) + '" class="g-dash"/>' +
      '<text x="' + (padL - 8) + '" y="' + (gy + 4).toFixed(1) + '" text-anchor="end" class="g-text">' + fMoney(teto * (1 - f)) + '</text>';
  }).join('');
  let caminho = '', aberto = false;
  rpv.forEach((v, i) => {
    if (v === null) { aberto = false; return; }
    caminho += (aberto ? 'L' : 'M') + X.cx(i).toFixed(1) + ' ' + y(v).toFixed(1) + ' ';
    aberto = true;
  });
  const pontos = rpv.map((v, i) => v === null ? '' :
    '<circle class="tg-dot" cx="' + X.cx(i).toFixed(1) + '" cy="' + y(v).toFixed(1) + '" r="3.2" style="fill:' +
    (v < media ? 'var(--neg)' : 'var(--pos)') + '"/>').join('');
  const linhaMedia = '<line class="tg-avg" x1="' + padL + '" x2="' + (W - padR) + '" y1="' + y(media).toFixed(1) + '" y2="' + y(media).toFixed(1) + '"/>' +
    '<text x="' + (W - padR + 8) + '" y="' + (y(media) + 4).toFixed(1) + '" class="g-text" style="fill:var(--warn)">média</text>';

  box.innerHTML =
    '<div class="legend">' +
      '<span class="legend-item" style="cursor:default"><span class="swatch" style="background:var(--pos)"></span>Acima da média do período</span>' +
      '<span class="legend-item" style="cursor:default"><span class="swatch" style="background:var(--neg)"></span>Abaixo da média</span>' +
      '<span class="legend-item" style="cursor:default"><span class="swatch" style="background:var(--warn)"></span>Média: ' + fMoney(media) + '</span>' +
    '</div>' +
    '<div class="scroll-x"><svg viewBox="0 0 ' + W + ' ' + H + '" class="chart" style="min-width:' + Math.min(W, 760) + 'px" preserveAspectRatio="xMidYMid meet">' +
    grade + linhaMedia + '<path class="tg-rev" d="' + caminho + '"/>' + pontos + X.rotulos + tgAlvos(dias, X, padL, padT, util) + '</svg></div>';

  $$('#tgRpv .tg-hit').forEach(r => {
    r.addEventListener('mousemove', ev => {
      const i = Number(r.dataset.i), d = dias[i];
      showTip(ev, '<div class="tip-h">' + brDate(d.date) + ' &middot; ' + diaSemana(d.date) + '</div>' +
        '<div class="tip-row"><span>Por visita</span><b>' + (rpv[i] === null ? '—' : fMoney(rpv[i])) + '</b></div>' +
        '<div class="tip-row"><span>Média do período</span><b>' + fMoney(media) + '</b></div>');
    });
    r.addEventListener('mouseleave', hideTip);
  });
}

function tgLinhaDia(rotulo, d, cls) {
  const m = tgMetricas(d);
  return '<tr' + (cls ? ' class="' + cls + '"' : '') + '><td>' + rotulo + '</td>' +
    '<td class="r">' + fInt(d.unique_views) + '</td>' +
    '<td class="r">' + fInt(d.unique_plays) + '</td>' +
    '<td class="r">' + fPct(m.play_rate, 1) + '</td>' +
    '<td class="r">' + fInt(d.conversions) + '</td>' +
    '<td class="r">' + fPct(m.conv, 2) + '</td>' +
    '<td class="r">' + (d.conversions ? fMoney(m.aov) : '—') + '</td>' +
    '<td class="r">' + fMoney(m.rpv) + '</td>' +
    '<td class="r hot">' + fMoney(d.revenue) + '</td></tr>';
}

function renderTgDays(R) {
  const linhas = R.days.slice().reverse().map(d =>
    tgLinhaDia(brDate(d.date) + '<span class="tg-day">' + diaSemana(d.date) +
      (d.date === hojeISO() ? ' &middot; parcial' : '') + '</span>', d));
  $('#tgDays').innerHTML = linhas.join('') + tgLinhaDia('Total', R.totals, 'tg-total');
}

function tgSpark(dias) {
  const W = 120, H = 26;
  const teto = Math.max(...dias.map(d => d.revenue), 1);
  const passo = dias.length > 1 ? W / (dias.length - 1) : 0;
  const d = dias.map((x, i) => (i ? 'L' : 'M') + (i * passo).toFixed(1) + ' ' + (H - 2 - (x.revenue / teto) * (H - 4)).toFixed(1)).join(' ');
  return '<svg class="tg-spark" viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none">' +
    '<path class="tg-rev" style="stroke-width:1.6" vector-effect="non-scaling-stroke" d="' + d + '"/></svg>';
}

function renderTgBrands() {
  const T = S.tg;
  const brands = T.brands.slice().sort((a, b) => b.totals.revenue - a.totals.revenue);
  $('#tgBrands').innerHTML = brands.map(b => {
    const m = tgMetricas(b.totals), p = tgMetricas(b.prev_totals);
    return '<tr data-brand="' + esc(b.name) + '" aria-selected="' + String(b.name === S.tgBrand) + '">' +
      '<td><span class="cell-title">' + esc(b.name) + '</span>' +
        '<span class="cell-sub">' + b.videos + ' VSL' + (b.videos === 1 ? '' : 's') +
        ' &middot; <span style="color:var(--brand-2)">ver divisão por VSL</span></span></td>' +
      '<td class="r">' + fInt(b.totals.unique_views) + '</td>' +
      '<td class="r">' + fInt(b.totals.conversions) + '</td>' +
      '<td class="r">' + fMoney(m.rpv) + '</td>' +
      '<td class="r hot">' + fMoney(b.totals.revenue) + '</td>' +
      '<td class="r">' + tgChg(m.revenue, p.revenue) + '</td>' +
      '<td>' + tgSpark(b.days) + '</td></tr>';
  }).join('');
  $('#tgBrandNote').textContent = 'Clique num brand para ver como o tráfego dele se divide entre as VSLs. ' +
    'Brands que dividem a mesma VSL (ex.: B4 e B8) mostram o mesmo número; o total geral conta cada VSL uma vez só.';
}

/** Último dia completo do período: hoje ainda está em andamento. */
function tgUltimoDia(dias) {
  const hoje = hojeISO();
  for (let k = dias.length - 1; k >= 0; k--) if (dias[k].date !== hoje) return k;
  return dias.length - 1;
}

function renderTgVsls() {
  const T = S.tg;
  const b = S.tgBrand && T.brands.find(x => x.name === S.tgBrand);
  if (!b) {
    $('#tgVslTitle').textContent = 'VSLs do brand';
    $('#tgVslWrap').style.display = 'none';
    $('#tgVslSummary').innerHTML = '<div class="blank"><b>Escolha um brand</b>' +
      'Use o Recorte acima ou clique num brand na tabela "Por brand" para ver quanto do tráfego vai para cada VSL e quanto cada uma fatura.</div>';
    return;
  }
  $('#tgVslTitle').textContent = 'VSLs do ' + b.name;
  $('#tgVslWrap').style.display = '';

  const k = tgUltimoDia(b.days);
  const diaRef = b.days[k];
  $('#tgVslUltimo').textContent = diaRef ? 'Em ' + brDate(diaRef.date).slice(0, 5) : 'Último dia';

  const visitas = b.totals.unique_views || 0;
  const fat = b.totals.revenue || 0;
  const visitasDia = diaRef ? diaRef.unique_views : 0;
  const linhas = b.vsls.map(v => ({
    v,
    trafego: visitas ? (v.totals.unique_views / visitas) * 100 : 0,
    trafegoDia: visitasDia ? (((v.days[k] || {}).unique_views || 0) / visitasDia) * 100 : 0,
    fatia: fat ? (v.totals.revenue / fat) * 100 : 0,
    rpv: tgMetricas(v.totals).rpv
  })).sort((x, y) => y.trafego - x.trafego || y.fatia - x.fatia);

  const div = (T.divisao || {})[b.name] || { pesos: {}, meta: null };
  const ativa = !!T.divisao_ativa;
  linhas.forEach(l => { l.conf = div.pesos[l.v.id]; });
  if (linhas.some(l => l.conf !== undefined)) linhas.sort((x, y) => (y.conf || 0) - (x.conf || 0) || y.trafego - x.trafego);

  const lider = linhas[0];
  $('#tgVslSummary').innerHTML = lider && lider.v.totals.unique_views
    ? '<div class="note sev-info" style="margin-bottom:12px"><p style="font-size:13.5px;color:var(--ink-1)">' +
        '<b>' + esc(lider.v.name) + '</b>' +
        (lider.conf !== undefined ? ' está configurada com <b>' + fPct(lider.conf, 0) + '</b> e' : '') +
        ' trouxe <b style="color:var(--brand-2)">' + fMoney(lider.v.totals.revenue) +
        '</b>, que é ' + fPct(lider.fatia, 1) + ' do faturamento do brand.</p></div>'
    : '';

  const barra = (pct, cor) => '<span class="tg-bar"><span style="width:' + Math.min(100, pct).toFixed(1) + '%;background:' + cor + '"></span></span>';
  $('#tgVsls').innerHTML = linhas.map(l => {
    const vazio = !l.v.totals.unique_views;
    return '<tr' + (vazio ? ' class="tg-vazia"' : '') + ' title="' + esc(l.v.name) + '">' +
      '<td><span class="cell-title">' + esc(l.v.name) + '</span></td>' +
      '<td class="r"><input class="tg-pct" type="number" min="0" max="100" step="1" inputmode="decimal" placeholder="—"' +
        ' data-pid="' + esc(l.v.id) + '" value="' + (l.conf !== undefined ? l.conf : '') + '"' +
        (ativa ? '' : ' disabled') + ' aria-label="Porcentagem configurada"></td>' +
      '<td class="r">' + fPct(l.trafegoDia, 1) + '</td>' +
      '<td class="r">' + fInt(l.v.totals.unique_views) + '</td>' +
      '<td class="r">' + fInt(l.v.totals.conversions) + '</td>' +
      '<td class="tg-fatia"><b class="num" style="color:var(--brand-2)">' + fMoney(l.v.totals.revenue) + '</b>' +
        ' <span style="color:var(--ink-3)">' + fPct(l.fatia, 1) + '</span>' + barra(l.fatia, 'var(--brand-2)') + '</td>' +
      '<td class="r">' + fMoney(l.rpv) + '</td></tr>';
  }).join('') +
  '<tr class="tg-total"><td>Total do brand</td><td class="r"><span class="num" id="tgSomaCel">—</span></td>' +
    '<td class="r">100%</td>' +
    '<td class="r">' + fInt(visitas) + '</td><td class="r">' + fInt(b.totals.conversions) + '</td>' +
    '<td class="tg-fatia"><b class="num">' + fMoney(fat) + '</b></td><td class="r">' + fMoney(tgMetricas(b.totals).rpv) + '</td></tr>';

  $('#tgSaveBar').innerHTML = ativa
    ? '<button class="btn btn-primary btn-sm" data-act="save-divisao">Salvar divisão</button>' +
      '<span>Soma: <span class="tg-soma" id="tgSoma"></span></span>' +
      '<span>' + (div.meta ? 'Atualizado em ' + brDate(div.meta.em.slice(0, 10)) + ' ' + esc(div.meta.em.slice(11)) +
        (div.meta.por ? ' por ' + esc(div.meta.por) : '') : 'Ainda não preenchido para este brand.') + '</span>'
    : '<span>Para digitar a divisão configurada, conecte o banco de configurações (Upstash) ao projeto na Vercel.</span>';
  tgAtualizarSoma();
}

function tgAtualizarSoma() {
  const campos = $$('#tgVsls .tg-pct');
  const preenchidos = campos.filter(c => c.value !== '');
  const soma = preenchidos.reduce((t, c) => t + (Number(c.value) || 0), 0);
  const texto = preenchidos.length ? fPct(soma, 0) : '—';
  const cor = !preenchidos.length ? 'var(--ink-3)' : (Math.abs(soma - 100) < 0.5 ? 'var(--pos)' : 'var(--warn)');
  [$('#tgSoma'), $('#tgSomaCel')].forEach(el => { if (el) { el.textContent = texto; el.style.color = cor; } });
}

async function salvarDivisao() {
  const brand = S.tgBrand;
  if (!brand || !S.tg) return;
  const pesos = {};
  $$('#tgVsls .tg-pct').forEach(c => { if (c.value !== '') pesos[c.dataset.pid] = Number(c.value); });
  const botao = $('[data-act="save-divisao"]');
  if (botao) botao.disabled = true;
  try {
    const res = await fetch('/api/tg/divisao?route=tg-divisao', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ brand, pesos })
    });
    if (res.status === 401) { location.href = '/'; return; }
    const salvo = await lerJson(res, '/api/tg/divisao');
    S.tg.divisao = S.tg.divisao || {};
    S.tg.divisao[brand] = salvo;
    renderTgVsls();
    toast('Divisão salva.');
  } catch (err) {
    console.error(err);
    toast(err.message || 'Não deu para salvar.', 'err');
  } finally {
    if (botao) botao.disabled = false;
  }
}

function exportTgCsv() {
  if (!S.tg) return;
  const R = tgRecorte();
  const linhas = [['dia', 'visitas_unicas', 'plays_unicos', 'vendas', 'faturamento', 'receita_por_visita']];
  R.days.forEach(d => linhas.push([d.date, d.unique_views, d.unique_plays, d.conversions,
    d.revenue.toFixed(2).replace('.', ','), (d.unique_views ? d.revenue / d.unique_views : 0).toFixed(4).replace('.', ',')]));
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob(['﻿' + linhas.map(l => l.join(';')).join('\n')], { type: 'text/csv;charset=utf-8' }));
  a.download = 'tg-trafego-faturamento-' + S.tg.start + '_' + S.tg.end + '.csv';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

function wire() {
  $('#filterForm').addEventListener('submit', ev => { ev.preventDefault(); savePrefs(); loadData(); });
  $('#fAuto').addEventListener('change', () => { savePrefs(); syncBaselineFields(); });

  $('#presets').addEventListener('click', ev => {
    const b = ev.target.closest('button[data-range]');
    if (!b) return;
    const r = rangePreset(b.dataset.range);
    if (r) { setRange(r[0], r[1]); loadData(); }
  });

  $('#trendPicker').addEventListener('click', ev => {
    const b = ev.target.closest('button[data-metric]');
    if (!b) return;
    S.trendMetric = b.dataset.metric;
    $$('#trendPicker button').forEach(x => x.setAttribute('aria-pressed', String(x === b)));
    drawTrend();
  });

  $('#rankHead').addEventListener('click', ev => {
    const th = ev.target.closest('th[data-sort]');
    if (!th) return;
    const k = th.dataset.sort;
    if (S.sortKey === k) S.sortDir = S.sortDir === 'desc' ? 'asc' : 'desc';
    else { S.sortKey = k; S.sortDir = 'desc'; }
    renderRanking();
  });

  $('#search').addEventListener('input', debounce(filterCohorts, 160));
  $('#tgBrand').addEventListener('change', ev => { S.tgBrand = ev.target.value; renderTg(); });
  $('#tgVsls').addEventListener('input', ev => { if (ev.target.classList.contains('tg-pct')) tgAtualizarSoma(); });

  document.addEventListener('click', ev => {
    const acao = ev.target.closest('[data-act]');
    if (acao) {
      const a = acao.dataset.act;
      if (a === 'export-csv') exportCsv();
      if (a === 'close-sheet') closeSheet();
      if (a === 'export-tg') exportTgCsv();
      if (a === 'save-divisao') salvarDivisao();
      if (a === 'theme') toggleTheme();
      if (a === 'palette') openPalette();
      if (a === 'rail') document.body.classList.toggle('rail-open');
      return;
    }
    const linhaTg = ev.target.closest('#tgBrands tr[data-brand]');
    if (linhaTg) {
      S.tgBrand = S.tgBrand === linhaTg.dataset.brand ? '' : linhaTg.dataset.brand;
      renderTg();
      if (S.tgBrand) $('#tgVslTitle').scrollIntoView({ behavior: 'smooth', block: 'center' });
      return;
    }
    const abrir = ev.target.closest('[data-open]');
    if (abrir) { openSheet(abrir.dataset.open); return; }

    const nav = ev.target.closest('.nav a[data-view]');
    if (nav) { ev.preventDefault(); goView(nav.dataset.view); return; }

    if (ev.target === $('#scrim')) closeSheet();
    if (ev.target === $('#palette')) closePalette();

    const item = ev.target.closest('.palette-item');
    if (item) runPalette(Number(item.dataset.idx));
  });

  $('#paletteInput').addEventListener('input', ev => buildPalette(ev.target.value));
  $('#paletteInput').addEventListener('keydown', ev => {
    if (ev.key === 'ArrowDown') { ev.preventDefault(); movePalette(1); }
    else if (ev.key === 'ArrowUp') { ev.preventDefault(); movePalette(-1); }
    else if (ev.key === 'Enter') { ev.preventDefault(); runPalette(paletteIdx); }
  });

  document.addEventListener('keydown', ev => {
    const digitando = /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName);

    if ((ev.metaKey || ev.ctrlKey) && ev.key.toLowerCase() === 'k') {
      ev.preventDefault(); openPalette(); return;
    }
    if (ev.key === 'Escape') {
      if ($('#palette').classList.contains('on')) closePalette();
      else if ($('#scrim').classList.contains('on')) closeSheet();
      return;
    }
    if (digitando) return;

    const atalhos = { '1': 'v-overview', '2': 'v-creatives', '3': 'v-tg' };
    if (atalhos[ev.key]) { goView(atalhos[ev.key]); return; }
    if (ev.key === '/') { ev.preventDefault(); openPalette(); }
    if (ev.key.toLowerCase() === 't') toggleTheme();
  });

  window.addEventListener('hashchange', () => {
    const id = location.hash.replace('#', '');
    if (id && id !== S.view) goView(id, false);
  });
}

function boot() {
  restorePrefs();
  initPickers();
  wire();
  syncBaselineFields();
  markPreset($('#fStart').value, $('#fEnd').value);

  const inicial = location.hash.replace('#', '');
  if (inicial) goView(inicial, false);

  loadData();
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
else boot();
"""


# ==========================================================
# 10. PÁGINA DO PAINEL
# ==========================================================

def _br(iso_str):
    if not iso_str:
        return ""
    try:
        return datetime.strptime(iso_str, "%Y-%m-%d").strftime("%d/%m/%Y")
    except Exception:
        return iso_str


def pagina_painel(inicio, fim, base_inicio, base_fim, campanha, usuario, origem):
    nome = usuario.get("name") or "Time"
    email = usuario.get("email") or ""
    foto = usuario.get("picture") or ""

    avatar = (
        f'<img src="{foto}" alt="" referrerpolicy="no-referrer">'
        if foto else
        f'<span class="initials">{nome[:2].upper()}</span>'
    )

    faixa_atual = f"{_br(inicio)} a {_br(fim)}" if inicio and fim else ""
    faixa_base = f"{_br(base_inicio)} a {_br(base_fim)}" if base_inicio and base_fim else ""
    auto_marcado = "" if faixa_base else " checked"

    aviso = ""
    if SECRET_INSEGURO:
        aviso = (
            '<div class="banner">A chave de assinatura da sessão está no valor '
            "padrão. Defina <code>SESSION_SECRET</code> no ambiente antes de usar "
            "este painel em produção.</div>"
        )

    nav = "".join([
        _nav_link("overview", "Visão geral", "1", True),
        _nav_link("creatives", "Criativos", "2"),
        _nav_link("tg", "TG Brands", "3"),
    ])

    presets = "".join(
        f'<button type="button" data-range="{chave}" aria-pressed="false">{rotulo}</button>'
        for chave, rotulo in [
            ("hoje", "Hoje"), ("7", "7 dias"), ("14", "14 dias"),
            ("30", "30 dias"), ("mes", "Este mês"), ("mes-1", "Mês passado"),
        ]
    )

    return f"""<!DOCTYPE html>
<html lang="pt-BR" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="color-scheme" content="dark light">
<title>Painel VSL</title>
{_HEAD_ASSETS}
<script src="https://scripts.converteai.net/lib/js/smartplayer-wc/v4/sdk.js" async></script>
<style>{_TOKENS}{_CSS}</style>
</head>
<body>
<div class="shell">

<aside class="rail">
  <div class="rail-mark">
    <img src="/logo.png?v=4m" alt="" onerror="this.remove()">
  </div>
  <nav class="nav" aria-label="Seções do painel">
    <div class="nav-group-label">Painel</div>
    {nav}
  </nav>
  <div class="rail-foot">
    <button class="btn btn-ghost btn-sm" data-act="palette" style="justify-content:space-between">
      Buscar<span class="kbd">&#8984;K</span>
    </button>
    <div class="who">
      {avatar}
      <span class="who-text">
        <span class="who-name">{nome}</span>
        <span class="who-mail">{email}</span>
      </span>
    </div>
    <div class="rail-actions">
      <button class="btn btn-sm" id="themeBtn" data-act="theme">Claro</button>
      <a class="btn btn-sm btn-danger" href="{origem}/logout">Sair</a>
    </div>
  </div>
</aside>

<main class="stage">
  {aviso}
  <header class="masthead">
    <div class="masthead-inner">
      <button class="btn btn-ghost btn-sm rail-toggle" data-act="rail" aria-label="Abrir menu">&#9776;</button>
      <div>
        <h1>Desempenho das VSLs</h1>
        <div class="period" id="periodLabel">{faixa_atual}</div>
      </div>
      <div class="spacer"></div>
      <form class="filters" id="filterForm" autocomplete="off">
        <div class="presets" id="presets" role="group" aria-label="Períodos rápidos">{presets}</div>

        <div class="field">
          <label for="mainRange">Período</label>
          <input type="text" id="mainRange" value="{faixa_atual}" placeholder="Escolher datas" readonly>
          <input type="hidden" id="fStart" value="{inicio}">
          <input type="hidden" id="fEnd" value="{fim}">
        </div>

        <div class="field">
          <label for="baseRange">Comparar com</label>
          <input type="text" id="baseRange" value="{faixa_base}" placeholder="Escolher datas" readonly>
          <input type="hidden" id="fBaseStart" value="{base_inicio}">
          <input type="hidden" id="fBaseEnd" value="{base_fim}">
        </div>

        <div class="field">
          <label for="fCampaign">Campanha</label>
          <input type="text" id="fCampaign" value="{campanha}" placeholder="Todas">
        </div>

        <label class="switch" style="padding-bottom:9px">
          <input type="checkbox" id="fAuto"{auto_marcado}>
          <span class="track"></span>
          Base automática
        </label>

        <button type="submit" class="btn btn-primary" style="margin-bottom:1px">Atualizar</button>
      </form>
    </div>
  </header>

  <div class="wrap">
    {_VIEWS}
  </div>
</main>
</div>

{_OVERLAYS}

<script>const VTURB_HASH = {json.dumps(VTURB_ACCOUNT_HASH)};</script>
<script>{_JS}</script>
</body>
</html>"""


# ==========================================================
# 11. ROTEADOR HTTP
# ==========================================================

_RE_DATA = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _data_valida(valor, padrao):
    """Aceita só datas reais. O formato certo não basta: '2026-13-99' passa no
    regex e vira um erro obscuro lá na ponta da API."""
    if not valor or not _RE_DATA.match(valor):
        return padrao
    try:
        datetime.strptime(valor, "%Y-%m-%d")
    except ValueError:
        return padrao
    return valor


class handler(BaseHTTPRequestHandler):
    server_version = "PainelVSL"

    # ---------- utilidades de resposta ----------

    def _responder(self, codigo, corpo, tipo="text/html; charset=utf-8", cookies=None):
        if isinstance(corpo, str):
            corpo = corpo.encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(corpo)))
        self.send_header("Cache-Control", "no-store")
        for chave, valor in CABECALHOS_SEGURANCA:
            self.send_header(chave, valor)
        for cookie in (cookies or []):
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(corpo)

    def _json(self, codigo, dados, cookies=None):
        self._responder(
            codigo,
            json.dumps(dados, ensure_ascii=False),
            "application/json; charset=utf-8",
            cookies,
        )

    def _redirecionar(self, destino, cookies=None):
        self.send_response(302)
        self.send_header("Location", destino)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        for cookie in (cookies or []):
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _cookie(self, nome):
        bruto = self.headers.get("Cookie", "") or ""
        for pedaco in bruto.split(";"):
            if "=" in pedaco:
                chave, valor = pedaco.strip().split("=", 1)
                if chave == nome:
                    return valor
        return None

    def log_message(self, formato, *args):  # silencia o log padrão barulhento
        log.info("%s %s", self.address_string(), formato % args)

    # ---------- rotas ----------

    def do_POST(self):
        """Só a gravação da divisão de tráfego configurada usa POST."""
        rota = urlparse(self.path).path.rstrip("/").lower()
        params = parse_qs(urlparse(self.path).query)
        if not (rota.endswith("/api/tg/divisao") or params.get("route", [""])[0] == "tg-divisao"):
            return self._json(404, {"error": "Rota não encontrada."})
        try:
            return self._api_tg_divisao()
        except BrokenPipeError:
            return
        except Exception as exc:
            log.exception("erro ao salvar a divisão")
            return self._json(500, {"error": f"Erro interno ({type(exc).__name__})."})

    def _api_tg_divisao(self):
        sessao = self._sessao_ou_401()
        if not sessao:
            return
        # Defesa contra CSRF além do SameSite=Lax: a origem tem que ser o
        # próprio painel e o corpo tem que ser JSON.
        host = self.headers.get("Host", "")
        origem = self.headers.get("Origin", "")
        if origem and urlparse(origem).netloc != host:
            return self._json(403, {"error": "Origem não permitida."})
        if "application/json" not in (self.headers.get("Content-Type", "") or ""):
            return self._json(415, {"error": "Envie JSON."})
        tamanho = int(self.headers.get("Content-Length", 0) or 0)
        if tamanho > 20000:
            return self._json(413, {"error": "Requisição grande demais."})
        try:
            corpo = json.loads(self.rfile.read(tamanho).decode("utf-8") or "{}")
        except ValueError:
            return self._json(400, {"error": "JSON inválido."})

        try:
            salvo = salvar_divisao(
                str(corpo.get("brand", ""))[:200],
                corpo.get("pesos") if isinstance(corpo.get("pesos"), dict) else {},
                sessao.get("name") or sessao.get("email") or "",
            )
        except ValueError as exc:
            return self._json(400, {"error": str(exc)})
        except ErroArmazenamento as exc:
            return self._json(503, {"error": str(exc)})
        self._json(200, salvo, [montar_cookie(COOKIE_NAME, renovar_sessao(sessao), host)])

    def do_GET(self):
        alvo = urlparse(self.path)
        rota = alvo.path.rstrip("/").lower() or "/"
        params = parse_qs(alvo.query)

        host = self.headers.get("Host", "")
        local = "localhost" in host or "127.0.0.1" in host
        origem = f"{'http' if local else 'https'}://{host}"

        # Alguns deploys reescrevem o caminho antes de entregar à função, então
        # o front também marca a intenção na query. Sem isso, uma chamada de API
        # cai no bloco final e volta HTML — que o navegador tenta ler como JSON.
        quer_retencao = params.get("route", [""])[0] == "retention"
        quer_tg = params.get("route", [""])[0] == "tg"
        quer_dados = params.get("is_api", [""])[0] == "true"
        eh_api = quer_dados or quer_retencao or quer_tg or "/api/" in rota + "/"

        try:
            if rota == "/logo.png":
                return self._servir_logo()

            if rota.endswith("/logout"):
                return self._redirecionar(
                    f"{origem}/",
                    [montar_cookie(COOKIE_NAME, "", host, deletar=True)],
                )

            pendencias = configuracao_pendente()
            criticas = [p for p in pendencias if p[0] != "SESSION_SECRET"]
            if criticas:
                return self._responder(503, pagina_configuracao(pendencias))

            if "callback" in rota or "code" in params:
                return self._oauth_callback(params, host, origem)

            if quer_retencao or rota.endswith("/api/retention") or rota.endswith("/retention"):
                return self._api_retencao(params, host)

            if quer_tg or rota.endswith("/api/tg"):
                return self._api_tg(params, host)

            if quer_dados or rota.endswith("/api/data") or rota.endswith("/data"):
                return self._api_dados(params, host)

            if params.get("diag", [""])[0] == "players":
                return self._diag_players(params)

            if params.get("diag", [""])[0] == "1":
                return self._diagnostico(rota, params, host)

            return self._painel(params, host, origem)

        except BrokenPipeError:  # navegador desistiu no meio
            return
        except Exception as exc:
            log.exception("erro na rota %s", rota)
            # Uma rota de API nunca pode devolver HTML: o front só sabe ler JSON.
            if eh_api:
                return self._json(500, {"error": f"Erro interno ({type(exc).__name__})."})
            return self._responder(500, _casca(
                "Erro — Painel VSL",
                '<main class="gate"><h1>Algo quebrou no servidor</h1>'
                f"<p>{type(exc).__name__}. Recarregue a página; se continuar, "
                "confira os logs do deploy.</p></main>",
            ))

    # ---------- implementações ----------

    def _servir_logo(self):
        for caminho in ("logo.png", "public/logo.png", "static/logo.png"):
            if os.path.exists(caminho):
                with open(caminho, "rb") as arquivo:
                    dados = arquivo.read()
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(dados)))
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                self.wfile.write(dados)
                return
        self._responder(404, "", "text/plain; charset=utf-8")

    def _oauth_callback(self, params, host, origem):
        codigo = params.get("code", [None])[0]
        if not codigo:
            return self._responder(400, pagina_login(origem, "O Google não devolveu o código de acesso. Tente de novo."))

        try:
            token = HTTP.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "code": codigo,
                    "grant_type": "authorization_code",
                    "redirect_uri": f"{origem}/api/auth/callback",
                },
                timeout=12,
            )
            if token.status_code != 200:
                log.warning("troca de token falhou: %s", token.status_code)
                return self._responder(400, pagina_login(origem, "Não foi possível concluir o login. Tente novamente."))

            acesso = token.json().get("access_token")
            perfil = HTTP.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {acesso}"},
                timeout=12,
            )
            if perfil.status_code != 200:
                return self._responder(400, pagina_login(origem, "Não foi possível ler seu perfil no Google."))

            dados = perfil.json()
            email = (dados.get("email") or "").lower()
            if email not in EMAILS_AUTORIZADOS:
                return self._responder(403, pagina_negada(email, origem))

            sessao = criar_sessao(email, dados.get("name"), dados.get("picture"))
            return self._redirecionar(f"{origem}/", [montar_cookie(COOKIE_NAME, sessao, host)])

        except Exception:
            log.exception("callback do OAuth falhou")
            return self._responder(500, pagina_login(origem, "O login falhou por um erro interno. Tente novamente."))

    def _sessao_ou_401(self):
        sessao = validar_sessao(self._cookie(COOKIE_NAME))
        if not sessao:
            self._json(401, {"error": "unauthorized"})
            return None
        return sessao

    def _api_dados(self, params, host):
        sessao = self._sessao_ou_401()
        if not sessao:
            return

        hoje = datetime.now()
        inicio = _data_valida(params.get("start", [""])[0], f"{hoje.year}-01-01")
        fim = _data_valida(params.get("end", [""])[0], hoje.strftime("%Y-%m-%d"))
        base_inicio = _data_valida(params.get("comp_start", [""])[0], None)
        base_fim = _data_valida(params.get("comp_end", [""])[0], None)
        campanha = params.get("campanha", [""])[0][:120]

        comeco = time.time()
        try:
            atual, anterior = carregar_periodo(
                f"{inicio} 00:00:00", f"{fim} 23:59:59",
                f"{base_inicio} 00:00:00" if base_inicio else None,
                f"{base_fim} 23:59:59" if base_fim else None,
                campanha,
            )
        except ErroVTurb as exc:
            return self._json(502, {"error": str(exc)})

        self._json(200, {
            "estrutura": atual,
            "estrutura_anterior": anterior,
            "start": inicio, "end": fim,
            "prev_start": base_inicio, "prev_end": base_fim,
            "elapsed_ms": int((time.time() - comeco) * 1000),
        }, [montar_cookie(COOKIE_NAME, renovar_sessao(sessao), host)])

    def _api_retencao(self, params, host):
        sessao = self._sessao_ou_401()
        if not sessao:
            return

        hoje = datetime.now()
        inicio = _data_valida(params.get("start", [""])[0], f"{hoje.year}-01-01")
        fim = _data_valida(params.get("end", [""])[0], hoje.strftime("%Y-%m-%d"))
        filtro = params.get("filtro", [""])[0][:120]

        try:
            videos = carregar_retencao(f"{inicio} 00:00:00", f"{fim} 23:59:59", filtro)
        except ErroVTurb as exc:
            return self._json(502, {"error": str(exc)})

        self._json(200, {"videos": videos, "start": inicio, "end": fim},
                   [montar_cookie(COOKIE_NAME, renovar_sessao(sessao), host)])

    def _api_tg(self, params, host):
        sessao = self._sessao_ou_401()
        if not sessao:
            return

        hoje = datetime.now()
        inicio = _data_valida(params.get("start", [""])[0], (hoje - timedelta(days=6)).strftime("%Y-%m-%d"))
        fim = _data_valida(params.get("end", [""])[0], hoje.strftime("%Y-%m-%d"))
        if inicio > fim:
            inicio, fim = fim, inicio
        # Teto de 366 dias: a janela de comparação dobra o que vai para a API.
        if (datetime.strptime(fim, "%Y-%m-%d") - datetime.strptime(inicio, "%Y-%m-%d")).days > 365:
            return self._json(400, {"error": "Escolha um período de até 1 ano para a visão TG."})

        comeco = time.time()
        try:
            dados = carregar_tg(inicio, fim)
        except ErroVTurb as exc:
            return self._json(502, {"error": str(exc)})

        dados["divisao"], dados["divisao_ativa"] = ler_divisao()
        dados.update({"start": inicio, "end": fim, "elapsed_ms": int((time.time() - comeco) * 1000)})
        self._json(200, dados, [montar_cookie(COOKIE_NAME, renovar_sessao(sessao), host)])

    def _diagnostico(self, rota, params, host):
        """/?diag=1 — mostra como o servidor enxergou a requisição.
        Serve para descobrir se o deploy está reescrevendo o caminho."""
        sessao = self._sessao_ou_401()
        if not sessao:
            return
        try:
            total = len(listar_players())
            vturb = f"ok, {total} vídeos na conta"
        except ErroVTurb as exc:
            vturb = str(exc)
        except Exception as exc:
            vturb = f"falhou ({type(exc).__name__})"

        self._json(200, {
            "caminho_bruto": self.path,
            "caminho_normalizado": rota,
            "parametros": {k: v[0] for k, v in params.items()},
            "vturb": vturb,
            "token_configurado": bool(API_TOKEN),
            "segredo_de_sessao_padrao": SECRET_INSEGURO,
        })

    def _diag_players(self, params):
        """/?diag=players&q=TG — players crus da vTurb cujo nome contém q.
        Serve para descobrir como as variações dos testes A/B aparecem na
        API: nome, id e quais campos vêm em cada player."""
        if not self._sessao_ou_401():
            return
        termo = (params.get("q", [""])[0] or "")[:80].strip().lower()
        try:
            todos = listar_players()
        except ErroVTurb as exc:
            return self._json(502, {"error": str(exc)})
        achados = [p for p in todos if termo in (p.get("name", "") or "").lower()] if termo else todos
        campos = sorted({k for p in todos for k in p.keys()})
        self._json(200, {
            "total_na_conta": len(todos),
            "encontrados": len(achados),
            "campos_disponiveis": campos,
            "players": [
                {"id": p.get("id"), "name": p.get("name"), "created_at": p.get("created_at"),
                 "ab_test_detectado": _rotulo_teste_ab(p), "bruto": p}
                for p in achados[:300]
            ],
        })

    def _painel(self, params, host, origem):
        sessao = validar_sessao(self._cookie(COOKIE_NAME))
        if not sessao:
            return self._responder(200, pagina_login(origem))

        hoje = datetime.now()
        padrao_inicio = (hoje - timedelta(days=6)).strftime("%Y-%m-%d")
        inicio = _data_valida(params.get("start", [""])[0], padrao_inicio)
        fim = _data_valida(params.get("end", [""])[0], hoje.strftime("%Y-%m-%d"))
        base_inicio = _data_valida(params.get("comp_start", [""])[0], "") or ""
        base_fim = _data_valida(params.get("comp_end", [""])[0], "") or ""
        campanha = params.get("campanha", [""])[0][:120]

        pagina = pagina_painel(
            inicio, fim, base_inicio, base_fim, campanha,
            {"name": sessao.get("name"), "email": sessao.get("email"), "picture": sessao.get("picture")},
            origem,
        )
        self._responder(200, pagina, cookies=[montar_cookie(COOKIE_NAME, renovar_sessao(sessao), host)])