"""
main.py — главный пайплайн (10 шагов, запускается каждый час).

 1. Поиск новых источников на GitHub (раз в сутки)
 2. Сбор конфигов из GitHub + Telegram
 3. Дедупликация
 4. Тест серверов (TCP + TLS, 80 параллельно)
 5. Обновление истории надёжности
 6. Геолокация серверов
 7. Запись файлов (VLESS_WORKING, RU_BYPASS, по протоколам, TOP50)
 8. HTML-дашборд
 9. Яндекс Диск (REST API с прямыми ссылками)
10. Telegram-уведомление
"""
import asyncio
import base64
import json as _json
import logging
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

import config as cfg
from collector        import collect_all
from tg_scraper       import collect_from_telegram
from tester           import batch_test
from geoip            import geolocate_hosts
from writer           import write_all_outputs
from html_gen         import generate_html
from yandex_upload    import upload_all
from tg_notify        import send_report, send_error
from history          import update as history_update, get_scores_bulk, prune_old
from source_discovery import discover_new_sources

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("main")

DISCOVERY_MARKER = Path(__file__).parent.parent / "output" / ".last_discovery"


def _should_discover() -> bool:
    if not DISCOVERY_MARKER.exists(): return True
    try:    return (time.time() - float(DISCOVERY_MARKER.read_text())) > 86400
    except: return True


def _mark_discovery():
    DISCOVERY_MARKER.parent.mkdir(parents=True, exist_ok=True)
    DISCOVERY_MARKER.write_text(str(time.time()))


def _parse(config_str: str):
    """Вытаскивает (host, port, sni) из конфига."""
    try:
        if config_str.lower().startswith("vmess://"):
            b64  = config_str[8:].split("#")[0].split("?")[0]
            b64 += "=" * (-len(b64) % 4)
            data = _json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
            h, p = str(data.get("add","")), int(data.get("port",0))
            return (h, p, data.get("sni") or None) if h and p else None
        else:
            parsed = urlparse(config_str)
            h, p   = parsed.hostname or "", parsed.port or 0
            sni    = (parse_qs(parsed.query).get("sni") or parse_qs(parsed.query).get("peer") or [None])[0]
            return (h, p, sni) if h and p else None
    except Exception:
        return None


async def main():
    t_start = time.monotonic()
    log.info("=" * 62)
    log.info("🚀 VLESS Collector  %s", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    log.info("=" * 62)

    try:
        # ── 1. Поиск новых источников (раз в сутки) ───────────────────────────
        if _should_discover():
            log.info("🔍 ШАГ 1/10 — Ищу новые источники на GitHub…")
            try:
                new = await discover_new_sources(max_new=10)
                log.info("   Найдено новых: %d", len(new))
                _mark_discovery()
            except Exception as e:
                log.warning("   Поиск источников: %s", e)
        else:
            log.info("🔍 ШАГ 1/10 — Пропущен (следующий через <24ч)")

        # ── 2. Сбор конфигов ──────────────────────────────────────────────────
        log.info("📥 ШАГ 2/10 — Сбор конфигов…")
        github_cfgs, ru_keys = await collect_all()
        tg_cfgs              = await collect_from_telegram()
        all_raw              = github_cfgs + tg_cfgs
        log.info("   Найдено: %d  RU-ключи: %d", len(all_raw), len(ru_keys))

        # ── 3. Дедупликация ───────────────────────────────────────────────────
        log.info("🧹 ШАГ 3/10 — Дедупликация…")
        seen, unique = set(), []
        for c in all_raw:
            k = c.split("#")[0].rstrip("?& ")
            if k not in seen: seen.add(k); unique.append(c)
        log.info("   Уникальных: %d  (дублей убрано: %d)", len(unique), len(all_raw)-len(unique))

        if not unique:
            raise RuntimeError("Нет конфигов — все источники недоступны?")

        # ── 4. Тест серверов (TCP + TLS) ─────────────────────────────────────
        log.info("🔍 ШАГ 4/10 — Тестирование %d конфигов…", len(unique))
        targets: list  = []
        cfg_by_hp: dict = {}
        for c in unique:
            t = _parse(c)
            if t:
                targets.append(t)
                cfg_by_hp.setdefault((t[0], t[1]), []).append(c)
        log.info("   Уникальных адресов: %d", len(targets))

        test_results = await batch_test(targets, max_workers=cfg.MAX_WORKERS)

        working:          list  = []
        tls_map:          dict  = {}
        all_tested_hosts: set   = set()
        working_hosts:    set   = set()
        seen_f:           set   = set()

        for r in sorted(test_results, key=lambda x: x.get("tcp_ms") or 9999):
            host, port = r["host"], r["port"]
            all_tested_hosts.add(host)
            if not r["alive"] or (r.get("tcp_ms") or 9999) > cfg.MAX_LATENCY:
                continue
            working_hosts.add(host)
            tls_map[host] = r.get("tls_ok", False)
            for c in cfg_by_hp.get((host, port), []):
                k = c.split("#")[0].rstrip("?& ")
                if k not in seen_f:
                    seen_f.add(k); working.append((c, r["tcp_ms"]))

        log.info("   ✅ Рабочих: %d из %d", len(working), len(targets))
        if not working:
            raise RuntimeError("Ни один сервер не прошёл проверку")

        # ── 5. История надёжности ─────────────────────────────────────────────
        log.info("📝 ШАГ 5/10 — Обновляем историю…")
        prune_old(days=cfg.HISTORY_PRUNE_DAYS)
        history_update(working_hosts, all_tested_hosts)
        score_map      = get_scores_bulk(list(working_hosts))
        reliable_count = sum(1 for s in score_map.values() if s >= cfg.RELIABILITY_MIN)
        new_count      = sum(1 for s in score_map.values() if s < 0)
        log.info("   Надёжных: %d  Новых: %d", reliable_count, new_count)

        # ── 6. Геолокация ─────────────────────────────────────────────────────
        log.info("🌍 ШАГ 6/10 — Геолокация серверов…")
        hosts   = list({urlparse(c).hostname or "" for c, _ in working if urlparse(c).hostname})
        geo_map = await geolocate_hosts(hosts)

        # ── 7. Запись файлов ──────────────────────────────────────────────────
        log.info("💾 ШАГ 7/10 — Записываем файлы…")
        stats = write_all_outputs(
            working, geo_map=geo_map, tls_map=tls_map,
            score_map=score_map, ru_keys=ru_keys,
        )
        ru_total = stats["by_protocol"].get("ru_bypass", 0)
        log.info("   🇷🇺 RU_BYPASS.txt: %d серверов", ru_total)

        # ── 8. HTML-дашборд ───────────────────────────────────────────────────
        log.info("🌐 ШАГ 8/10 — HTML-дашборд…")
        generate_html(stats)

        # ── 9. Яндекс Диск ────────────────────────────────────────────────────
        yd_result = None
        if cfg.YANDEX_TOKEN or (cfg.YANDEX_LOGIN and cfg.YANDEX_PASS):
            log.info("☁️  ШАГ 9/10 — Яндекс Диск…")
            try:
                yd_result = await upload_all(
                    token=cfg.YANDEX_TOKEN,
                    login=cfg.YANDEX_LOGIN,
                    password=cfg.YANDEX_PASS,
                    raw_base=cfg.RAW_BASE,
                )
            except Exception as e:
                log.warning("   Яндекс Диск: %s", e)
        else:
            log.info("☁️  ШАГ 9/10 — Пропущен (нет YANDEX_TOKEN)")

        # ── 10. Telegram ──────────────────────────────────────────────────────
        elapsed = int(time.monotonic() - t_start)
        if cfg.TG_BOT_TOKEN and cfg.TG_CHAT_ID:
            log.info("📨 ШАГ 10/10 — Telegram…")
            try: await send_report(stats, yd_result=yd_result, elapsed_sec=elapsed)
            except Exception as e: log.warning("   Telegram: %s", e)
        else:
            log.info("📨 ШАГ 10/10 — Пропущен (нет TG_BOT_TOKEN)")

        # ── Итог ──────────────────────────────────────────────────────────────
        log.info("=" * 62)
        log.info("🏁 ГОТОВО  %dс | серверов: %d | RU: %d | TLS: %d | надёжных: %d",
                 elapsed, stats["total_working"], ru_total,
                 stats["tls_confirmed"], reliable_count)
        log.info("=" * 62)

    except Exception as e:
        err = traceback.format_exc()
        log.error("💥 Критическая ошибка:\n%s", err)
        if cfg.TG_BOT_TOKEN and cfg.TG_CHAT_ID:
            try: await send_error(err)
            except Exception: pass
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
