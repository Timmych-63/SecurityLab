import html
import json
from pathlib import Path
from .storage import atomic_text

def report(store, rid, output: Path):
    body = {'schema_version': 1, 'run': store.get(rid), 'finding': store.finding(rid),
            'evidence': store.evidence(rid), 'history': store.history(rid),
            'limitations': ['Scripted demo without AI', 'Only synthetic fixture evaluated',
                            'Docker, Hermes, GPU and Windows integration not verified']}
    output.mkdir(parents=True, exist_ok=True)
    atomic_text(output / 'report.json', json.dumps(body, ensure_ascii=False, indent=2))
    finding = body['finding'] or {}
    esc = lambda v: html.escape(str(v), quote=True)
    rows = ''.join('<tr><td>' + esc(k) + '</td><td>' + esc(v) + '</td></tr>' for k,v in finding.items())
    proofs = ''.join('<details open><summary>' + esc(k) + '</summary><pre>' +
                    esc(json.dumps(v, ensure_ascii=False, indent=2)) + '</pre></details>' for k,v in body['evidence'].items())
    page = '''<!doctype html><html lang="ru"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>SecurityLab — отчёт учебного прогона</title>
<style>body{max-width:1050px;margin:40px auto;padding:0 24px;font:16px/1.6 system-ui;color:#17202b;background:#fafaf7}h1{line-height:1.2}table{border-collapse:collapse;width:100%}td{padding:8px;border-bottom:1px solid #ccd2d8;vertical-align:top}td:first-child{width:210px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#edf0f1;padding:16px;font-size:13px}summary{cursor:pointer;font-weight:600;margin-top:20px}.notice{border-left:4px solid #b75e13;padding:12px;background:#fff3dc}</style>
<h1>SecurityLab</h1><p class="notice">Учебный прогон без AI. Результат относится только к синтетическому сервису, а не к безопасности вашего проекта.</p>'''
    page += '<p>Прогон: ' + esc(rid) + ' · ' + esc(body['run']['status']) + '</p>'
    page += '<h2>Находки: ' + str(bool(finding) * 1) + '</h2><table>' + rows + '</table><h2>Доказательства и исправление</h2>' + proofs
    page += '<h2>История</h2><pre>' + esc(json.dumps(body['history'], ensure_ascii=False, indent=2)) + '</pre></html>'
    atomic_text(output / 'report.html', page)
    store.export_events(rid, output / 'events.jsonl')
    return output / 'report.html'
