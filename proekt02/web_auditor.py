import datetime
import http.server
import json
import socketserver
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

HOST = "0.0.0.0"
PORT = 5050

# Отключаем строгую проверку SSL-сертификатов для возможности аудита тестовых и самоподписанных сайтов
SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE

HEADERS_TO_CHECK = {
    "Content-Security-Policy": {
        "severity": "HIGH",
        "desc": (
            "Защищает от атак межсайтового скриптинга (XSS) и внедрения данных."
        ),
        "fix": "Настройте директиву Content-Security-Policy: default-src 'self'",
    },
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "desc": (
            "Принудительно переводит браузер на зашифрованное соединение HTTPS"
            " (HSTS)."
        ),
        "fix": (
            "Добавьте: Strict-Transport-Security: max-age=31536000;"
            " includeSubDomains"
        ),
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "desc": "Защищает сайт от атак с подделкой клика (Clickjacking).",
        "fix": "Добавьте заголовок: X-Frame-Options: SAMEORIGIN или DENY",
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "desc": "Предотвращает подмену MIME-типов браузером (MIME Sniffing).",
        "fix": "Добавьте заголовок: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "desc": "Контролирует передачу конфиденциального URL в заголовке Referer.",
        "fix": "Установите: Referrer-Policy: strict-origin-when-cross-origin",
    },
}

SENSITIVE_PATHS = [
    (
        "/.env",
        "CRITICAL",
        "Файл окружения содержит ключи API, токены и пароли от баз данных.",
    ),
    (
        "/.git/HEAD",
        "HIGH",
        "Раскрытие исходного кода приложения через открытый репозиторий Git.",
    ),
    (
        "/backup.sql",
        "CRITICAL",
        "Дамп базы данных в публичном веб-доступе.",
    ),
    (
        "/robots.txt",
        "INFO",
        "Служебный файл для поисковых ботов (может раскрывать скрытые пути).",
    ),
]


def audit_website(target_url):
  """Проводит комплексный аудит безопасности переданного URL-адреса."""
  if not target_url.startswith(("http://", "https://")):
    target_url = "https://" + target_url

  parsed_url = urllib.parse.urlparse(target_url)
  base_origin = f"{parsed_url.scheme}://{parsed_url.netloc}"

  results = {
      "target": target_url,
      "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
      "status": "SUCCESS",
      "score": 100,
      "grade": "A+",
      "findings": [],
  }

  req_headers = {
      "User-Agent": (
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberSecAuditor/2.0"
      )
  }

  # 1. Запрос к главной странице и анализ заголовков
  try:
    req = urllib.request.Request(
        target_url, headers=req_headers, method="GET"
    )
    with urllib.request.urlopen(
        req, timeout=7, context=SSL_CONTEXT
    ) as response:
      resp_headers = dict(response.info())
      resp_cookies = response.headers.get_all("Set-Cookie") or []
  except Exception as e:
    return {
        "target": target_url,
        "status": "ERROR",
        "error_message": f"Не удалось подключиться к целевому хосту: {str(e)}",
    }

  # Проверка Security Headers
  for h_name, h_info in HEADERS_TO_CHECK.items():
    matched = any(h_name.lower() == k.lower() for k in resp_headers.keys())
    if matched:
      results["findings"].append({
          "title": f"Заголовок {h_name} включен",
          "severity": "PASS",
          "desc": h_info["desc"],
          "remediation": "Конфигурация соответствует нормам.",
      })
    else:
      deduct = 15 if h_info["severity"] == "HIGH" else 8
      results["score"] -= deduct
      results["findings"].append({
          "title": f"Отсутствует заголовок {h_name}",
          "severity": h_info["severity"],
          "desc": h_info["desc"],
          "remediation": h_info["fix"],
      })

  # Проверка утечки версий сервера
  for leak_hdr in ["Server", "X-Powered-By"]:
    for k, v in resp_headers.items():
      if k.lower() == leak_hdr.lower():
        results["score"] -= 5
        results["findings"].append({
            "title": f"Раскрытие версии ПО через заголовок {k}",
            "severity": "LOW",
            "desc": (
                f"Сервер раскрывает используемый стек технологий: '{v}'. Это"
                " облегчает злоумышленнику подбор готовых эксплойтов."
            ),
            "remediation": (
                "Отключите показ баннера в настройках сервера (например,"
                " 'server_tokens off;' в Nginx)."
            ),
        })

  # Проверка безопасности Cookie
  for c_str in resp_cookies:
    c_lower = c_str.lower()
    cookie_name = c_str.split("=")[0].strip()
    if "httponly" not in c_lower:
      results["score"] -= 8
      results["findings"].append({
          "title": f"Cookie '{cookie_name}' не защищен флагом HttpOnly",
          "severity": "MEDIUM",
          "desc": (
              "Скрипты JavaScript имеют доступ к чтению cookie (угроза хищения"
              " сессии при XSS)."
          ),
          "remediation": "Добавьте флаг HttpOnly при установке Set-Cookie.",
      })
    if "secure" not in c_lower:
      results["score"] -= 8
      results["findings"].append({
          "title": f"Cookie '{cookie_name}' не имеет флага Secure",
          "severity": "MEDIUM",
          "desc": (
              "Cookie может быть перехвачен в открытом виде при передаче по"
              " незащищенному HTTP."
          ),
          "remediation": "Добавьте директиву Secure для отправки только по TLS.",
      })

  # 2. Проверка утечки служебных путей
  for path, severity, desc in SENSITIVE_PATHS:
    test_url = base_origin + path
    try:
      probe = urllib.request.Request(
          test_url, headers=req_headers, method="GET"
      )
      with urllib.request.urlopen(
          probe, timeout=4, context=SSL_CONTEXT
      ) as p_res:
        if p_res.status == 200:
          if path == "/robots.txt":
            results["findings"].append({
                "title": f"Обнаружен файл {path}",
                "severity": "INFO",
                "desc": desc,
                "remediation": (
                    "Проверьте, не содержит ли robots.txt пути к приватным"
                    " админ-панелям."
                ),
            })
          else:
            results["score"] -= 25
            results["findings"].append({
                "title": f"КРИТИЧЕСКАЯ УТЕЧКА: Доступен файл {path}",
                "severity": severity,
                "desc": desc,
                "remediation": (
                    f"Запретите публичный доступ к {path} в конфигурации"
                    " веб-сервера."
                ),
            })
    except Exception:
      pass  # 404/403 означает, что файл недоступен извне (корректная защита)

  # Нормализация рейтинга
  results["score"] = max(5, min(100, results["score"]))
  if results["score"] >= 90:
    results["grade"] = "A+"
  elif results["score"] >= 80:
    results["grade"] = "A"
  elif results["score"] >= 65:
    results["grade"] = "B"
  elif results["score"] >= 50:
    results["grade"] = "C"
  else:
    results["grade"] = "F"

  return results


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecAudit // OWASP Web Vulnerability Scanner</title>
<style>
  :root {
    --bg: #090d16;
    --card: #111827;
    --accent: #00f0ff;
    --danger: #ff2a5f;
    --warn: #ffb703;
    --success: #00f59b;
    --info: #38bdf8;
    --border: #1e293b;
    --text: #f1f5f9;
    --muted: #94a3b8;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; padding: 25px; }
  .container { max-width: 1050px; margin: 0 auto; }
  
  header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--border); padding-bottom: 20px; margin-bottom: 25px; }
  .title-group h1 { margin: 0; font-size: 24px; color: var(--accent); letter-spacing: 0.5px; }
  .title-group p { margin: 5px 0 0; font-size: 13px; color: var(--muted); }

  .scan-box { display: flex; gap: 10px; background: var(--card); border: 1px solid var(--border); padding: 15px; border-radius: 8px; margin-bottom: 25px; }
  .scan-box input { flex: 1; background: #050811; border: 1px solid var(--border); color: var(--text); padding: 12px 16px; border-radius: 6px; font-size: 14px; font-family: inherit; }
  .scan-box input:focus { outline: none; border-color: var(--accent); }
  .scan-box button { background: var(--accent); color: #000; font-weight: bold; border: none; padding: 0 25px; border-radius: 6px; cursor: pointer; transition: 0.2s; font-size: 14px; }
  .scan-box button:hover { opacity: 0.9; transform: translateY(-1px); }

  .score-card { display: grid; grid-template-columns: 200px 1fr; gap: 20px; background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 25px; margin-bottom: 25px; align-items: center; }
  .score-dial { text-align: center; border-right: 1px solid var(--border); padding-right: 20px; }
  .grade { font-size: 64px; font-weight: 900; line-height: 1; }
  .score-num { font-size: 14px; color: var(--muted); margin-top: 5px; }
  
  .grade-A { color: var(--success); }
  .grade-B { color: var(--info); }
  .grade-C { color: var(--warn); }
  .grade-F { color: var(--danger); }

  .summary-stats { display: flex; gap: 15px; }
  .stat-item { flex: 1; background: #050811; border: 1px solid var(--border); padding: 15px; border-radius: 6px; }
  .stat-label { font-size: 11px; color: var(--muted); text-transform: uppercase; }
  .stat-val { font-size: 22px; font-weight: bold; margin-top: 5px; }

  .findings-container { display: flex; flex-direction: column; gap: 12px; }
  .finding-card { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 18px; border-left: 4px solid var(--border); }
  .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .finding-title { font-size: 15px; font-weight: 600; }
  
  .badge { font-size: 11px; font-weight: bold; padding: 4px 10px; border-radius: 4px; text-transform: uppercase; }
  .badge-CRITICAL { background: rgba(255, 42, 95, 0.2); color: var(--danger); }
  .badge-HIGH { background: rgba(255, 42, 95, 0.15); color: var(--danger); }
  .badge-MEDIUM { background: rgba(255, 183, 3, 0.15); color: var(--warn); }
  .badge-LOW { background: rgba(56, 189, 248, 0.15); color: var(--info); }
  .badge-INFO { background: rgba(148, 163, 184, 0.15); color: var(--muted); }
  .badge-PASS { background: rgba(0, 245, 155, 0.15); color: var(--success); }

  .finding-desc { font-size: 13px; color: #cbd5e1; margin-bottom: 10px; line-height: 1.4; }
  .finding-fix { font-size: 12px; background: #050811; padding: 10px; border-radius: 4px; border: 1px solid #1f293d; color: var(--accent); font-family: monospace; }
  
  .print-btn { background: #1e293b; color: #fff; border: 1px solid #334155; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; }
  .print-btn:hover { background: #334155; }
  #loader { display: none; text-align: center; padding: 40px; color: var(--accent); font-family: monospace; }
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="title-group">
      <h1>🛡️ WEB SECURITY AUDITOR // OWASP TOP 10</h1>
      <p>Автоматизированный аудит заголовков безопасности, утечек данных и векторов атак</p>
    </div>
    <button class="print-btn" onclick="window.print()">Сохранить отчёт (PDF)</button>
  </header>

  <div class="scan-box">
    <input type="text" id="targetInput" placeholder="Введите целевой сайт (например, https://example.com или 192.168.2.112)" value="https://example.com">
    <button id="scanBtn" onclick="runScan()">Начать аудит</button>
  </div>

  <div id="loader">⚡ ВЫПОЛНЯЕТСЯ ПРОВЕРКА ЦЕЛЕВОГО СЕРВЕРА И АНАЛИЗ ЗАЩИТЫ...</div>

  <div id="reportArea" style="display: none;">
    <div class="score-card">
      <div class="score-dial">
        <div id="gradeElem" class="grade grade-A">A+</div>
        <div id="scoreElem" class="score-num">95 / 100 PTS</div>
      </div>
      <div>
        <div style="font-size: 18px; font-weight: bold; margin-bottom: 5px;" id="targetDisplay"></div>
        <div style="font-size: 12px; color: var(--muted); margin-bottom: 15px;" id="timeDisplay"></div>
        <div class="summary-stats">
          <div class="stat-item">
            <div class="stat-label">Критических угроз</div>
            <div id="statCrit" class="stat-val" style="color:var(--danger)">0</div>
          </div>
          <div class="stat-item">
            <div class="stat-label">Предупреждений</div>
            <div id="statWarn" class="stat-val" style="color:var(--warn)">0</div>
          </div>
          <div class="stat-item">
            <div class="stat-label">Пройденных проверок</div>
            <div id="statPass" class="stat-val" style="color:var(--success)">0</div>
          </div>
        </div>
      </div>
    </div>

    <h3 style="margin-bottom: 15px; color: var(--muted);">ДЕТАЛЬНЫЙ ПРОТОКОЛ АУДИТА БЕЗОПАСНОСТИ</h3>
    <div id="findingsList" class="findings-container"></div>
  </div>
</div>

<script>
async function runScan() {
  const target = document.getElementById('targetInput').value.trim();
  if (!target) return;

  const btn = document.getElementById('scanBtn');
  const loader = document.getElementById('loader');
  const reportArea = document.getElementById('reportArea');

  btn.disabled = true;
  loader.style.display = 'block';
  reportArea.style.display = 'none';

  try {
    const res = await fetch('/api/scan?url=' + encodeURIComponent(target));
    const data = await res.json();
    loader.style.display = 'none';
    btn.disabled = false;

    if (data.status === 'ERROR') {
      alert(data.error_message);
      return;
    }

    reportArea.style.display = 'block';
    document.getElementById('targetDisplay').innerText = 'Целевой узел: ' + data.target;
    document.getElementById('timeDisplay').innerText = 'Время проверки: ' + data.scan_time;

    const gradeElem = document.getElementById('gradeElem');
    gradeElem.innerText = data.grade;
    gradeElem.className = 'grade grade-' + (data.grade[0] === 'A' ? 'A' : data.grade[0]);
    document.getElementById('scoreElem').innerText = data.score + ' / 100 PTS';

    let crit = 0, warn = 0, pass = 0;
    const list = document.getElementById('findingsList');
    list.innerHTML = '';

    data.findings.forEach(f => {
      if (f.severity === 'CRITICAL' || f.severity === 'HIGH') crit++;
      else if (f.severity === 'MEDIUM' || f.severity === 'LOW') warn++;
      else if (f.severity === 'PASS') pass++;

      const borderCol = f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'var(--danger)' : 
                       (f.severity === 'MEDIUM' || f.severity === 'LOW' ? 'var(--warn)' : 
                       (f.severity === 'PASS' ? 'var(--success)' : 'var(--muted)'));

      list.innerHTML += `
        <div class="finding-card" style="border-left-color: ${borderCol};">
          <div class="finding-header">
            <span class="finding-title">${f.title}</span>
            <span class="badge badge-${f.severity}">${f.severity}</span>
          </div>
          <div class="finding-desc">${f.desc}</div>
          <div class="finding-fix"><b>Рекомендация по устранению:</b> ${f.remediation}</div>
        </div>
      `;
    });

    document.getElementById('statCrit').innerText = crit;
    document.getElementById('statWarn').innerText = warn;
    document.getElementById('statPass').innerText = pass;

  } catch(e) {
    loader.style.display = 'none';
    btn.disabled = false;
    alert('Сбой выполнения запроса к сканеру.');
  }
}
</script>
</body>
</html>
"""


class ScannerServer(http.server.SimpleHTTPRequestHandler):

  def do_GET(self):
    parsed = urllib.parse.urlparse(self.path)

    # API конечная точка сканирования
    if parsed.path == "/api/scan":
      params = urllib.parse.parse_qs(parsed.query)
      target = params.get("url", [""])[0]

      if not target:
        self.send_response(400)
        self.end_headers()
        return

      scan_data = audit_website(target)

      self.send_response(200)
      self.send_header("Content-Type", "application/json; charset=utf-8")
      self.end_headers()
      self.wfile.write(json.dumps(scan_data, ensure_ascii=False).encode())

    # Главная страница дашборда
    else:
      self.send_response(200)
      self.send_header("Content-Type", "text/html; charset=utf-8")
      self.end_headers()
      self.wfile.write(DASHBOARD_HTML.encode("utf-8"))

  def log_message(self, format, *args):
    return  # Отключение лишнего консольного вывода


if __name__ == "__main__":
  print("\033[92m" + "=" * 65)
  print(" [*] Web Security Auditor & OWASP Scanner запущен")
  print(f" [*] Откройте в браузере: http://localhost:{PORT}")
  print("=" * 65 + "\033[0m")

  with socketserver.TCPServer((HOST, PORT), ScannerServer) as server:
    try:
      server.serve_forever()
    except KeyboardInterrupt:
      print("\n[*] Сканер остановлен.")