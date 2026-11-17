# ==============================================================================
# 1. ПОДКЛЮЧЕНИЕ БИБЛИОТЕК
# ==============================================================================
import hashlib  # Библиотека криптографических хэш-функций (MD5, SHA-256, PBKDF2)
import http.server  # Встроенный HTTP-сервер для раздачи интерфейса и API
import json  # Формат передачи данных между Python и браузером
import os  # Работа с путями и генерация случайной криптографической «соли»
import socket  # Определение локального IP-адреса в Wi-Fi / LAN сети
import socketserver  # Сетевой TCP-сервер
import threading  # Многопоточность для автооткрытия браузера
import time  # Точный таймер для замера скорости хэширования (H/s)
import urllib.parse  # Разбор параметров URL-запросов
import webbrowser  # Автоматический запуск браузера

PORT = 8000
HOST = "0.0.0.0"


class ReuseAddressTCPServer(socketserver.TCPServer):
  # Разрешаем мгновенно занимать порт 8000 при перезапуске скрипта
  allow_reuse_address = True


# ==============================================================================
# 2. РЕАЛЬНЫЙ ТЕСТ ПРОИЗВОДИТЕЛЬНОСТИ ПРОЦЕССОРА (BENCHMARK)
# ==============================================================================
def run_cpu_benchmark():
  """Замеряет реальную скорость вычисления хэшей на текущем ПК (хэшей в секунду)."""
  test_data = b"benchmark_password_2026"
  duration = 0.25  # Длительность замера для каждого алгоритма (250 мс)

  # 1. Замер скорости MD5
  count_md5 = 0
  start = time.perf_counter()
  while time.perf_counter() - start < duration:
    hashlib.md5(test_data).hexdigest()
    count_md5 += 1
  md5_speed = int(count_md5 / duration)

  # 2. Замер скорости SHA-256
  count_sha = 0
  start = time.perf_counter()
  while time.perf_counter() - start < duration:
    hashlib.sha256(test_data).hexdigest()
    count_sha += 1
  sha256_speed = int(count_sha / duration)

  # 3. Замер скорости PBKDF2 (100 000 итераций — стандарт защиты паролей)
  salt = b"static_bench_salt"
  start = time.perf_counter()
  hashlib.pbkdf2_hmac("sha256", test_data, salt, 100_000)
  pbkdf2_time = time.perf_counter() - start
  pbkdf2_speed = max(1, int(1.0 / pbkdf2_time))

  return {
      "md5_hps": md5_speed,
      "sha256_hps": sha256_speed,
      "pbkdf2_hps": pbkdf2_speed,
  }


# Выполняем замер один раз при старте сервера
CPU_BENCHMARK = run_cpu_benchmark()


def get_local_ip():
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip
  except Exception:
    return "127.0.0.1"


# ==============================================================================
# 3. ОБРАБОТЧИК HTTP-ЗАПРОСОВ И КРИПТОГРАФИЧЕСКОГО API
# ==============================================================================
class CrackerLabHandler(http.server.SimpleHTTPRequestHandler):

  def do_GET(self):
    parsed = urllib.parse.urlparse(self.path)

    # API 1: Отдаёт реальные показатели скорости текущего процессора
    if parsed.path == "/api/benchmark":
      self.send_json(CPU_BENCHMARK)

    # API 2: Вычисляет реальные криптографические хэши для введённого пароля
    elif parsed.path == "/api/hash":
      params = urllib.parse.parse_qs(parsed.query)
      pwd = params.get("pwd", [""])[0]
      pwd_bytes = pwd.encode("utf-8")

      # Генерируем случайную 8-байтную соль для PBKDF2
      salt = os.urandom(8).hex()
      pbkdf2_hash = hashlib.pbkdf2_hmac(
          "sha256", pwd_bytes, salt.encode(), 100_000
      ).hex()

      self.send_json({
          "md5": hashlib.md5(pwd_bytes).hexdigest(),
          "sha256": hashlib.sha256(pwd_bytes).hexdigest(),
          "pbkdf2": f"pbkdf2:sha256:100000${salt}${pbkdf2_hash[:32]}...",
      })

    # В остальных случаях отдаём веб-интерфейс index.html
    else:
      super().do_GET()

  def send_json(self, payload):
    self.send_response(200)
    self.send_header("Content-Type", "application/json; charset=utf-8")
    self.end_headers()
    self.wfile.write(json.dumps(payload).encode("utf-8"))

  def log_message(self, format, *args):
    # Отключаем лишний спам HTTP-логов в терминале
    return


def open_browser():
  webbrowser.open(f"http://localhost:{PORT}")


if __name__ == "__main__":
  os.chdir(os.path.dirname(os.path.abspath(__file__)))
  local_ip = get_local_ip()

  with ReuseAddressTCPServer((HOST, PORT), CrackerLabHandler) as httpd:
    print("\033[92m" + "=" * 68)
    print(" ⚡ СТЕНД АНАЛИЗА СТОЙКОСТИ ПАРОЛЕЙ И BRUTE-FORCE ЗАПУЩЕН")
    print(
        f" [*] Бенчмарк вашего ПК : MD5 = {CPU_BENCHMARK['md5_hps']:,} хэш/сек"
        f" | PBKDF2 = {CPU_BENCHMARK['pbkdf2_hps']} хэш/сек"
    )
    print(f" [*] Локальный адрес    : http://localhost:{PORT}")
    print(f" [*] Адрес в сети       : http://{local_ip}:{PORT}")
    print("=" * 68 + "\033[0m")

    threading.Timer(0.5, open_browser).start()
    try:
      httpd.serve_forever()
    except KeyboardInterrupt:
      print("\n[*] Стенд остановлен.")