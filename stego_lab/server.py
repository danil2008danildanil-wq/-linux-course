import http.server
import os
import socket
import socketserver
import threading
import webbrowser

PORT = 8000
HOST = "0.0.0.0"  # Доступ с текущего ПК и любых устройств в локальной сети


class ReuseAddressTCPServer(socketserver.TCPServer):
  allow_reuse_address = True


def get_local_ip():
  """Определяет локальный IP-адрес компьютера в сети Wi-Fi / LAN."""
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip
  except Exception:
    return "127.0.0.1"


def open_browser():
  webbrowser.open(f"http://localhost:{PORT}")


def run_server():
  os.chdir(os.path.dirname(os.path.abspath(__file__)))
  handler = http.server.SimpleHTTPRequestHandler
  local_ip = get_local_ip()

  with ReuseAddressTCPServer((HOST, PORT), handler) as httpd:
    print("\033[96m" + "=" * 65)
    print(" 🔬 ЛАБОРАТОРИЯ СТЕГАНОГРАФИИ (LSB & STEGANALYSIS) ЗАПУЩЕНА")
    print(f" [*] Локальный адрес : http://localhost:{PORT}")
    print(f" [*] Адрес в сети    : http://{local_ip}:{PORT}")
    print(" [*] Для остановки нажмите Ctrl + C")
    print("=" * 65 + "\033[0m")

    threading.Timer(0.5, open_browser).start()

    try:
      httpd.serve_forever()
    except KeyboardInterrupt:
      print("\n\033[93m[*] Сервер остановлен.\033[0m")


if __name__ == "__main__":
  run_server()