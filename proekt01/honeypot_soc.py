import datetime
import http.server
import json
import os
import socket
import socketserver
import threading
import paramiko

SSH_PORT = 2222
WEB_PORT = 5000
HOST = "0.0.0.0"
KEY_FILE = "server.key"

# База данных событий для веб-дашборда
events_db = {
    "total_connections": 0,
    "auth_attempts": [],
    "commands": [],
    "recent_logs": [],
}

if not os.path.exists(KEY_FILE):
  key = paramiko.RSAKey.generate(2048)
  key.write_private_key_file(KEY_FILE)
else:
  key = paramiko.RSAKey(filename=KEY_FILE)


def register_event(ip, event_type, details):
  """Регистрация событий в консоли сервера, лог-файле и памяти дашборда."""
  timestamp = datetime.datetime.now().strftime("%H:%M:%S")
  entry = f"[{timestamp}] [{ip}] [{event_type}] {details}"
  print(f"\033[93m{entry}\033[0m")

  with open("honeypot.log", "a", encoding="utf-8") as f:
    f.write(entry + "\n")

  events_db["recent_logs"].insert(
      0, {"time": timestamp, "ip": ip, "type": event_type, "details": details}
  )
  if len(events_db["recent_logs"]) > 50:
    events_db["recent_logs"].pop()

  if event_type == "CONNECTION":
    events_db["total_connections"] += 1
  elif event_type == "AUTH_ATTEMPT":
    parts = details.split(" | ")
    user = parts[0].replace("User: ", "") if len(parts) > 0 else "-"
    pwd = parts[1].replace("Pass: ", "") if len(parts) > 1 else "-"
    events_db["auth_attempts"].insert(
        0, {"time": timestamp, "ip": ip, "user": user, "pass": pwd}
    )
  elif event_type == "COMMAND":
    events_db["commands"].insert(
        0, {"time": timestamp, "ip": ip, "cmd": details}
    )


class HoneypotSSHServer(paramiko.ServerInterface):

  def __init__(self, client_ip):
    self.client_ip = client_ip
    self.event = threading.Event()

  def check_channel_request(self, kind, chanid):
    return (
        paramiko.OPEN_SUCCEEDED
        if kind == "session"
        else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    )

  def check_auth_password(self, username, password):
    register_event(
        self.client_ip,
        "AUTH_ATTEMPT",
        f"User: {username} | Pass: {password}",
    )
    return paramiko.AUTH_SUCCESSFUL

  def get_allowed_auths(self, username):
    return "password"

  def check_channel_shell_request(self, channel):
    self.event.set()
    return True

  def check_channel_pty_request(self, channel, *args):
    return True


# ==============================================================================
# БАЗА ФЕЙКОВЫХ ОТВЕТОВ СИСТЕМЫ ДЛЯ ХАКЕРА
# ==============================================================================
FAKE_CREDS = (
    "DB_HOST=10.0.0.15\r\n"
    "DB_PORT=5432\r\n"
    "DB_USER=postgres_admin\r\n"
    "DB_PASS=SuperSecretP@ssw0rd2026!\r\n"
    "JWT_SECRET=a8f59d9c2e0b11eeb805\r\n"
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\r\n"
)

FAKE_ID_RSA = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\r\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\r\n"
    "NhAAAAAwEAAQAAAYEAv852cK0mQ3p0/K2+FqM4H9pG2V7L3q2pQ1r7M2...\r\n"
    "[FAKE PRIVATE KEY FOR THREAT ANALYSIS]\r\n"
    "-----END OPENSSH PRIVATE KEY-----\r\n"
)

FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\r\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\r\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\r\n"
    "sync:x:4:65534:sync:/bin:/bin/sync\r\n"
    "games:x:5:60:games:/usr/games:/usr/sbin/nologin\r\n"
    "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\r\n"
    "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\r\n"
    "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\r\n"
    "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\r\n"
    "sysadmin:x:1000:1000:System Administrator,,,:/home/sysadmin:/bin/bash\r\n"
    "backup_service:x:1001:1001::/var/backups:/bin/sh\r\n"
)

FAKE_PS_AUX = (
    "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n"
    "root         1  0.0  0.1 168432 11240 ?        Ss   06:00   0:02"
    " /sbin/init\r\n"
    "root         2  0.0  0.0      0     0 ?        S    06:00   0:00"
    " [kthreadd]\r\n"
    "root       420  0.1  0.8 284512 32410 ?        Ssl  06:01   0:15"
    " /usr/bin/dockerd\r\n"
    "postgres   780  0.2  1.4 412080 58900 ?        Ss   06:01   0:32"
    " /usr/lib/postgresql/14/bin/postgres\r\n"
    "root       992  0.0  0.2  72296  7120 ?        Ss   06:02   0:01"
    " /usr/sbin/sshd -D\r\n"
    "root      1450  0.0  0.1  14856  4120 pts/0    Ss   07:15   0:00 -bash\r\n"
    "root      1492  0.0  0.0  21420  2450 pts/0    R+   07:20   0:00 ps"
    " aux\r\n"
)

FAKE_NETSTAT = (
    "Active Internet connections (only servers)\r\n"
    "Proto Recv-Q Send-Q Local Address           Foreign Address        "
    " State\r\n"
    "tcp        0      0 0.0.0.0:22              0.0.0.0:*              "
    " LISTEN\r\n"
    "tcp        0      0 0.0.0.0:5432            0.0.0.0:*              "
    " LISTEN\r\n"
    "tcp        0      0 127.0.0.1:3306          0.0.0.0:*              "
    " LISTEN\r\n"
    "tcp        0      0 0.0.0.0:80              0.0.0.0:*              "
    " LISTEN\r\n"
    "tcp        0      0 0.0.0.0:443             0.0.0.0:*              "
    " LISTEN\r\n"
)

FAKE_HISTORY = (
    "    1  apt update && apt upgrade -y\r\n"
    "    2  docker run -d -p 5432:5432 postgres\r\n"
    "    3  cat /etc/shadow\r\n"
    "    4  tar -czvf /root/database_backup.sql.tar.gz /var/lib/postgresql\r\n"
    "    5  ssh-keygen -t rsa -b 4096\r\n"
    "    6  ufw allow 22/tcp\r\n"
    "    7  ufw enable\r\n"
    "    8  systemctl restart ssh\r\n"
)


def handle_ssh_client(client_socket, client_addr):
  ip = client_addr[0]
  register_event(ip, "CONNECTION", "Новая сессия атаки")
  transport = paramiko.Transport(client_socket)
  transport.add_server_key(key)
  server = HoneypotSSHServer(ip)

  try:
    transport.start_server(server=server)
    channel = transport.accept(20)
    if not channel:
      return
    server.event.wait(10)

    # Приветствие Linux
    channel.send(
        b"\r\nWelcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-generic"
        b" x86_64)\r\n"
        b" * Documentation:  https://help.ubuntu.com\r\n"
        b" * Management:     https://landscape.canonical.com\r\n"
        b" * Support:        https://ubuntu.com/advantage\r\n\r\n"
        b"System information as of current session:\r\n"
        b"  System load:  0.15               Processes:             114\r\n"
        b"  Usage of /:   24.1% of 48.20GB   Users logged in:       1\r\n"
        b"  Memory usage: 38%                IPv4 address for eth0: 10.0.0.15\r\n\r\n"
        b"Last login: Sun Nov  8 19:42:10 2026 from 192.168.1.100\r\n"
    )

    current_dir = "/root"
    prompt = f"root@srv-prod-db:{current_dir}# ".encode()
    channel.send(prompt)

    buf = ""
    while True:
      char = channel.recv(1).decode("utf-8", errors="ignore")
      if not char:
        break

      if char in ("\r", "\n"):
        channel.send(b"\r\n")
        raw_cmd = buf.strip()
        cmd = raw_cmd.lower()

        if raw_cmd:
          register_event(ip, "COMMAND", raw_cmd)

        # Выход
        if cmd in ("exit", "logout", "quit"):
          channel.send(b"logout\r\nConnection to srv-prod-db closed.\r\n")
          break

        # Очистка экрана
        elif cmd == "clear":
          channel.send(b"\033[2J\033[H")

        # Информация о текущем пользователе
        elif cmd in ("whoami", "id"):
          channel.send(
              b"uid=0(root) gid=0(root)"
              b" groups=0(root),4(adm),24(cdrom),27(sudo)\r\n"
          )

        # Текущая директория
        elif cmd == "pwd":
          channel.send(f"{current_dir}\r\n".encode())

        # Навигация cd
        elif cmd.startswith("cd"):
          target = cmd.replace("cd", "").strip()
          if not target or target == "~":
            current_dir = "/root"
          elif target in ("..", "/"):
            current_dir = "/"
          elif target in ("/etc", "etc"):
            current_dir = "/etc"
          elif target in ("/var/log", "logs", "/var"):
            current_dir = "/var/log"
          prompt = f"root@srv-prod-db:{current_dir}# ".encode()

        # Список файлов
        elif cmd in ("ls", "dir"):
          if current_dir == "/root":
            channel.send(
                b"creds.env  database_backup.sql  id_rsa  notes.txt  scripts/\r\n"
            )
          elif current_dir == "/etc":
            channel.send(
                b"passwd  shadow  hosts  hostname  ssh/  cron.d/  fstab\r\n"
            )
          else:
            channel.send(b"auth.log  syslog  nginx/  postgresql/  dpkg.log\r\n")

        elif cmd.startswith("ls -"):
          channel.send(
              b"total 44\r\n"
              b"drwx------  4 root root 4096 Nov  8 18:20 .\r\n"
              b"drwxr-xr-x 20 root root 4096 Nov  1 10:14 ..\r\n"
              b"-rw-------  1 root root  280 Nov  8 18:15 creds.env\r\n"
              b"-rw-r--r--  1 root root 8192 Nov  8 17:40 database_backup.sql\r\n"
              b"-rw-------  1 root root 2602 Nov  8 18:02 id_rsa\r\n"
              b"-rw-r--r--  1 root root  420 Nov  8 18:22 notes.txt\r\n"
              b"drwxr-xr-x  2 root root 4096 Nov  8 16:30 scripts\r\n"
          )

        # Чтение файлов (cat / nano / head / tail / less)
        elif any(cmd.startswith(c) for c in ("cat", "more", "less", "head", "tail")):
          if "creds.env" in cmd:
            channel.send(FAKE_CREDS.encode())
          elif "id_rsa" in cmd:
            channel.send(FAKE_ID_RSA.encode())
          elif "passwd" in cmd:
            channel.send(FAKE_PASSWD.encode())
          elif "shadow" in cmd:
            channel.send(
                b"root:$6$v19gT$gG6XkO0PqWbZ1qO...:19240:0:99999:7:::\r\n"
                b"sysadmin:$6$kJ82k$QO8x1P...:19240:0:99999:7:::\r\n"
            )
          elif "notes.txt" in cmd:
            channel.send(
                b"TODO for DevOps:\r\n"
                b"1. Transfer postgres backup to AWS S3 bucket.\r\n"
                b"2. Revoke temporary SSH root access after audit.\r\n"
            )
          else:
            channel.send(
                b"cat: "
                + raw_cmd.split()[-1].encode()
                + b": No such file or directory\r\n"
            )

        # Сетевые подключения
        elif any(
            cmd.startswith(c)
            for c in ("netstat", "ss", "lsof -i", "ip a", "ifconfig")
        ):
          if "ip" in cmd or "ifconfig" in cmd:
            channel.send(
                b"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state"
                b" UNKNOWN\r\n"
                b"    inet 127.0.0.1/8 scope host lo\r\n"
                b"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state"
                b" UP\r\n"
                b"    inet 10.0.0.15/24 brd 10.0.0.255 scope global eth0\r\n"
            )
          else:
            channel.send(FAKE_NETSTAT.encode())

        # Системные процессы
        elif cmd in ("ps", "ps aux", "ps -ef", "top", "htop"):
          channel.send(FAKE_PS_AUX.encode())

        # Диск и оперативная память
        elif cmd.startswith("df"):
          channel.send(
              b"Filesystem     1K-blocks     Used Available Use% Mounted on\r\n"
              b"/dev/sda1       50058240 12054120  35489810  25% /\r\n"
              b"tmpfs            4032120        0   4032120   0% /dev/shm\r\n"
          )
        elif cmd.startswith("free"):
          channel.send(
              b"               total        used        free      shared"
              b"  buff/cache   available\r\n"
              b"Mem:         8192000     3142000     2850000      124000"
              b"     2200000     4726000\r\n"
              b"Swap:        2097152           0     2097152\r\n"
          )

        # Версия ядра и дистрибутива
        elif cmd in ("uname -a", "uname -r"):
          channel.send(
              b"Linux srv-prod-db 5.15.0-89-generic #99-Ubuntu SMP Mon Nov 6"
              b" 14:00:00 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux\r\n"
          )
        elif any(x in cmd for x in ("os-release", "issue", "version")):
          channel.send(
              b'NAME="Ubuntu"\r\nVERSION="22.04.2 LTS (Jammy'
              b' Jellyfish)"\r\nID=ubuntu\r\n'
          )

        # История терминала
        elif cmd == "history":
          channel.send(FAKE_HISTORY.encode())

        # Имитация попытки скачать вирус/майнер (wget / curl)
        elif cmd.startswith("wget") or cmd.startswith("curl"):
          target_url = raw_cmd.split()[-1]
          channel.send(
              f"--2026-11-09 12:40:01--  {target_url}\r\n"
              f"Resolving {target_url.split('/')[2] if '/' in target_url else 'target'}... 185.190.140.22\r\n"
              "Connecting to remote host... connected.\r\n"
              "HTTP request sent, awaiting response... 200 OK\r\n"
              "Length: 48920 (48K) [application/x-sh]\r\n"
              "Saving to: 'payload.sh'\r\n\r\n"
              "payload.sh          100%[===================>]  47.77K  --.-KB/s    in 0.02s\r\n\r\n"
              "2026-11-09 12:40:02 (2.34 MB/s) - 'payload.sh' saved [48920/48920]\r\n".encode()
          )

        # Проверка sudo
        elif cmd in ("sudo -l", "sudo su", "su"):
          channel.send(
              b"User root may run the following commands on"
              b" srv-prod-db:\r\n    (ALL : ALL) ALL\r\n"
          )

        # Создание или удаление файлов (создают видимость работы)
        elif any(cmd.startswith(c) for c in ("touch", "mkdir", "rm", "chmod")):
          pass  # В Linux команды touch/rm/chmod при успехе ничего не выводят

        # Эхо
        elif cmd.startswith("echo"):
          echo_text = raw_cmd[5:].strip().strip("\"'")
          channel.send(f"{echo_text}\r\n".encode())

        # Неизвестная команда
        elif cmd:
          first_word = raw_cmd.split()[0]
          channel.send(f"bash: {first_word}: command not found\r\n".encode())

        buf = ""
        channel.send(prompt)

      elif char in ("\x7f", "\x08"):
        if buf:
          buf = buf[:-1]
          channel.send(b"\b \b")
      else:
        buf += char
        channel.send(char.encode())

  except Exception:
    pass
  finally:
    register_event(ip, "DISCONNECT", "Сессия завершена")
    transport.close()
    client_socket.close()


def run_ssh_service():
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind((HOST, SSH_PORT))
  s.listen(50)
  while True:
    client_socket, client_addr = s.accept()
    threading.Thread(
        target=handle_ssh_client,
        args=(client_socket, client_addr),
        daemon=True,
    ).start()


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"><title>SOC Threat Intelligence Dashboard</title>
<style>
  :root { --bg: #0b0f19; --card: #111827; --accent: #00f0ff; --red: #ff0055; --green: #00ff66; --text: #e2e8f0; }
  body { margin: 0; background: var(--bg); color: var(--text); font-family: 'Segoe UI', monospace; padding: 20px; }
  header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #1f293d; padding-bottom: 15px; margin-bottom: 20px; }
  .badge { background: #1f293d; padding: 6px 14px; border-radius: 20px; font-weight: bold; border: 1px solid #374151; }
  .alert { border-color: var(--red); color: var(--red); animation: pulse 1s infinite alternate; }
  @keyframes pulse { from { box-shadow: 0 0 5px var(--red); } to { box-shadow: 0 0 20px var(--red); } }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 15px; margin-bottom: 20px; }
  .card { background: var(--card); border: 1px solid #1f293d; border-radius: 8px; padding: 15px; }
  .stat-num { font-size: 32px; font-weight: bold; color: var(--accent); margin-top: 5px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px; border-bottom: 1px solid #1f293d; }
  th { color: #94a3b8; }
  .term { background: #050811; border-radius: 6px; padding: 10px; height: 180px; overflow-y: auto; font-family: Consolas, monospace; font-size: 13px; color: var(--green); border: 1px solid #1f293d; }
  .tag { background: #1e293b; padding: 2px 6px; border-radius: 4px; font-size: 11px; }
  .tag-danger { background: rgba(255, 0, 85, 0.2); color: var(--red); }
</style>
</head>
<body>
<header>
  <div>
    <h1 style="margin:0; font-size: 24px; color: var(--accent);">🛡️ SOC THREAT MONITOR // SSH-HONEYPOT</h1>
    <span style="color:#64748b; font-size: 12px;">Центр анализа несанкционированного доступа</span>
  </div>
  <div id="statusBadge" class="badge">СТАТУС: МОНИТОРИНГ АКТИВЕН</div>
</header>

<div class="grid">
  <div class="card">
    <div style="color: #94a3b8; font-size: 12px;">ПОДКЛЮЧЕНИЙ К ЛОВУШКЕ</div>
    <div id="connCount" class="stat-num">0</div>
  </div>
  <div class="card">
    <div style="color: #94a3b8; font-size: 12px;">ПЕРЕХВАЧЕНО ПАРОЛЕЙ</div>
    <div id="credCount" class="stat-num" style="color: var(--red);">0</div>
  </div>
  <div class="card">
    <div style="color: #94a3b8; font-size: 12px;">ВЫПОЛНЕНО КОМАНД В ШЕЛЛЕ</div>
    <div id="cmdCount" class="stat-num" style="color: var(--green);">0</div>
  </div>
</div>

<div class="grid" style="grid-template-columns: 1fr 1fr;">
  <div class="card">
    <h3 style="margin-top:0; color:var(--red);">🔑 Перехваченные учетные данные</h3>
    <table>
      <thead><tr><th>Время</th><th>IP</th><th>Логин</th><th>Пароль</th></tr></thead>
      <tbody id="authTable"></tbody>
    </table>
  </div>
  <div class="card">
    <h3 style="margin-top:0; color:var(--accent);">💻 Последние команды взломщика</h3>
    <table>
      <thead><tr><th>Время</th><th>IP</th><th>Команда</th></tr></thead>
      <tbody id="cmdTable"></tbody>
    </table>
  </div>
</div>

<div class="card">
  <h3 style="margin-top:0; color:#94a3b8;">📟 Системный поток событий ловушки (Live Feed)</h3>
  <div id="liveFeed" class="term"></div>
</div>

<script>
let lastCredsCount = 0;
const audioCtx = new (window.AudioContext || window.webkitAudioContext)();

function beep() {
  try {
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.frequency.value = 880;
    gain.gain.value = 0.1;
    osc.start();
    osc.stop(audioCtx.currentTime + 0.15);
  } catch(e) {}
}

async function updateDashboard() {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();
    
    document.getElementById('connCount').innerText = data.total_connections;
    document.getElementById('credCount').innerText = data.auth_attempts.length;
    document.getElementById('cmdCount').innerText = data.commands.length;

    if (data.auth_attempts.length > lastCredsCount) {
      if (lastCredsCount > 0) beep();
      lastCredsCount = data.auth_attempts.length;
      const badge = document.getElementById('statusBadge');
      badge.className = 'badge alert';
      badge.innerText = 'ВНИМАНИЕ: АТАКА В РЕАЛЬНОМ ВРЕМЕНИ!';
      setTimeout(() => {
        badge.className = 'badge';
        badge.innerText = 'СТАТУС: МОНИТОРИНГ АКТИВЕН';
      }, 4000);
    }

    document.getElementById('authTable').innerHTML = data.auth_attempts.slice(0, 5).map(a => 
      `<tr><td>${a.time}</td><td>${a.ip}</td><td><span class="tag">${a.user}</span></td><td style="color:var(--red); font-weight:bold;">${a.pass}</td></tr>`
    ).join('');

    document.getElementById('cmdTable').innerHTML = data.commands.slice(0, 5).map(c => 
      `<tr><td>${c.time}</td><td>${c.ip}</td><td><code>${c.cmd}</code></td></tr>`
    ).join('');

    document.getElementById('liveFeed').innerHTML = data.recent_logs.slice(0, 15).map(l => 
      `<div>[${l.time}] [${l.ip}] <span class="${l.type === 'AUTH_ATTEMPT' ? 'tag-danger' : 'tag'}">${l.type}</span>: ${l.details}</div>`
    ).join('');
  } catch(e) {}
}

setInterval(updateDashboard, 1000);
updateDashboard();
</script>
</body>
</html>
"""


class WebHandler(http.server.SimpleHTTPRequestHandler):

  def do_GET(self):
    if self.path == "/api/stats":
      self.send_response(200)
      self.send_header("Content-Type", "application/json")
      self.end_headers()
      self.wfile.write(json.dumps(events_db).encode())
    else:
      self.send_response(200)
      self.send_header("Content-Type", "text/html; charset=utf-8")
      self.end_headers()
      self.wfile.write(DASHBOARD_HTML.encode("utf-8"))

  def log_message(self, format, *args):
    return


if __name__ == "__main__":
  threading.Thread(target=run_ssh_service, daemon=True).start()

  print("\033[92m" + "=" * 65)
  print(f"[+] SSH-Ловушка запущена на порту : {SSH_PORT}")
  print(f"[+] Веб-дашборд SOC доступен на   : http://localhost:{WEB_PORT}")
  print("=" * 65 + "\033[0m")

  with socketserver.TCPServer((HOST, WEB_PORT), WebHandler) as httpd:
    try:
      httpd.serve_forever()
    except KeyboardInterrupt:
      print("\n[*] Комплекс безопасности остановлен.")