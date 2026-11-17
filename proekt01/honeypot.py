# ==============================================================================
# 1. ПОДКЛЮЧЕНИЕ НЕОБХОДИМЫХ МОДУЛЕЙ
# ==============================================================================

import datetime  # Для получения текущей даты и точного времени событий (для логов)
import os  # Для проверки существования файлов на диске (например, ключа сервера)
import socket  # Для создания низкоуровневых сетевых TCP-сокетов (слушать входящие соединения)
import sys  # Для взаимодействия с интерпретатором Python и системным выводом
import threading  # Для многопоточности (чтобы сервер мог обслуживать несколько хакеров одновременно)
import paramiko  # Главная библиотека: реализует протоколы SSHv2, шифрование и сессии

# ==============================================================================
# 2. НАСТРОЙКИ СЕРВЕРА И ПУТИ К ФАЙЛАМ
# ==============================================================================

PORT = (
    2222  # Порт, который будет слушать ловушка (2222, чтобы не конфликтовать со
          # стандартным SSH на 22 порту)
)
HOST = (
    "0.0.0.0"  # Слушать на всех сетевых интерфейсах (локально 127.0.0.1 и по
               # локальной сети)
)
KEY_FILE = "server.key"  # Имя файла, в котором сохраняется приватный RSA-ключ сервера
LOG_FILE = "honeypot.log"  # Имя текстового файла, куда будут сохраняться все действия злоумышленников

# ==============================================================================
# 3. ГЕНЕРАЦИЯ / ЗАГРУЗКА SSH-КЛЮЧА ХОСТА
# ==============================================================================

# Любой настоящий SSH-сервер обязан иметь свой закрытый ключ для шифрования канала связи
if not os.path.exists(KEY_FILE):
  # Если файла ключа ещё нет на диске, генерируем новый RSA-ключ длиной 2048 бит
  print("[*] Генерация временного RSA-ключа сервера...")
  key = paramiko.RSAKey.generate(2048)
  # Сохраняем сгенерированный ключ в файл server.key, чтобы использовать его повторно
  key.write_private_key_file(KEY_FILE)
else:
  # Если файл уже существует, просто загружаем его из файла
  key = paramiko.RSAKey(filename=KEY_FILE)


# ==============================================================================
# 4. ФУНКЦИЯ ЛОГИРОВАНИЯ СОБЫТИЙ
# ==============================================================================


def log_event(ip, event_type, details):
  """Формирует строку события, выводит её цветной в консоль и дописывает в лог-файл."""
  # Получаем текущую временную метку в читаемом формате: ГГГГ-ММ-ДД ЧЧ:ММ:СС
  timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

  # Формируем стандартную запись: [Время] [IP атакующего] [Тип действия] Подробности
  entry = f"[{timestamp}] [{ip}] [{event_type}] {details}"

  # Выводим строку в консоль сервера жёлтым цветом (\033[93m — код цвета ANSI, \033[0m — сброс цвета)
  print(f"\033[93m{entry}\033[0m")

  # Открываем файл honeypot.log в режиме добавления ("a" - append), чтобы не затирать старые записи
  with open(LOG_FILE, "a", encoding="utf-8") as f:
    f.write(entry + "\n")  # Записываем строку с переносом на новую


# ==============================================================================
# 5. КЛАСС ЭМУЛЯЦИИ SSH-СЕРВЕРА (PARAMIKO SERVER INTERFACE)
# ==============================================================================


class HoneypotSSHServer(paramiko.ServerInterface):
  """Класс-интерфейс, который диктует Paramiko, как реагировать на запросы SSH-клиента."""

  def __init__(self, client_ip):
    self.client_ip = client_ip  # Сохраняем IP-адрес подключившегося клиента
    self.event = (
        threading.Event()
    )  # Специальный флаг для ожидания открытия интерактивной оболочки (Shell)

  def check_channel_request(self, kind, chanid):
    # Разрешаем клиенту открывать стандартный сеанс связи ("session")
    if kind == "session":
      return paramiko.OPEN_SUCCEEDED
    # Любые другие типы запросов (например, проброс портов) отклоняем
    return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

  def check_auth_password(self, username, password):
    # ГЛАВНАЯ ФИШКА ХАНИПОТА: перехватываем логин и пароль в лог
    log_event(
        self.client_ip, "AUTH_ATTEMPT", f"User: {username} | Pass: {password}"
    )
    # И возвращаем статус "Успешно" независимо от того, что ввёл взломщик
    return paramiko.AUTH_SUCCESSFUL

  def get_allowed_auths(self, username):
    # Сообщаем клиенту, что вход осуществляется по обычному паролю
    return "password"

  def check_channel_shell_request(self, channel):
    # Когда клиент запрашивает открытие терминала (Shell), взводим флаг готовности
    self.event.set()
    return True

  def check_channel_pty_request(
      self, channel, term, width, height, pixelwidth, pixelheight, modes
  ):
    # Подтверждаем создание псевдотерминала (PTY) для корректной эмуляции консоли Linux
    return True


# ==============================================================================
# 6. ФУНКЦИЯ ОБРАБОТКИ СЕССИИ КЛИЕНТА (ОТДЕЛЬНЫЙ ПОТОК)
# ==============================================================================


def handle_client(client_socket, client_addr):
  """Обрабатывает соединение с конкретным атакующим в изолированном потоке."""
  ip = client_addr[0]  # Извлекаем строковый IP-адрес клиента
  log_event(ip, "CONNECTION", "Подключение нового клиента к ловушке")

  # Оборачиваем сырой TCP-сокет в криптографический транспорт Paramiko
  transport = paramiko.Transport(client_socket)
  transport.add_server_key(key)  # Подключаем ключ хоста для рукопожатия (SSH handshake)

  # Создаём экземпляр нашего фейкового сервера
  server = HoneypotSSHServer(ip)

  try:
    # Запускаем протокол SSH-согласования
    transport.start_server(server=server)

    # Ждём до 20 секунд, пока клиент создаст канал связи
    channel = transport.accept(20)
    if channel is None:
      log_event(ip, "DISCONNECT", "Клиент не открыл сессию")
      return

    # Ждём до 10 секунд запроса на запуск оболочки shell
    server.event.wait(10)
    if not server.event.is_set():
      log_event(ip, "DISCONNECT", "PTY/Shell не запрошены")
      return

    # Отправляем фейковый приветственный баннер операционной системы Ubuntu
    channel.send(
        b"\r\nWelcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-generic x86_64)\r\n\r\n"
        b" * Documentation:  https://help.ubuntu.com\r\n"
        b" * Management:     https://landscape.canonical.com\r\n\r\n"
    )

    # Задаём вид командной строки (приглашение суперпользователя root)
    prompt = b"root@srv-prod-db:~# "
    channel.send(prompt)

    cmd_buffer = ""  # Буфер для накопления введенных символов в текущую команду

    # Бесконечный цикл посимвольного чтения ввода от клиента
    while True:
      # Читаем ровно 1 байт из сетевого канала
      char = channel.recv(1).decode("utf-8", errors="ignore")

      # Если клиент разорвал соединение, выходим из цикла
      if not char:
        break

      # Если нажата клавиша Enter (\r или \n)
      if char in ("\r", "\n"):
        channel.send(b"\r\n")  # Переводим строку в терминале клиента
        cmd = cmd_buffer.strip()  # Обрезаем случайные пробелы по краям команды

        # Если команда не пустая, сохраняем её в лог
        if cmd:
          log_event(ip, "COMMAND", cmd)

        # Симуляция ответов системы на базовые команды разведки
        if cmd == "exit":
          channel.send(b"logout\r\n")
          break  # Завершаем сессию, если клиент ввёл exit
        elif cmd in ("id", "whoami"):
          # Имитируем вывод root-пользователя
          channel.send(b"uid=0(root) gid=0(root) groups=0(root)\r\n")
        elif cmd == "uname -a":
          # Имитируем информацию о версии ядра Linux
          channel.send(
              b"Linux srv-prod-db 5.15.0-generic #1 SMP x86_64 GNU/Linux\r\n"
          )
        elif cmd in ("ls", "dir"):
          # Показываем фальшивые файлы, привлекающие внимание взломщика
          channel.send(b"backup_db.sql  config.env  id_rsa  notes.txt\r\n")
        elif cmd.startswith("cat"):
          # Если пытаются читать файлы, выводим фейковый список системных аккаунтов
          channel.send(
              b"root:x:0:0:root:/root:/bin/bash\r\nadmin:x:1000:1000::/home/admin:/bin/bash\r\n"
          )
        elif cmd == "pwd":
          channel.send(b"/root\r\n")  # Показываем домашнюю папку root
        elif cmd:
          # На любую неизвестную команду выдаем стандартную ошибку bash
          channel.send(f"bash: {cmd}: command not found\r\n".encode())

        cmd_buffer = ""  # Очищаем буфер для следующей команды
        channel.send(prompt)  # Снова выводим строку приглашения

      # Обработка клавиши Backspace (удаление последнего символа)
      elif char in ("\x7f", "\x08"):
        if cmd_buffer:
          cmd_buffer = cmd_buffer[:-1]  # Удаляем символ из буфера строки
          channel.send(
              b"\b \b"
          )  # Стираем символ на экране у клиента (курсор назад, пробел, курсор назад)

      # Любой обычный напечатанный символ
      else:
        cmd_buffer += char  # Добавляем символ в буфер
        channel.send(char.encode())  # Отправляем символ обратно (эхо-печать)

  except Exception as e:
    # Фиксируем непредвиденные сбои в соединении
    log_event(ip, "ERROR", str(e))
  finally:
    # Гарантированно освобождаем сокеты и закрываем сессию при отключении
    log_event(ip, "DISCONNECT", "Клиент отключился")
    transport.close()
    client_socket.close()


# ==============================================================================
# 7. ФУНКЦИЯ ЗАПУСКА СЛУШАЮЩЕГО СЕРВЕРА
# ==============================================================================


def start_honeypot():
  # Создаём стандартный сетевой сокет (IPv4, TCP-поток)
  server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  # Разрешаем повторное использование порта сразу после перезапуска (избегает ошибки "Address already in use")
  server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

  # Привязываем сокет к адресу и порту 2222
  server_socket.bind((HOST, PORT))

  # Переводим сокет в режим ожидания (до 100 подключений в очереди)
  server_socket.listen(100)

  print(
      f"\033[92m[+] SSH-Honeypot запущен и ожидает подключения на порту"
      f" {PORT}...\033[0m"
  )

  # Основной цикл приема соединений
  while True:
    # Метод accept блокирует выполнение, пока кто-то не подключится
    client_socket, client_addr = server_socket.accept()

    # Для каждого нового подключения создаем отдельный поток (Thread)
    thread = threading.Thread(
        target=handle_client, args=(client_socket, client_addr)
    )

    # Делаем поток фоновым (daemon), чтобы он автоматически закрылся при остановке скрипта
    thread.daemon = True

    # Запускаем поток на выполнение
    thread.start()


# ==============================================================================
# 8. ТОЧКА ВХОДА (ЗАПУСК ПРОГРАММЫ)
# ==============================================================================

# Проверяем, что файл запущен напрямую пользователем, а не импортирован как библиотека
if __name__ == "__main__":
  start_honeypot()