#!/bin/bash

# Определение цветов
CYAN='\033[1;36m'
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # Сброс цвета

clear
echo -e "${CYAN}==========================================${NC}"
echo -e "${CYAN}        QUICK SECURITY AUDITOR            ${NC}"
echo -e "${CYAN}==========================================${NC}"

# 1. Проверка прав на системные файлы
echo -e "\n${GREEN}[1] Проверка критических файлов:${NC}"

if [ -f /etc/shadow ]; then
    SHADOW_PERM=$(stat -c "%a" /etc/shadow)
    if [ "$SHADOW_PERM" -le 640 ]; then
        echo -e "  [${GREEN}OK${NC}] /etc/shadow имеет безопасные права: $SHADOW_PERM"
    else
        echo -e "  [${RED}ОПАСНОСТЬ${NC}] /etc/shadow слишком открыт: $SHADOW_PERM"
    fi
else
    echo -e "  [${YELLOW}INFO${NC}] Доступ к /etc/shadow ограничен"
fi

# 2. Поиск открытых портов (Listening Sockets)
echo -e "\n${GREEN}[2] Активные сетевые порты (LISTEN):${NC}"
ss -tuln | awk 'NR==1 {print $1, $2, $4, $5} /LISTEN/ {printf "%-6s %-6s %-22s %-22s\n", $1, $2, $4, $5}'

# 3. Поиск SUID-файлов (потенциальный вектор для Privilege Escalation)
echo -e "\n${GREEN}[3] Найдено SUID-файлов в /usr/bin (первые 5):${NC}"
SUID_COUNT=$(find /usr/bin -type f -perm -4000 2>/dev/null | wc -l)
echo -e "  Всего SUID-бинарников: ${YELLOW}$SUID_COUNT${NC}"
find /usr/bin -type f -perm -4000 2>/dev/null | head -n 5 | sed 's/^/  -> /'

# 4. Проверка запущенных процессов от root
echo -e "\n${GREEN}[4] Статистика процессов root:${NC}"
ROOT_PROC=$(ps -u root --no-headers 2>/dev/null | wc -l)
echo -e "  Запущено процессов от суперпользователя: ${YELLOW}$ROOT_PROC${NC}"

# 5. Проверка активных сессий пользователей
echo -e "\n${GREEN}[5] Активные пользователи в системе:${NC}"
who | awk '{print "  Пользователь:", $1, "| Терминал:", $2, "| Время входа:", $3, $4}'

echo -e "\n${CYAN}==========================================${NC}"