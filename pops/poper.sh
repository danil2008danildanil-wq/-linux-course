#!/bin/bash

# Определение цветов
CYAN='\033[1;36m'
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # Сброс цвета

# Бесконечный цикл обновления
while true; do
    clear
    echo -e "${CYAN}==========================================${NC}"
    echo -e "${CYAN}        CLI SYSTEM DASHBOARD (LIVE)      ${NC}"
    echo -e "${CYAN}==========================================${NC}"
    echo -e "Нажмите ${RED}[Ctrl + C]${NC} для выхода из монитора\n"

    # 1. Uptime
    echo -e "${GREEN}[+] Время работы системы:${NC}"
    uptime -p

    # 2. Использование RAM
    echo -e "\n${GREEN}[+] Оперативная память (RAM):${NC}"
    free -h | awk 'NR==1{print $0} NR==2{print $0}'

    # 3. Дисковое пространство + Alert
    echo -e "\n${GREEN}[+] Корневой диск (/):${NC}"
    DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ "$DISK_USAGE" -gt 80 ]; then
        echo -e "${RED}⚠️  ВНИМАНИЕ: Диск заполнен на $DISK_USAGE%!${NC}"
    else
        echo -e "${YELLOW}Статус диска:${NC} Заполнено $DISK_USAGE%"
    fi
    df -h / | awk 'NR==1{print $0} NR==2{print $0}'

    # 4. Топ-5 процессов по CPU
    echo -e "\n${GREEN}[+] Топ-5 процессов по CPU:${NC}"
    ps aux --sort=-%cpu | head -n 6 | awk '{printf "%-10s %-8s %-6s %-6s %s\n", $1, $2, $3, $4, $11}'

    echo -e "\n${CYAN}==========================================${NC}"
    
    # Задержка в 2 секунды перед перезапуском
    sleep 2
done