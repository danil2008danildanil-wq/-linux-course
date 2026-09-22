#!/bin/bash

# Определение цветов
CYAN='\033[1;36m'
GREEN='\033[1;32m'
NC='\033[0m' # Сброс цвета

clear
echo -e "${CYAN}==========================================${NC}"
echo -e "${CYAN}        CLI SYSTEM DASHBOARD             ${NC}"
echo -e "${CYAN}==========================================${NC}"

# 1. Uptime
echo -e "\n${GREEN}[+] Время работы системы:${NC}"
uptime -p

# 2. Использование RAM
echo -e "\n${GREEN}[+] Оперативная память (RAM):${NC}"
free -h | awk 'NR==1{print $0} NR==2{print $0}'

# 3. Дисковое пространство
echo -e "\n${GREEN}[+] Корневой диск (/):${NC}"
df -h / | awk 'NR==1{print $0} NR==2{print $0}'

# 4. Топ-5 процессов по CPU
echo -e "\n${GREEN}[+] Топ-5 процессов по загрузке CPU:${NC}"
ps aux --sort=-%cpu | head -n 6 | awk '{printf "%-10s %-8s %-6s %-6s %s\n", $1, $2, $3, $4, $11}'

echo -e "\n${CYAN}==========================================${NC}"