#!/bin/bash

CYAN='\033[1;36m'
GREEN='\033[1;32m'
RED='\033[1;31m'
NC='\033[0m'

while true; do
    clear
    echo -e "${CYAN}==========================================${NC}"
    echo -e "${CYAN}     LINUX SYSTEM & SECURITY TOOLKIT      ${NC}"
    echo -e "${CYAN}==========================================${NC}"
    echo -e "1) Системный мониторинг (Real-time)"
    echo -e "2) Быстрый аудит безопасности"
    echo -e "3) Выход"
    echo -e "${CYAN}==========================================${NC}"
    read -p "Выберите опцию [1-3]: " choice

    case $choice in
        1)
            ./src/monitor.sh
            ;;
        2)
            ./src/security.sh
            echo ""
            read -p "Нажмите Enter, чтобы вернуться в меню..."
            ;;
        3)
            echo -e "${GREEN}Завершение работы.${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Ошибка: выберите число от 1 до 3.${NC}"
            sleep 1
            ;;
    esac
done