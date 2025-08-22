#!/bin/sh
# Установка static WebUI (Entware / Keenetic)

# === АНИМАЦИЯ ===
animation() {
  local pid=$1 message=$2 spin='|/-\' i=0
  echo -n "[ ] $message..."
  while kill -0 $pid 2>/dev/null; do
    i=$(( (i+1) %4 ))
    printf "\r[%s] %s..." "${spin:$i:1}" "$message"
    usleep 100000
  done
  wait $pid
  if [ $? -eq 0 ]; then
    printf "\r[✔] %s\n" "$message"
  else
    printf "\r[✖] %s\n" "$message"
    return 1
  fi
}

run_with_animation() {
  local msg="$1"
  shift
  ( "$@" ) >/dev/null 2>&1 &
  animation $! "$msg"
}

set -e

echo "Начинается установка static WebUI..."

# 1) Пакеты
run_with_animation "Установка Lighttpd + PHP8" \
  opkg install lighttpd lighttpd-mod-cgi lighttpd-mod-setenv lighttpd-mod-redirect lighttpd-mod-rewrite \
  php8 php8-cgi php8-cli php8-mod-curl php8-mod-openssl php8-mod-session jq

# 2) Директории
run_with_animation "Создание директорий" \
  sh -c 'mkdir -p /opt/share/www/static /opt/etc/lighttpd/conf.d'

# 3) index.php — ПРАВИЛЬНЫЙ URL без refs/heads
run_with_animation "Загрузка index.php" \
  sh -c 'curl -fsSL https://raw.githubusercontent.com/pegakmop/keeneticstatic/main/opt/share/www/static/index.php -o /opt/share/www/static/index.php'

# 4) Конфиг Lighttpd (порт 95)
run_with_animation "Настройка Lighttpd" sh -c '
cat > /opt/etc/lighttpd/conf.d/80-static.conf << "EOF"
$SERVER["socket"] == ":95" {
    server.document-root = "/opt/share/www/"
    server.modules += ( "mod_cgi", "mod_setenv", "mod_rewrite" )
    cgi.assign = ( ".php" => "/opt/bin/php8-cgi" )
    setenv.set-environment = ( "PATH" => "/opt/bin:/usr/bin:/bin" )
    index-file.names = ( "index.php" )
    url.rewrite-once = ( "^/(.*)" => "/static/$1" )
}
EOF

# гарантируем подключение conf.d/*.conf
MAIN=/opt/etc/lighttpd/lighttpd.conf
grep -q "conf.d/\*\.conf" "$MAIN" 2>/dev/null || \
  echo "include \"/opt/etc/lighttpd/conf.d/*.conf\"" >> "$MAIN"
'

# 5) Перезапуск
run_with_animation "Перезапуск Lighttpd" /opt/etc/init.d/S80lighttpd restart

# 6) Сообщение
ip_address=$(ip addr show br0 2>/dev/null | awk "/inet / {print \$2}" | cut -d/ -f1 | head -n1)
echo ""
echo "✅ static WebUI установлен. Откройте в браузере: http://$ip_address:95"
