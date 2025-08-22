#!/bin/sh
# Установка static WebUI

# === АНИМАЦИЯ ===
animation() {
    local pid=$1 message=$2 spin='|/-\\' i=0
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
    fi
}

run_with_animation() {
    local msg="$1"
    shift
    ("$@") >/dev/null 2>&1 &
    animation $! "$msg"
}

echo "Начинается установка static WebUI..."

run_with_animation "Установка Lighttpd + PHP8" \
    opkg install lighttpd lighttpd-mod-cgi lighttpd-mod-setenv lighttpd-mod-redirect lighttpd-mod-rewrite \
    php8 php8-cgi php8-cli php8-mod-curl php8-mod-openssl php8-mod-session jq

run_with_animation "Создание директорий" \
    mkdir -p /opt/share/www/static /opt/etc/lighttpd/conf.d

run_with_animation "Создание index.php" 
curl -sL https://raw.githubusercontent.com/pegakmop/keeneticwebstatic/refs/heads/main/opt/share/www/static/index.php -o /opt/share/www/static/index.php

run_with_animation "Настройка Lighttpd" sh -c 'cat > /opt/etc/lighttpd/conf.d/80-static.conf <<EOF
server.port := 8899
server.username := ""
server.groupname := ""

\$HTTP["host"] =~ "^(.+):8899$" {
    url.redirect = ( "^/static/" => "http://%1:99" )
    url.redirect-code = 301
}

\$SERVER["socket"] == ":99" {
    server.document-root = "/opt/share/www/"
    server.modules += ( "mod_cgi" )
    cgi.assign = ( ".php" => "/opt/bin/php8-cgi" )
    setenv.set-environment = ( "PATH" => "/opt/bin:/usr/bin:/bin" )
    index-file.names = ( "index.php" )
    url.rewrite-once = ( "^/(.*)" => "/static/$1" )
}
EOF'

run_with_animation "Перезапуск Lighttpd" /opt/etc/init.d/S80lighttpd restart

ip_address=$(ip addr show br0 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)
echo ""
echo "✅ static WebUI установлен. Откройте в браузере: http://$ip_address:99"
