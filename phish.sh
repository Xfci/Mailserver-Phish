#!/bin/bash

# Otomatik Phishing Mail Sunucu Kurulum Scripti
# Red Team ve Güvenlik Testleri için
# Kullanım: ./setup_phishing_server.sh domain.com

# Renkli çıktılar için
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Başlangıç kontrolü
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Bu script root olarak çalıştırılmalı!${NC}"
    exit 1
fi

if [ $# -eq 0 ]; then
    echo -e "${RED}Kullanım: $0 <domain>${NC}"
    echo -e "${YELLOW}Örnek: $0 example.com${NC}"
    exit 1
fi

DOMAIN=$1
MAIL_HOSTNAME="mail.${DOMAIN}"

echo -e "${BLUE}=== Phishing Mail Sunucu Otomatik Kurulum ===${NC}"
echo -e "${GREEN}Domain: ${DOMAIN}${NC}"
echo -e "${GREEN}Mail Hostname: ${MAIL_HOSTNAME}${NC}"
echo ""

# Onay isteme
read -p "Kuruluma devam edilsin mi? (y/N): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Kurulum iptal edildi.${NC}"
    exit 1
fi

log_step() {
    echo -e "${BLUE}[ADIM]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[BAŞARILI]${NC} $1"
}

log_error() {
    echo -e "${RED}[HATA]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[UYARI]${NC} $1"
}

# 1. Sistem güncellemesi ve Postfix kurulumu
log_step "1. Sistem güncelleniyor ve Postfix kuruluyor..."
apt update -y
echo "postfix postfix/mailname string ${DOMAIN}" | debconf-set-selections
echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections
apt install -y postfix mailutils

# 2. Hostname ayarları
log_step "2. Hostname ayarları yapılandırılıyor..."
echo "mail" > /etc/hostname
hostnamectl set-hostname mail

# /etc/hosts dosyasını güncelle
cp /etc/hosts /etc/hosts.backup
sed -i "1i ${MAIL_HOSTNAME} mail" /etc/hosts

# 3. Postfix ana konfigürasyon
log_step "3. Postfix konfigürasyonu yapılandırılıyor..."
cp /etc/postfix/main.cf /etc/postfix/main.cf.backup

cat > /etc/postfix/main.cf << EOF
# See /usr/share/postfix/main.cf.dist for a commented, more complete version

# Debian specific:  Specifying a file name will cause the first
# line of that file to be used as the name.  The Debian default
# is /etc/mailname.
#myorigin = /etc/mailname

smtpd_banner = \$myhostname ESMTP \$mail_name (Ubuntu)
biff = no

# appending .domain is the MUA's job.
append_dot_mydomain = no

# Uncomment the next line to generate "delayed mail" warnings
#delay_warning_time = 4h

readme_directory = no

# See http://www.postfix.org/COMPATIBILITY_README.html -- default to 2 on
# fresh installs.
compatibility_level = 2

# TLS parameters
smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
smtpd_tls_security_level=may

smtp_tls_CApath=/etc/ssl/certs
smtp_tls_security_level=may
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache

smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
myhostname = ${MAIL_HOSTNAME}
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = /etc/mailname
mydestination = ${MAIL_HOSTNAME}, mail, localhost.localdomain, localhost
relayhost = 
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all

# SPF Policy Daemon ayarları
policyd-spf_time_limit = 3600
smtpd_recipient_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    check_policy_service unix:private/policyd-spf

# DKIM Milter ayarları
milter_default_action = accept
milter_protocol = 6
smtpd_milters = local:opendkim/opendkim.sock
non_smtpd_milters = \$smtpd_milters
EOF

# /etc/mailname dosyasını güncelle
echo "${DOMAIN}" > /etc/mailname

# 4. SPF Policy Daemon kurulumu
log_step "4. SPF Policy Daemon kuruluyor..."
apt install -y postfix-policyd-spf-python

# master.cf dosyasına SPF policy daemon ekle
cp /etc/postfix/master.cf /etc/postfix/master.cf.backup
echo "" >> /etc/postfix/master.cf
echo "# SPF Policy Daemon" >> /etc/postfix/master.cf
echo "policyd-spf  unix  -       n       n       -       0       spawn" >> /etc/postfix/master.cf
echo "    user=policyd-spf argv=/usr/bin/policyd-spf" >> /etc/postfix/master.cf

# 5. OpenDKIM kurulumu ve konfigürasyonu
log_step "5. OpenDKIM kuruluyor ve konfigüre ediliyor..."
apt install -y opendkim opendkim-tools

# postfix kullanıcısını opendkim grubuna ekle
gpasswd -a postfix opendkim

# OpenDKIM konfigürasyon dosyasını oluştur
cp /etc/opendkim.conf /etc/opendkim.conf.backup

cat > /etc/opendkim.conf << EOF
# This is a basic configuration that can easily be adapted to suit a standard
# installation. For more advanced options, see opendkim.conf(5) and/or
# /usr/share/doc/opendkim/examples/opendkim.conf.sample.

# Log to syslog
Syslog                  yes
# Log additional detail
LogWhy                  yes

# Required to use local socket with MTAs that access the socket as a non-
# privileged user (e.g. Postfix)
UMask                   002

# Sign for example.com with key in /etc/dkimkeys/dkim.key using
# selector '2007' (e.g. 2007._domainkey.example.com)
#Domain                 example.com
#KeyFile                /etc/dkimkeys/dkim.key
#Selector               2007

# Commonly-used options; the commented-out versions show the defaults.
Canonicalization        relaxed/simple
Mode                    sv
SubDomains              no

# Always oversign From (sign using actual From and a null From to prevent
# malicious signatures header fields (From and/or others) between the signer
# and the verifier.  From is oversigned by default in the Debian pacakge
# because it is often the identity key used by reputation systems and thus
# somewhat security sensitive.
OversignHeaders         From

# List domains to use for RFC 6541 DKIM Authorized Third-Party Signatures
# (ATPS) (experimental)

#ATPSHashAlgorithm      sha256

AutoRestart             yes
AutoRestartRate         10/1M
Background              yes
DNSTimeout              5
SignatureAlgorithm      rsa-sha256

KeyTable                refile:/etc/opendkim/key.table
SigningTable            refile:/etc/opendkim/signing.table
ExternalIgnoreList      /etc/opendkim/trusted.hosts
InternalHosts           /etc/opendkim/trusted.hosts

Socket                  local:/var/spool/postfix/opendkim/opendkim.sock
EOF

# OpenDKIM klasörlerini oluştur
mkdir -p /etc/opendkim
mkdir -p /etc/opendkim/keys

# İzinleri ayarla
chown -R opendkim:opendkim /etc/opendkim
chmod go-rw /etc/opendkim/keys

# Signing table oluştur
cat > /etc/opendkim/signing.table << EOF
*@${DOMAIN} default._domainkey.${DOMAIN}
*@*.${DOMAIN} default._domainkey.${DOMAIN}
EOF

# Key table oluştur
cat > /etc/opendkim/key.table << EOF
default._domainkey.${DOMAIN} ${DOMAIN}:default:/etc/opendkim/keys/${DOMAIN}/default.private
EOF

# Trusted hosts oluştur
cat > /etc/opendkim/trusted.hosts << EOF
127.0.0.1
localhost
*.${DOMAIN}
EOF

# DKIM anahtarları oluştur
log_step "6. DKIM anahtarları oluşturuluyor..."
mkdir -p /etc/opendkim/keys/${DOMAIN}
opendkim-genkey -b 2048 -d ${DOMAIN} -D /etc/opendkim/keys/${DOMAIN} -s default -v

# Anahtar izinlerini ayarla
chown opendkim:opendkim /etc/opendkim/keys/${DOMAIN}/default.private
chmod 600 /etc/opendkim/keys/${DOMAIN}/default.private

# OpenDKIM socket klasörü oluştur
mkdir -p /var/spool/postfix/opendkim
chown opendkim:postfix /var/spool/postfix/opendkim

# OpenDKIM default dosyasını güncelle
echo 'SOCKET="local:/var/spool/postfix/opendkim/opendkim.sock"' > /etc/default/opendkim

# 7. SSH servisini enable et
log_step "7. SSH servisi enable ediliyor..."
systemctl enable ssh
systemctl start ssh

# 8. Nginx kurulumu ve SSL sertifikası
log_step "8. Nginx kuruluyor ve SSL sertifikası oluşturuluyor..."
apt install -y nginx certbot python3-certbot-nginx

# Önce basit HTTP konfigürasyonu
cat > /etc/nginx/sites-available/${DOMAIN} << EOF
server {
    listen 80;
    server_name ${DOMAIN} www.${DOMAIN};
    
    location /.well-known/acme-challenge/ {
        root /var/www/html;
        allow all;
    }
    
    # Admin panel
    location /login {
        proxy_pass https://127.0.0.1:92/login;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_ssl_verify off;
    }
    
    # Admin panel static files
    location /static/ {
        proxy_pass https://127.0.0.1:92/static/;
        proxy_set_header Host \$host;
        proxy_ssl_verify off;
    }
    
    # Admin panel API
    location /api/ {
        proxy_pass https://127.0.0.1:92/api/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_ssl_verify off;
    }
    
    # Phishing pages
    location / {
        proxy_pass http://127.0.0.1:91;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Site'ı aktifleştir
ln -sf /etc/nginx/sites-available/${DOMAIN} /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Nginx'i başlat
systemctl start nginx
systemctl enable nginx

# SSL sertifikası al (non-interactive)
log_step "9. Let's Encrypt SSL sertifikası alınıyor..."
certbot --nginx -d ${DOMAIN} -d www.${DOMAIN} --non-interactive --agree-tos --email admin@${DOMAIN} --redirect || {
    log_warning "SSL sertifikası alınamadı, sadece HTTP modunda devam ediliyor"
}

# 10. Gophish kurulumu
log_step "10. Gophish kuruluyor..."

# Gerekli paketleri kur (unzip gerekli)
apt install -y unzip wget

# Gophish'in en son sürümünü indir
GOPHISH_VERSION="v0.12.1"
GOPHISH_URL="https://github.com/gophish/gophish/releases/download/${GOPHISH_VERSION}/gophish-${GOPHISH_VERSION}-linux-64bit.zip"

cd /tmp
log_step "Gophish ${GOPHISH_VERSION} indiriliyor..."
if wget -q --show-progress "${GOPHISH_URL}"; then
    log_success "Gophish başarıyla indirildi"
else
    log_error "Gophish indirilemedi"
    exit 1
fi

# Zip dosyasını çıkar ve /opt/gophish dizinine kur
mkdir -p /opt/gophish
log_step "Gophish çıkarılıyor..."
if unzip -q gophish-${GOPHISH_VERSION}-linux-64bit.zip -d /opt/gophish; then
    log_success "Gophish başarıyla çıkarıldı"
else
    log_error "Gophish çıkarılamadı"
    exit 1
fi

# Geçici dosyayı temizle
rm -f /tmp/gophish-${GOPHISH_VERSION}-linux-64bit.zip

# Gophish binary'sinin varlığını kontrol et
if [ ! -f "/opt/gophish/gophish" ]; then
    log_error "Gophish binary dosyası bulunamadı"
    exit 1
fi

# Gophish kullanıcısı oluştur
useradd -r -s /bin/false gophish || true

# Log dizini oluştur
mkdir -p /var/log/gophish

# Gophish konfigürasyon dosyası
cd /opt/gophish
cat > config.json << EOF
{
	"admin_server": {
		"listen_url": "0.0.0.0:92",
		"use_tls": true,
		"cert_path": "gophish_admin.crt",
		"key_path": "gophish_admin.key",
		"trusted_origins": []
	},
	"phish_server": {
		"listen_url": "0.0.0.0:91",
		"use_tls": false,
		"cert_path": "example.crt",
		"key_path": "example.key"
	},
	"db_name": "sqlite3",
	"db_path": "gophish.db",
	"migrations_prefix": "db/db_",
	"contact_address": "",
	"logging": {
		"filename": "",
		"level": ""
	}
}
EOF

# İzinleri ayarla
chown -R gophish:gophish /opt/gophish /var/log/gophish
chmod +x /opt/gophish/gophish

# Gophish admin panel için self-signed SSL sertifikası oluştur
log_step "Gophish admin panel SSL sertifikası oluşturuluyor..."
cd /opt/gophish
openssl req -newkey rsa:2048 -nodes -keyout gophish_admin.key -x509 -days 365 -out gophish_admin.crt -subj "/C=US/ST=State/L=City/O=Organization/CN=${DOMAIN}"

# SSL sertifikalarının sahipliğini ayarla
chown gophish:gophish gophish_admin.key gophish_admin.crt
chmod 600 gophish_admin.key
chmod 644 gophish_admin.crt

# Port 80 ve 443 için gerekli yetkiyi ver (düşük portlara bind olabilmek için)
setcap cap_net_bind_service=+ep /opt/gophish/gophish

# Systemd service dosyası oluştur
cat > /etc/systemd/system/gophish.service << EOF
[Unit]
Description=Gophish is an open-source phishing toolkit
Documentation=https://getgophish.com/documentation/
After=network.target
Wants=network.target

[Service]
Type=simple
User=gophish
Group=gophish
WorkingDirectory=/opt/gophish
Environment=HOME=/opt/gophish
Environment=STDOUT=/var/log/gophish/gophish.log
Environment=STDERR=/var/log/gophish/gophish.log
ExecStart=/bin/sh -c "/opt/gophish/gophish >>\${STDOUT} 2>>\${STDERR}"
Restart=on-failure
RestartSec=5s
StandardOutput=append:/var/log/gophish/gophish.log
StandardError=append:/var/log/gophish/gophish.log

[Install]
WantedBy=multi-user.target
Alias=gophish.service
EOF

# 11. OpenDKIM sorunlarını çöz
log_step "11. OpenDKIM sorunları düzeltiliyor..."

# OpenDKIM'i durdur
systemctl stop opendkim || true

# Socket dosyasını ve klasörünü temizle
rm -rf /var/spool/postfix/opendkim/*
rm -f /var/run/opendkim/opendkim.sock

# Socket klasörünü yeniden oluştur
mkdir -p /var/spool/postfix/opendkim
mkdir -p /var/run/opendkim
chown opendkim:postfix /var/spool/postfix/opendkim
chown opendkim:opendkim /var/run/opendkim

# OpenDKIM konfigürasyonunu kontrol et
if ! opendkim -n -f /etc/opendkim.conf; then
    log_error "OpenDKIM konfigürasyonunda hata var"
else
    log_success "OpenDKIM konfigürasyonu doğru"
fi

# OpenDKIM'i başlat
systemctl start opendkim
systemctl enable opendkim

# OpenDKIM başlayana kadar bekle
sleep 3

if systemctl is-active --quiet opendkim; then
    log_success "OpenDKIM başarıyla başlatıldı"
else
    log_error "OpenDKIM başlatılamadı, manuel kontrol gerekli"
    journalctl -xeu opendkim.service --no-pager -n 20
fi

# Postfix'i yeniden başlat
systemctl restart postfix
systemctl enable postfix

# Gophish servisini başlat
log_step "Gophish servisi başlatılıyor..."
systemctl daemon-reload

if systemctl start gophish; then
    log_success "Gophish servisi başarıyla başlatıldı"
    systemctl enable gophish
    log_success "Gophish servisi otomatik başlatma için etkinleştirildi"
else
    log_error "Gophish servisi başlatılamadı"
    journalctl -xeu gophish.service --no-pager -n 10
fi

# Servislerin durumunu kontrol et
sleep 5

# 12. Test ve bilgilendirme
log_step "12. Kurulum tamamlandı!"
echo ""
log_success "Postfix ve OpenDKIM başarıyla kuruldu ve yapılandırıldı."
echo ""
echo -e "${YELLOW}=== YAPILMASI GEREKENLER ===${NC}"
echo ""
echo -e "${BLUE}1. DNS Kayıtları:${NC}"
echo ""
echo -e "${GREEN}A Kaydı:${NC}"
echo -e "   Adı: mail"
echo -e "   Değer: $(curl -s ifconfig.me 2>/dev/null || echo 'SUNUCU_IP_ADRESI')"
echo ""
echo -e "${GREEN}MX Kaydı:${NC}"
echo -e "   Adı: @"
echo -e "   Değer: ${MAIL_HOSTNAME}"
echo -e "   Öncelik: 10"
echo ""
echo -e "${GREEN}SPF Kaydı (TXT):${NC}"
echo -e "   Adı: @"
echo -e "   Değer: v=spf1 mx ~all"
echo ""
echo -e "${GREEN}DKIM Kaydı (TXT):${NC}"
echo -e "   Adı: default._domainkey"
echo -e "   Değer:"
echo ""
echo -n -e "${YELLOW}"
cat /etc/opendkim/keys/${DOMAIN}/default.txt | sed 's/.*"\(.*\)".*/\1/' | tr -d '\n\t '
echo -e "${NC}"
echo ""
echo ""
echo -e "${GREEN}PTR (Reverse DNS) Kaydı:${NC}"
echo -e "   IP: $(curl -s ifconfig.me 2>/dev/null || echo 'SUNUCU_IP_ADRESI')"
echo -e "   Değer: ${MAIL_HOSTNAME}"
echo ""
echo -e "${RED}=== DNS KAYITLARINI GİRİN ===${NC}"
echo -e "${YELLOW}Yukarıdaki DNS kayıtlarını domain yöneticinize (Cloudflare) girin.${NC}"
echo -e "${YELLOW}DNS kayıtlarının yayılması birkaç dakika sürebilir.${NC}"
echo ""
read -p "DNS kayıtlarını girip propagation'ı beklediniz mi? (y/N): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log_step "DNS kayıtları kontrol ediliyor..."
    
    # DKIM test
    log_step "DKIM kaydı test ediliyor..."
    if opendkim-testkey -d ${DOMAIN} -s default -vvv 2>&1 | grep -q "key OK"; then
        log_success "DKIM kaydı doğru şekilde ayarlanmış"
    else
        log_warning "DKIM kaydı henüz doğrulanamadı, lütfen birkaç dakika bekleyip manuel kontrol edin"
    fi
    
    # MX test
    log_step "MX kaydı test ediliyor..."
    if dig +short MX ${DOMAIN} | grep -q "${MAIL_HOSTNAME}"; then
        log_success "MX kaydı doğru şekilde ayarlanmış"
    else
        log_warning "MX kaydı bulunamadı veya henüz yayılmadı"
    fi
    
    # SPF test
    log_step "SPF kaydı test ediliyor..."
    if dig +short TXT ${DOMAIN} | grep -q "spf1"; then
        log_success "SPF kaydı doğru şekilde ayarlanmış"
    else
        log_warning "SPF kaydı bulunamadı veya henüz yayılmadı"
    fi
else
    log_warning "DNS kayıtlarını girdikten sonra script'i yeniden çalıştırabilirsiniz"
fi
echo ""
echo -e "${BLUE}3. Gophish Erişimi:${NC}"
echo ""
echo -e "${GREEN}Admin Panel:${NC}"
if [ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
    echo -e "   URL: https://${DOMAIN}/login"
else
    echo -e "   URL: http://${DOMAIN}/login"
    log_warning "SSL sertifikası yok, HTTP kullanılıyor"
fi
echo -e "   Direkt Erişim (Port 92): https://${DOMAIN}:92"
echo -e "   İlk giriş için şifre terminalde görünecek veya log'larda:"
echo -e "   journalctl -u gophish -f | grep 'Please login with'"
echo ""
echo -e "${GREEN}Gophish Servis Yönetimi:${NC}"
echo -e "   Başlat: systemctl start gophish"
echo -e "   Durdur: systemctl stop gophish"
echo -e "   Yeniden başlat: systemctl restart gophish"
echo -e "   Durum: systemctl status gophish"
echo ""
echo -e "${BLUE}4. SSL Sertifika Yenileme:${NC}"
echo -e "   certbot renew --dry-run"
echo ""
echo ""
echo -e "${GREEN}DKIM Test:${NC}"
echo -e "   opendkim-testkey -d ${DOMAIN} -s default -vvv"
echo ""
echo -e "${GREEN}Test Mail Gönderimi:${NC}"
echo -e '   echo "Test mesajı" | mailx -s "Test" -r "test@'${DOMAIN}'" test@mail-tester.com'
echo ""
echo -e "${GREEN}Gmail Test:${NC}"
echo -e '   echo "Gmail test" | mailx -s "Gmail Test" -r "support@'${DOMAIN}'" hedef@gmail.com'
echo ""
echo ""
echo -e "${YELLOW}=== NOTLAR ===${NC}"
echo -e "• DNS kayıtlarının yayılması 24 saate kadar sürebilir"
echo -e "• PTR kaydı için cloud provider ayarlarını kontrol edin"
echo -e "• mail-tester.com ile email score testini yapın"
echo -e "• Konfigürasyon dosyaları yedeklendi (.backup uzantısı ile)"
echo ""
echo -e "${YELLOW}=== İLAVE NOTLAR ===${NC}"
echo -e "• Gophish admin panel TLS ile güvenli (port 92)"
echo -e "• Phishing server HTTP (port 91)"
echo -e "• Gophish ilk şifresi terminal çıktısında görünecek"
echo -e "• SSL sertifikası otomatik yenilenecek"
echo -e "• Nginx reverse proxy olarak Gophish'i yönlendiriyor"
echo -e "• Tüm servisler sistem başlangıcında otomatik başlayacak"

# Son kontroller
log_step "Tüm servislerin durumları kontrol ediliyor..."
if systemctl is-active --quiet postfix; then
    log_success "Postfix servisi çalışıyor"
else
    log_error "Postfix servisi çalışmıyor"
fi

if systemctl is-active --quiet opendkim; then
    log_success "OpenDKIM servisi çalışıyor"
else
    log_error "OpenDKIM servisi çalışmıyor"
fi

if systemctl is-active --quiet nginx; then
    log_success "Nginx servisi çalışıyor"
else
    log_error "Nginx servisi çalışmıyor"
fi

if systemctl is-active --quiet gophish; then
    log_success "Gophish servisi çalışıyor"
else
    log_error "Gophish servisi çalışmıyor"
fi

if systemctl is-active --quiet ssh; then
    log_success "SSH servisi çalışıyor"
else
    log_error "SSH servisi çalışmıyor"
fi

echo ""
log_success "Kurulum scripti tamamlandı!"
echo -e "${GREEN}Sistem yeniden başlatıldıktan sonra hostname değişiklikleri tam olarak aktif olacak.${NC}"
echo ""
read -p "Sistemi şimdi yeniden başlatmak istiyor musunuz? (y/N): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log_step "Sistem yeniden başlatılıyor..."
    reboot
fi
