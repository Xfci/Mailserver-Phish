#!/bin/bash

# Phishing Test Altyapısı Doğrulama Scripti
# Kullanım: ./check.sh -d domain.com -mt test-xxxxx@srv1.mail-tester.com

set -e

# Renkli output için
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ERRORS=0
WARNINGS=0
SUCCESS=0

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
    ((SUCCESS++))
}

log_warn() {
    echo -e "${YELLOW}[⚠]${NC} $1"
    ((WARNINGS++))
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
    ((ERRORS++))
}

# Parametreleri parse et
while getopts "d:mt:h" opt; do
    case $opt in
        d) DOMAIN="$OPTARG" ;;
        m) 
            if [ "$OPTARG" = "t" ]; then
                shift $((OPTIND-2))
                MAIL_TESTER="$1"
                OPTIND=1
            fi
            ;;
        h) 
            echo "Kullanım: $0 -d domain.com -mt test-xxxxx@srv1.mail-tester.com"
            echo "  -d: Domain adı (örn: test-domain.com)"
            echo "  -mt: Mail-tester email adresi"
            exit 0
            ;;
        \?) 
            log_error "Geçersiz parametre. -h ile yardımı görüntüleyin."
            exit 1
            ;;
    esac
done

# Parametreleri kontrol et
if [ -z "$DOMAIN" ]; then
    log_error "Domain (-d) parametresi zorunludur!"
    echo "Kullanım: $0 -d domain.com -mt test-xxxxx@srv1.mail-tester.com"
    exit 1
fi

echo "============================================"
echo "  Phishing Test Altyapısı Doğrulama"
echo "  Domain: $DOMAIN"
echo "============================================"
echo ""

# 1. Sistem Servisleri Kontrolü
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. SİSTEM SERVİSLERİ KONTROLÜ"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# SSH kontrolü
if systemctl is-active --quiet ssh; then
    log_success "SSH servisi çalışıyor"
else
    log_error "SSH servisi çalışmıyor"
fi

# Postfix kontrolü
if systemctl is-active --quiet postfix; then
    log_success "Postfix servisi çalışıyor"
else
    log_error "Postfix servisi çalışmıyor"
fi

# OpenDKIM kontrolü
if systemctl is-active --quiet opendkim; then
    log_success "OpenDKIM servisi çalışıyor"
else
    log_error "OpenDKIM servisi çalışmıyor"
fi

# Gophish kontrolü
if systemctl is-active --quiet gophish; then
    log_success "Gophish servisi çalışıyor"
else
    log_error "Gophish servisi çalışmıyor"
fi

# Nginx kontrolü
if systemctl is-active --quiet nginx; then
    log_success "Nginx servisi çalışıyor"
else
    log_error "Nginx servisi çalışmıyor"
fi

echo ""

# 2. DNS Kayıtları Kontrolü
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2. DNS KAYITLARI KONTROLÜ"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# A kaydı kontrolü
A_RECORD=$(dig +short $DOMAIN A | head -n1)
if [ -n "$A_RECORD" ]; then
    log_success "A kaydı bulundu: $A_RECORD"
else
    log_error "A kaydı bulunamadı"
fi

# MX kaydı kontrolü
MX_RECORD=$(dig +short $DOMAIN MX | head -n1)
if [ -n "$MX_RECORD" ]; then
    log_success "MX kaydı bulundu: $MX_RECORD"
else
    log_error "MX kaydı bulunamadı"
fi

# SPF kaydı kontrolü
SPF_RECORD=$(dig +short $DOMAIN TXT | grep "v=spf1")
if [ -n "$SPF_RECORD" ]; then
    log_success "SPF kaydı bulundu: $SPF_RECORD"
else
    log_error "SPF kaydı bulunamadı"
fi

# DKIM kaydı kontrolü
DKIM_RECORD=$(dig +short default._domainkey.$DOMAIN TXT | head -n1)
if [ -n "$DKIM_RECORD" ]; then
    log_success "DKIM kaydı bulundu"
else
    log_error "DKIM kaydı bulunamadı"
fi

# DMARC kaydı kontrolü
DMARC_RECORD=$(dig +short _dmarc.$DOMAIN TXT | head -n1)
if [ -n "$DMARC_RECORD" ]; then
    log_success "DMARC kaydı bulundu: $DMARC_RECORD"
else
    log_warn "DMARC kaydı bulunamadı (opsiyonel)"
fi

# PTR (Reverse DNS) kontrolü
if [ -n "$A_RECORD" ]; then
    PTR_RECORD=$(dig +short -x $A_RECORD | head -n1)
    if [[ "$PTR_RECORD" == *"$DOMAIN"* ]]; then
        log_success "Reverse DNS doğru yapılandırılmış: $PTR_RECORD"
    else
        log_warn "Reverse DNS yapılandırması kontrol edilmeli. Bulunan: $PTR_RECORD"
    fi
fi

echo ""

# 3. DKIM Anahtar Testi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3. DKIM ANAHTAR TESTİ"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f "/etc/opendkim/keys/$DOMAIN/default.private" ]; then
    log_success "DKIM private key dosyası mevcut"
    
    # DKIM test
    DKIM_TEST=$(opendkim-testkey -d $DOMAIN -s default -vvv 2>&1)
    if echo "$DKIM_TEST" | grep -q "key OK"; then
        log_success "DKIM anahtarı DNS'de doğru şekilde yayınlanmış"
    else
        log_error "DKIM anahtarı DNS'de bulunamadı veya hatalı"
        echo "$DKIM_TEST" | grep -i "error\|warning" || true
    fi
else
    log_error "DKIM private key dosyası bulunamadı"
fi

echo ""

# 4. Postfix Yapılandırma Kontrolü
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4. POSTFIX YAPILANDIRMA KONTROLÜ"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# myhostname kontrolü
MYHOSTNAME=$(postconf -h myhostname)
if [ "$MYHOSTNAME" = "$DOMAIN" ]; then
    log_success "Postfix myhostname doğru: $MYHOSTNAME"
else
    log_warn "Postfix myhostname farklı: $MYHOSTNAME (Beklenen: $DOMAIN)"
fi

# milter kontrolü
MILTER=$(postconf -h smtpd_milters)
if [[ "$MILTER" == *"opendkim"* ]]; then
    log_success "OpenDKIM milter yapılandırılmış"
else
    log_error "OpenDKIM milter yapılandırması bulunamadı"
fi

echo ""

# 5. Nginx Yapılandırma Kontrolü
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5. NGINX YAPILANDIRMA KONTROLÜ"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Nginx syntax test
if nginx -t 2>&1 | grep -q "successful"; then
    log_success "Nginx yapılandırması geçerli"
else
    log_error "Nginx yapılandırması hatalı"
    nginx -t 2>&1 | tail -n5
fi

# Domain config kontrolü
if [ -f "/etc/nginx/conf.d/$DOMAIN.conf" ]; then
    log_success "Nginx domain config dosyası mevcut"
else
    log_error "Nginx domain config dosyası bulunamadı"
fi

echo ""

# 6. SSL Sertifika Kontrolü
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "6. SSL SERTİFİKA KONTROLÜ"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -d "/etc/letsencrypt/live/$DOMAIN" ]; then
    log_success "Let's Encrypt sertifikası mevcut"
    
    # Sertifika son kullanma tarihi
    CERT_EXPIRY=$(openssl x509 -enddate -noout -in /etc/letsencrypt/live/$DOMAIN/cert.pem | cut -d= -f2)
    log_info "Sertifika son kullanma tarihi: $CERT_EXPIRY"
else
    log_warn "SSL sertifikası bulunamadı. Certbot ile sertifika oluşturun."
fi

# HTTPS bağlantı testi
if timeout 5 curl -sk https://$DOMAIN > /dev/null 2>&1; then
    log_success "HTTPS bağlantısı başarılı"
else
    log_warn "HTTPS bağlantısı başarısız veya SSL sertifikası yok"
fi

echo ""

# 7. Gophish Kontrolleri
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "7. GOPHISH KONTROLLARI"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Gophish binary kontrolü
if [ -f "/root/gophish" ]; then
    log_success "Gophish binary mevcut"
else
    log_error "Gophish binary bulunamadı"
fi

# Gophish config kontrolü
if [ -f "/root/config.json" ]; then
    log_success "Gophish config dosyası mevcut"
    
    # Admin port kontrolü
    ADMIN_PORT=$(grep -o '"listen_url":[^,]*' /root/config.json | head -n1 | grep -o '[0-9]*')
    if netstat -tuln | grep -q ":$ADMIN_PORT "; then
        log_success "Gophish admin paneli $ADMIN_PORT portunda dinliyor"
    else
        log_warn "Gophish admin paneli $ADMIN_PORT portunda dinlemiyor"
    fi
    
    # Phish port kontrolü
    PHISH_PORT=$(grep -o '"listen_url":[^,]*' /root/config.json | tail -n1 | grep -o '[0-9]*')
    if netstat -tuln | grep -q ":$PHISH_PORT "; then
        log_success "Gophish phishing servisi $PHISH_PORT portunda dinliyor"
    else
        log_error "Gophish phishing servisi $PHISH_PORT portunda dinlemiyor"
    fi
else
    log_error "Gophish config dosyası bulunamadı"
fi

echo ""

# 8. Port Kontrolleri
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "8. PORT KONTROLLARI"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Port 25 (SMTP)
if netstat -tuln | grep -q ":25 "; then
    log_success "Port 25 (SMTP) açık"
else
    log_error "Port 25 (SMTP) kapalı"
fi

# Port 80 (HTTP)
if netstat -tuln | grep -q ":80 "; then
    log_success "Port 80 (HTTP) açık"
else
    log_error "Port 80 (HTTP) kapalı"
fi

# Port 443 (HTTPS)
if netstat -tuln | grep -q ":443 "; then
    log_success "Port 443 (HTTPS) açık"
else
    log_warn "Port 443 (HTTPS) kapalı (SSL kurulumu yapılmamış olabilir)"
fi

echo ""

# 9. Mail Tester ile Test
if [ -n "$MAIL_TESTER" ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "9. MAIL-TESTER İLE TEST"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    log_info "Test maili gönderiliyor: $MAIL_TESTER"
    
    if echo "Bu bir test mailidir. Phishing test altyapısı doğrulama scripti tarafından gönderildi." | mailx -s "Phishing Test - Doğrulama" -r "test@$DOMAIN" "$MAIL_TESTER" 2>/dev/null; then
        log_success "Test maili başarıyla gönderildi"
        log_info "Mail-tester.com'da sonuçları kontrol edin"
    else
        log_error "Test maili gönderilemedi"
    fi
    
    # Mail log kontrolü
    sleep 2
    if tail -n 50 /var/log/mail.log | grep -q "$MAIL_TESTER"; then
        log_success "Mail log'larında gönderim kaydı bulundu"
    else
        log_warn "Mail log'larında gönderim kaydı bulunamadı"
    fi
    
    echo ""
fi

# 10. Log Dosyaları Kontrolü
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "10. LOG DOSYALARI KONTROLÜ"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Postfix log
if tail -n 20 /var/log/mail.log | grep -qi "error\|fatal"; then
    log_warn "Postfix log'larında hata mesajları var"
    echo "Son hatalar:"
    tail -n 20 /var/log/mail.log | grep -i "error\|fatal" | tail -n 5
else
    log_success "Postfix log'larında kritik hata yok"
fi

# OpenDKIM log
if tail -n 20 /var/log/mail.log | grep -i "opendkim" | grep -qi "error\|fatal"; then
    log_warn "OpenDKIM log'larında hata mesajları var"
else
    log_success "OpenDKIM log'larında kritik hata yok"
fi

# Nginx log
if [ -f "/var/log/nginx/error.log" ]; then
    if tail -n 20 /var/log/nginx/error.log | grep -qi "error"; then
        log_warn "Nginx log'larında hata mesajları var"
    else
        log_success "Nginx log'larında kritik hata yok"
    fi
fi

echo ""
echo "============================================"
echo "  ÖZET"
echo "============================================"
echo -e "${GREEN}Başarılı: $SUCCESS${NC}"
echo -e "${YELLOW}Uyarı: $WARNINGS${NC}"
echo -e "${RED}Hata: $ERRORS${NC}"
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✓ Tüm kontroller başarılı! Sistem kullanıma hazır.${NC}"
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠ Bazı uyarılar var ancak sistem çalışır durumda.${NC}"
    exit 0
else
    echo -e "${RED}✗ Kritik hatalar mevcut. Lütfen hataları düzeltin.${NC}"
    echo ""
    echo "Yardım için:"
    echo "  - journalctl -u postfix -n 50"
    echo "  - journalctl -u opendkim -n 50"
    echo "  - journalctl -u gophish -n 50"
    echo "  - tail -f /var/log/mail.log"
    exit 1
fi
