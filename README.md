# 🛡️ WebAuditAgent v1.0

**WebAuditAgent** — bu web-saytlardagi xavfsizlik zaifliklarini avtomatik aniqlaydigan, tahlil qiladigan va xalqaro standartlarga mos interaktiv hisobotlar (HTML/PDF) yaratadigan zamonaviy skanerlash va audit tizimi. Ushbu loyiha kiberxavfsizlik va axborot xavfsizligi yo'nalishidagi bitiruv diplom ishi moduli sifatida ishlab chiqilgan.

---

## ❓ Loyiha nima va u nima uchun kerak?

Zamonaviy web-ilovalarga qilinayotgan hujumlar kun sayin ortib bormoqda. Web-sayt xavfsizligini qo'lda tekshirish ko'p vaqt va yuqori malaka talab etadi. **WebAuditAgent** ushbu jarayonni avtomatlashtiradi:
- **Tizimli va tezkor audit:** Saytning umumiy xavfsizlik holatini bir necha daqiqada baholaydi.
- **OWASP Top 10 mosligi:** SQL Injection, XSS, CSRF, ochiq konfiguratsiyalar va boshqa jiddiy zaifliklarni aniqlaydi.
- **Tayyor Remediation (Tuzatish yo'riqnomasi):** Topilgan har bir xato uchun dasturchilarga uni qanday yopish bo'yicha tayyor kod parchalari va xavfsiz sozlamalarni taqdim etadi.
- **31 ta ixtisoslashgan asbob:** Tarmoq, DNS, SSL/TLS, HTTP headerlari va ma'lumotlar oshkor bo'lishi kabi yo'nalishlarda chuqur tekshiruv olib boradi.

---

## 🛠️ O'rnatish va Sozlash

Loyiha Python 3.11+ muhitida ishlaydi.

### 1. Loyihani yuklab olish va virtual muhit yaratish:
```bash
git clone https://github.com/sh0dmonov/cyberscan.git
cd cyberscan
python -m venv venv
venv\Scripts\activate      # Windows uchun
source venv/bin/activate    # Linux/macOS uchun
```

### 2. Kutubxonalarni o'rnatish:
```bash
pip install -r requirements.txt
```

### 3. Tashqi dasturlar (Wrapperlar uchun ixtiyoriy):
Portlarni va SSL protokollarini chuqur skanerlash uchun tizimingizga quyidagilarni o'rnating:
- **Nmap:** [Nmap Download](https://nmap.org/download.html) sahifasidan yuklab olib o'rnating va `PATH` ga qo'shing.
- **sslyze:** `pip install sslyze` orqali virtual muhitga o'rnatiladi.
*(Agar bu dasturlar o'rnatilmasa, tizim crash bo'lmaydi, faqat tegishli modullarni o'tkazib yuboradi).*

---

## 🚀 Ishlatish yo'riqnomasi

Dastur ikki xil rejimda ishlaydi: **CLI (Terminal)** va **Web UI (Grafik interfeys)**.

### A. CLI (Terminal) orqali skanerlash
Eng tez va qulay usul. Skanerlash yakunlangach, natijalar `reports/` papkasida HTML hisobot shaklida saqlanadi.

```bash
# Oddiy skanerlash:
python scan.py scan --url https://example.com

# Ruxsatnomani avtomatik tasdiqlash (--yes) va chuqur skanerlash:
python scan.py scan --url https://example.com --depth deep --yes

# PDF formatida ham saqlash (weasyprint talab etiladi):
python scan.py scan --url https://example.com --format html --format pdf
```

### B. Web UI (Grafik Dashboard)
Vizual boshqaruv paneli va real vaqtda skanerlash progressini kuzatish uchun:

```bash
# Serverni ishga tushirish:
python -m uvicorn ui.main:app --host 127.0.0.1 --port 8000 --reload
```
Brauzerda oching: **[http://localhost:8000](http://localhost:8000)**

---

## 🔍 Tizimdagi 31 ta ixtisoslashgan Skaner modullari

Skanerlash to'liq modulli (plugin) arxitekturaga ega bo'lib, quyidagi 31 ta mustaqil tekshiruvni o'z ichiga oladi:

1. **CMS/Tech Fingerprint:** Web-sayt foydalanayotgan CMS (WordPress, Joomla, Laravel, Django, React va h.k.) aniqlaydi.
2. **Robots.txt Parser:** `robots.txt` dagi maxfiy va Disallow qilingan yo'llarni tahlil qiladi.
3. **Sitemap Analyzer:** `sitemap.xml` tarkibini va umumiy sayt xaritasini o'rganadi.
4. **DNS SPF Auditor:** Email spoofing (domen nomidan soxta xat yuborish) dan himoyalanganlikni tekshiradi.
5. **DNS DMARC Auditor:** Phishing hujumlariga qarshi DMARC siyosati mavjudligini audit qiladi.
6. **DNS MX Checker:** Pochta serverlarining mavjudligi va xavfsizligini aniqlaydi.
7. **DNS Zone Transfer (AXFR):** DNS server konfiguratsiyasidagi jiddiy zaifliklarni tekshiradi.
8. **CSP Header Audit:** XSS va Data Injection hujumlaridan himoya qiluvchi Content-Security-Policy headerini tekshiradi.
9. **HSTS Header Audit:** HTTPS ulanishni majburlovchi Strict-Transport-Security headerini audit qiladi.
10. **X-Frame-Options Audit:** Sayt iframe ichiga olinishi (Clickjacking) xavfini tekshiradi.
11. **X-Content-Type Audit:** MIME-sniffing hujumlaridan himoya headerini tekshiradi.
12. **Referrer-Policy Audit:** Tashqi havolalarga o'tganda ma'lumot sizib chiqishini tekshiradi.
13. **Permissions-Policy Audit:** Kamera, mikrofon kabi brauzer imkoniyatlarini cheklashni tekshiradi.
14. **Server Banner Auditor:** Server nomi va versiyasi oshkor bo'layotganini audit qiladi.
15. **X-Powered-By Auditor:** Dasturlash tili yoki framework ma'lumoti sizib chiqishini tekshiradi.
16. **SSL Certificate Auditor:** SSL sertifikat muddati, CA ishonchliligi va validligini tahlil qiladi.
17. **SSL Protocol Auditor:** Eskirgan, zaif SSLv2, SSLv3, TLS 1.0, TLS 1.1 protokollari mavjudligini aniqlaydi.
18. **.env File Exposure:** Maxfiy parollar va API kalitlar saqlanadigan `.env` fayli ochiqligini tekshiradi.
19. **.git Folder Exposure:** `.git/config` fayli ochiqligini va butun kod bazasi sizib chiqishi xavfini aniqlaydi.
20. **Backup Archives Exposure:** `.zip`, `.tar.gz`, `.sql` kabi ma'lumotlar bazasi va kod zaxiralari ochiqligini tekshiradi.
21. **PHPInfo Exposure:** PHP sozlamalarini oshkor qiluvchi `phpinfo.php` fayllari ommaga ochiqligini audit qiladi.
22. **PHPMyAdmin Exposure:** PHPMyAdmin kirish paneli ochiqligini tekshiradi.
23. **Swagger API Exposure:** API endpointlarini oshkor qiluvchi Swagger va OpenAPI hujjatlarini tekshiradi.
24. **Spring Boot Actuator:** Actuator endpointlari orqali tizim ma'lumotlari sizib chiqishini audit qiladi.
25. **CORS Policy Auditor:** CORS wildcard origin (`*`) va credentials sozlamalari xatolarini tekshiradi.
26. **Reflected XSS Injector:** Input maydonlariga payload kiritib, Reflected XSS zaifligini tekshiradi.
27. **Error-based SQLi:** SQL xato xabarlari orqali SQL Injection xavfini aniqlaydi.
28. **Boolean-based Blind SQLi:** TRUE va FALSE so'rovlar orqali Blind SQL Injection zaifligini tekshiradi.
29. **CSRF Form Token Auditor:** POST formalarida CSRF himoya tokenlari mavjudligini tahlil qiladi.
30. **Cookie Security Flags:** Cookie fayllarida `HttpOnly`, `Secure` va `SameSite` flaglari to'g'ri o'rnatilganini tekshiradi.
31. **Nmap Port Scanner:** Nishondagi ochiq tarmoq portlari va faol xizmatlar ro'yxatini aniqlaydi.

---

## 📊 Hisobotning afzalliklari

Yaratiladigan hisobot `reports/` papkasida HTML formatda saqlanadi va quyidagi imkoniyatlarga ega:
- **Interactive Severity Filters:** Zaifliklarni xavfliligi bo'yicha (Critical, High, Medium, Low) birgina klavish orqali tezkor filtrlash (JavaScript orqali).
- **Proportion Bar Chart:** Xatolar taqsimotini ko'rsatuvchi 100% offline ishlaydigan chiroyli horizontal diagramma.
- **Batafsil ma'lumotlar:** Har bir xato uchun xalqaro CVSS 3.1 balli, CWE kodi, aniq topilgan dalil (Evidence), Proof of Concept (PoC) va tuzatish yechimlari.

---

## ⚠️ HUQUQIY VA ETIK OGOHLANTIRISH (Disclaimer)

> **MUHIM:** Ushbu dastur faqat kiberxavfsizlik sohasidagi tadqiqotlar, xavfsizlik auditlari va ruxsat olingan (authorized) tizimlarni tekshirish uchun mo'ljallangan. Dasturni ruxsatisiz boshqa shaxslarning tizimlarida ishlatish qonunan taqiqlanadi va jinoiy javobgarlikka sabab bo'lishi mumkin. Dasturdan noto'g'ri foydalanish natijasida kelib chiqadigan har qanday oqibatlar uchun dastur mualliflari javobgar emas.
