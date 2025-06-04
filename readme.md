# 🚀 جعبه‌‌ابزار مدیریت سرور (Server-Toolkit)

> **یک منوی تعاملی برای انجام سریع کارهای ضروری سرور**  
> ریپو: **https://github.com/mpxss/server-toolkit**  
> لایسنس: **MIT**

![banner](https://raw.githubusercontent.com/mpxss/server-toolkit/main/docs/assets/banner.png)

---

## 🧐 چرا از این ابزار استفاده کنم؟

| 🛠️ مشکل رایج | ✨ راهکار Server-Toolkit |
|--------------|--------------------------|
| تغییر دستیِ مکرر DNS، وب‌سرور، یا پورت SSH | یک منو → انتخاب شماره → اجرای خودکار + گزارش ✅/❌ |
| فراموش‌کردن همگام‌سازی ساعت سرور یا گرفتن بک‌آپ | گزینهٔ «System Settings» → همه در یکجا |
| نیاز به بک‌آپ امن روی تلگرام/دیسکورد/ایمیل | ویزارد بک‌آپ Bash با رمز‌گذاری و کران‌جاب |

---

## ✨ امکانات (یک نگاه کلی)

| 🎛️ ماژول | قابلیت‌ها |
|----------|-----------|
| **Network** 🌐 | 🔸 سوییچ DNS (Google, Cloudflare, …)<br>🔸 نصب Unbound (کش DNS)<br>🔸 تست سرعت `bench.sh` |
| **System Settings** ⚙️ | 🔸 همگام‌سازی ساعت (NTP)<br>🔸 اطلاعات توزیع (`lsb_release -a`)<br>🔸 مانیتور زنده (`htop`)<br>🔸 ویزارد بک‌آپ خودکار |
| **Security** 🔒 | 🔸 تغییر پورت SSH + باز شدن UFW<br>🔸 فعال/غیرفعال کردن Ping<br>🔸 گواهی SSL (Self-Signed, Certbot)<br>🔸 وضعیت UFW & Fail2Ban |
| **Webserver** 🕸️ | 🔸 نصب/ری‌استارت/توقف **Nginx** و **Apache**<br>🔸 ساخت سریع v-host با یک سؤال |

---

## ⏱️ راه‌اندازی سریع (۳ دقیقه!)

```bash
# 1) بسته‌های پایه روی سرور (Ubuntu 20.04+)
sudo apt update && sudo apt install git python3 python3-pip -y

# 2) کلون ریپو
git clone https://github.com/mpxss/server-toolkit.git
cd server-toolkit

# 3) نصب وابستگی پایتونی (فقط requests)
pip3 install --user -r requirements.txt

# 4) اجرای منو (نیاز به sudo)
sudo ./cli_menu.py
```

> 💡 **اولین اجرا** ممکن است چند بستهٔ کمبود (مثل `htop`, `zip`) را نصب کند؛ منتظر ✅ بمانید.

---

## 🖥️ پیش‌‌نمایش منو اصلی

```text
############################################
               SERVER INFO
IP      : 203.0.113.5
ISP     : Example ISP
Country : DE
############################################
MAIN MENU
1) Network 🌐
2) System Settings ⚙️
3) Security 🔒
4) Webserver 🕸️
0) Exit
```

> اعداد فارسی هم قبول می‌شوند؛ پس از هر عملیات نتیجه‌ی (✅ موفق / ❌ خطا) چاپ می‌شود.

---

## 📚 راهنمای کامل (گام‌به‌گام)

<details>
<summary>👀 باز / بسته کردن</summary>

### ۱) Network 🌐
| # | شرح |
|---|-----|
| 1 | **DNS** → چهار سرویس؛ با انتخاب، `resolv.conf` قفل می‌شود. |
| 2 | **Unbound** → نصب، کانفیگ، تست و ری‌لود خودکار. |
| 3 | **Speed-Test** → اجرای `wget -qO- bench.sh | bash`. |

### ۲) System Settings ⚙️
| # | شرح |
|---|-----|
| 1 | همگام‌سازی NTP + `ntpdate`. |
| 2 | اطلاعات توزیع لینوکس. |
| 3 | اجرای `htop` (اگر نبود نصب می‌کند). |
| 4 | ویزارد بک‌آپ؛ در انتها کران‌جاب می‌سازد. |

### ۳) Security 🔒
| # | شرح |
|---|-----|
| 1 | تغییر پورت SSH + بازشدن پورت جدید در UFW. |
| 2 | فعال/غیرفعال‌کردن Ping. |
| 3 | ساخت گواهی Self-Signed یا گرفتن Let’s Encrypt. |
| 4 | نمایش UFW و Fail2Ban. |

### ۴) Webserver 🕸️
| # | شرح |
|---|-----|
| 1–4 | نصب/وضعیت/ری‌استارت/توقف **Nginx**. |
| 5–8 | همان موارد برای **Apache**. |
| 9 | ساخت v-host در Nginx (sites-available). |
| 10 | ساخت v-host در Apache (a2ensite). |

</details>

---

## 💾 بک‌آپ خودکار (Wizard)

1. به مسیر **System Settings → Backup** بروید.  
2. *Remark* (نام بک‌آپ) + بازهٔ زمانی دقیقه‌ای + مقصد (تلگرام/دیسکورد/ایمیل) را وارد کنید.  
3. اسکریپت `/root/_<remark>_backuper_script.sh` ساخته و کران‌جاب افزوده می‌شود.  
4. اولین بک‌آپ همان لحظه آپلود خواهد شد.

> برای حذف همهٔ بک‌آپ‌ها: دوباره وارد و گزینه «Remove All Backupers» را بزنید.

---

## 🔄 به‌روزرسانی پروژه

```bash
cd ~/server-toolkit
git pull                       # دریافت آخرین نسخه
sudo ./cli_menu.py             # منوی جدید
```

> ⚠️ اگر روی سرور اصلی کار می‌کنید، قبل از Pull یک بک‌آپ بگیرید.

---

## 🤝 مشارکت در توسعه

1. ریپو را **Fork** کنید.  
2. شاخهٔ جدید بسازید: `git checkout -b feat/my-feature`.  
3. تغییر دهید → `git add` → `git commit -m "feat: ..."`.  
4. **Pull Request** بدهید.

ایده‌های ساده برای شروع:
* پشتیبانی از RHEL/Fedora (dnf) در ماژول وب‌سرور 🔧
* افزودن تست‌های خودکار با **pytest** 🧪
* رابط وب کوچک مبتنی بر Flask 🌐

---

## ⚖️ لایسنس

کد تحت مجوز **MIT** منتشر شده است. استفاده، فورک و ستاره ⭐ آزاد!
