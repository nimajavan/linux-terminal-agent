# راهنمای کامل نصب و راه‌اندازی Sentinel در Ubuntu و WSL

این راهنما نصب از صفر، اتصال به Ollama ویندوز، اجرای داشبورد، سرویس دائمی و رفع خطاهای رایج را پوشش می‌دهد. فرمان‌های این راهنما برای Ubuntu در WSL نوشته شده‌اند؛ به‌جز بخش‌هایی که صریحاً PowerShell نام دارند.

> **دسترسی:** پس از ورود با `AGENT_WEB_TOKEN`، ایجنت هر فرمان Bash را با دسترسی `root` اجرا می‌کند. توکن را مانند رمز عبور root نگه دارید. فرمان‌ها تأیید جداگانه ندارند و هر فرمان حداکثر ۱۲۰ ثانیه زمان اجرا دارد.

## ۱. پیش‌نیازها

- ویندوز با WSL و یک توزیع Ubuntu؛ یا یک سرور Ubuntu برای حالتی که مدل روی همان سرور یا یک میزبان قابل دسترس باشد.
- Python نسخهٔ ۳.۱۴ یا جدیدتر به همراه ماژول `venv`، `git` و `curl` در Ubuntu.
- Ollama نصب‌شده در ویندوز و یک مدل نصب‌شده با قابلیت فراخوانی ابزار (`tools`). نام دقیق مدل را با `ollama list` پیدا کنید. نمونهٔ این راهنما `qwen3-coder:30b` است؛ اگر مدل دیگری دارید نام آن را در `.env` جایگزین کنید.

در PowerShell بررسی کنید:

```powershell
wsl --list --verbose
ollama list
ollama show qwen3-coder:30b
Invoke-RestMethod http://127.0.0.1:11434/api/version
```

اگر مدل نصب نیست، در PowerShell `ollama pull qwen3-coder:30b` را اجرا کنید. دانلود مدل به اینترنت و فضای کافی نیاز دارد. اگر `ollama` در PATH پیدا نشد، از `& "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" list` استفاده کنید. اگر درخواست نسخه در ویندوز هم خطا می‌دهد، ابتدا خود Ollama را اجرا کنید؛ تا وقتی این آزمایش موفق نشده سراغ تنظیمات ایجنت نروید.

در Ubuntu بررسی کنید:

```bash
python3.14 --version
python3.14 -m venv --help
git --version
curl --version
```

اگر Python ۳.۱۴ در توزیع شما موجود نیست، آن را از منبع معتبر مناسب همان نسخهٔ Ubuntu نصب کنید. اسکریپت نصب پروژه Python سیستم را نصب یا جایگزین نمی‌کند.

## ۲. دریافت پروژه و نصب وابستگی‌ها

در ترمینال Ubuntu، با کاربری که می‌خواهید پوشهٔ پروژه را نگه دارد:

```bash
cd "$HOME"
git clone https://github.com/nimajavan/linux-terminal-agent.git linux-terminal-agent
cd linux-terminal-agent
bash setup.sh "$HOME/server-agent"
cd "$HOME/server-agent"
```

`setup.sh` پوشهٔ مقصد خالی را می‌سازد، فایل‌ها را کپی می‌کند، محیط مجازی Python و وابستگی‌ها را نصب می‌کند و توکن تصادفی داشبورد را در `.env` می‌گذارد. اگر پوشهٔ `~/server-agent` از قبل وجود دارد، نصب‌کننده عمداً روی آن نمی‌نویسد. برای به‌روزرسانی نصب موجود، ابتدا از `.env` و تغییرات محلی پشتیبان بگیرید و فایل‌های برنامه را با نسخهٔ مخزن مقایسه و به‌روزرسانی کنید؛ نصب‌کننده را روی همان پوشه دوباره اجرا نکنید.

اگر نصب بسته‌ها به‌دلیل شبکه یا دسترسی به PyPI شکست خورد، ابتدا اتصال اینترنت و DNS خود Ubuntu را بررسی کنید و سپس نصب را در مقصد خالی از نو انجام دهید. برای نصب از سورس، مراحل جایگزین در [README](../README.md) آمده است.

## ۳. اتصال WSL به Ollama ویندوز

ابتدا در Ubuntu این دستور را اجرا کنید:

```bash
curl --fail --show-error --max-time 10 http://127.0.0.1:11434/v1/models
```

اگر JSON حاوی مدل‌ها می‌بینید، آدرس Ollama برای ایجنت `http://127.0.0.1:11434/v1` است. اگر `Connection refused` یا `Could not connect` می‌بینید، نوع شبکهٔ WSL را بررسی کنید. در حالت NAT، `127.0.0.1` داخل Ubuntu همان ویندوز نیست. حتی اگر `http://127.0.0.1:11434/api/version` در PowerShell کار کند، الزاماً از WSL قابل دسترس نیست.

### روش پیشنهادی در Windows 11: شبکهٔ mirrored

در PowerShell فایل `%USERPROFILE%\.wslconfig` را باز کنید، مثلاً با `notepad "$env:USERPROFILE\.wslconfig"`. در بخش `[wsl2]` مقدار زیر را قرار دهید و سایر تنظیمات فایل را حفظ کنید:

```ini
[wsl2]
networkingMode=mirrored
```

**برای اعمال این تغییر باید همهٔ پردازش‌های WSL متوقف شوند.** کارهای باز در Ubuntu را ذخیره کنید و سپس، در زمانی که خودتان انتخاب می‌کنید، در PowerShell اجرا کنید:

```powershell
wsl --shutdown
wsl -d Ubuntu-26.04
```

نام توزیع را با خروجی `wsl --list --verbose` تطبیق دهید. پس از بالا آمدن مجدد Ubuntu، دستور `curl .../v1/models` بالا را تکرار کنید. برای mirrored به Windows 11 22H2 یا جدیدتر و WSL به‌روز نیاز است. اگر WSL همچنان پیام `NAT mode does not support localhost proxies` می‌دهد، بررسی کنید فایل `.wslconfig` واقعاً در پروفایل ویندوز شماست، مقدار `networkingMode=nat` باقی نمانده و WSL بعد از ذخیرهٔ فایل خاموش و دوباره راه‌اندازی شده است.

### اگر از NAT استفاده می‌کنید

Ollama باید روی یک آدرس میزبان ویندوز که از WSL قابل دسترس است گوش کند. تنها تغییر `LLM_BASE_URL` به IP ویندوز کافی نیست اگر Ollama فقط روی `127.0.0.1` ویندوز گوش می‌دهد. آدرس میزبان WSL را با `ip route show default` در Ubuntu پیدا کنید و در PowerShell شنوندهٔ Ollama را با `Get-NetTCPConnection -LocalPort 11434 -State Listen` بررسی کنید. سپس `OLLAMA_HOST` را برای Ollama روی آدرس مناسب تنظیم، Ollama را دوباره اجرا و دسترسی را از Ubuntu با `curl http://IP:11434/v1/models` آزمایش کنید. این روش ممکن است به قاعدهٔ محدود فایروال ویندوز نیاز داشته باشد؛ API Ollama را در شبکهٔ عمومی منتشر نکنید. IP ممکن است پس از راه‌اندازی دوباره تغییر کند، پس آدرس تست‌شده را در `.env` بنویسید. راهنمای رسمی [شبکهٔ WSL](https://learn.microsoft.com/en-us/windows/wsl/networking) جزئیات حالت NAT و mirrored را توضیح می‌دهد.

## ۴. تنظیم فایل `.env`

در همان پوشه‌ای که `main.py` را اجرا می‌کنید:

```bash
cd "$HOME/server-agent"
nano .env
```

مقدارهای زیر را با مدل خود تنظیم کنید. توکن تصادفی ساخته‌شده توسط نصب‌کننده را حفظ کنید:

```dotenv
LLM_API_KEY=ollama
LLM_BASE_URL=http://127.0.0.1:11434/v1
LLM_MODEL=qwen3-coder:30b
SERVER_HOST=127.0.0.1
SERVER_PORT=8000
```

در NAT، به‌جای `127.0.0.1` آدرس میزبان **واقعاً تست‌شده از Ubuntu** را قرار دهید. `LLM_BASE_URL` باید به `/v1` ختم شود؛ برنامه مسیر `/chat/completions` را خودش اضافه می‌کند. `LLM_API_KEY=ollama` فقط مقدار لازم برای کلاینت سازگار OpenAI است و رمز دسترسی داشبورد نیست.

اگر نصب‌کننده را استفاده نکرده‌اید، از `.env.ollama.example` یک `.env` بسازید و توکن تازه تولید کنید:

```bash
cp .env.ollama.example .env
python3.14 -c 'import secrets; print(secrets.token_urlsafe(48))'
chmod 600 .env
```

خروجی تصادفی دستور را به‌جای `AGENT_WEB_TOKEN=CHANGE_ME...` در `.env` بگذارید. برای دیدن توکن نصب موجود، روی ترمینال خودتان `grep '^AGENT_WEB_TOKEN=' .env` را اجرا کنید. توکن را در GitHub، issue یا پیام عمومی قرار ندهید. اگر قبلاً متغیرهایی را با `export` تنظیم کرده‌اید، مقدارهای محیط shell می‌توانند بر `.env` مقدم باشند؛ با `env | grep -E '^(LLM_|AGENT_WEB_TOKEN|SERVER_)'` بررسی کنید و مقدارهای قدیمی را حذف کنید.

## ۵. اجرای دستی و آزمایش

پیش از اجرای برنامه، درخواست مدل را از داخل Ubuntu بررسی کنید:

```bash
curl --fail --show-error --max-time 10 http://127.0.0.1:11434/v1/models
```

آدرس این دستور را با میزبان `LLM_BASE_URL` خود یکسان کنید. سپس:

```bash
cd "$HOME/server-agent"
sudo .venv/bin/python main.py
```

اگر همین حالا `root` هستید، `sudo` لازم نیست. برنامه به‌طور پیش‌فرض روی `127.0.0.1:8000` در Ubuntu گوش می‌دهد. در مرورگر ویندوز `http://127.0.0.1:8000` را باز کنید، مقدار `AGENT_WEB_TOKEN` را در بخش Access token وارد کنید و Connect بزنید. یک آزمایش ساده مانند «با `id -u` شناسهٔ کاربر را نشان بده» انجام دهید؛ خروجی مورد انتظار `0` است.

اگر مرورگر ویندوز به پورت ۸۰۰۰ WSL دسترسی ندارد، یک تونل SSH محلی با پورت آزاد مانند ۹۰۰۰ بسازید:

```powershell
ssh -N -L 9000:127.0.0.1:8000 root@WSL_IP
```

`WSL_IP` را در Ubuntu با `hostname -I` پیدا کنید و سپس `http://127.0.0.1:9000` را باز کنید. SSH server باید در Ubuntu فعال باشد. خطای `bind [127.0.0.1]:8000: Permission denied` هنگام تونل روی ویندوز معمولاً یعنی پورت محلی ۸۰۰۰ قابل استفاده نیست؛ پورت محلی دیگری مانند ۹۰۰۰ انتخاب کنید. پورت مقصد سمت Ubuntu همچنان ۸۰۰۰ است.

برای توقف اجرای دستی، در ترمینال برنامه `Ctrl+C` بزنید.

## ۶. اجرای خودکار با systemd، اختیاری

ابتدا اجرای دستی را آزمایش کنید. فایل سرویس داخل مخزن برای نصب در `/opt/server-agent` نوشته شده است و تنظیمات را از `/etc/server-agent.env` می‌خواند؛ مستقیماً برای پوشهٔ `~/server-agent` مناسب نیست. اگر سرویس می‌خواهید، دستورهای بخش [Install the boot-time service](../README.md#install-the-boot-time-service) را از ریشهٔ مخزن دنبال کنید و سه مقدار Ollama و توکن را در `/etc/server-agent.env` قرار دهید. برای بررسی:

```bash
sudo systemctl status server-agent --no-pager
sudo journalctl -u server-agent -n 100 --no-pager
```

## ۷. رفع خطاهای رایج

- `APIConnectionError` یا پیام `Retrying request`: وب‌اپ بالا آمده ولی درخواست به Ollama نرسیده است. `LLM_BASE_URL` را از `.env` همان نصب بررسی کنید؛ `curl .../v1/models` را **داخل Ubuntu** روی همان آدرس اجرا کنید. اگر Windows localhost پاسخ می‌دهد اما Ubuntu پاسخ نمی‌دهد، بخش شبکهٔ WSL بالا را دنبال کنید. بعد از تغییر `.env` برنامه را دوباره اجرا کنید.
- `Set AGENT_WEB_TOKEN ... at least 32 characters`: `.env` همان مسیری را اصلاح کنید که `main.py` از آن اجرا می‌شود و توکن تصادفی حداقل ۳۲ کاراکتری بگذارید. مقدار `LLM_API_KEY` جایگزین این توکن نمی‌شود.
- صفحه باز نمی‌شود: با `ss -ltnp '( sport = :8000 )'` در Ubuntu شنونده را بررسی کنید؛ آدرس `SERVER_HOST` و `SERVER_PORT` را ببینید. اگر تونل SSH دارید، پورت محلی مرورگر باید با سمت چپ `-L` یکسان باشد.
- پیام دسترسی root: برنامه باید با root اجرا شود. در نصب دستی `sudo .venv/bin/python main.py` بزنید.
- مدل پاسخ متنی شبیه `<function=run_bash_command>` می‌دهد: آخرین نسخهٔ مخزن را نصب کنید؛ نسخهٔ فعلی الگوی کامل Qwen3-Coder را به فراخوانی ابزار تبدیل می‌کند. مدل انتخابی باید `tools` را پشتیبانی کند.
- تأخیر زیاد اولین پاسخ: مدل بزرگ ممکن است برای اولین بار زمان زیادی صرف بارگذاری کند. ابتدا با Ollama مدل را گرم کنید یا یک مدل کوچک‌تر با قابلیت tools انتخاب کنید. محدودیت زمانی درخواست provider در برنامه برقرار است.

## منابع

- [رابط سازگار Ollama با OpenAI](https://docs.ollama.com/api/openai-compatibility)
- [فراخوانی ابزار در Ollama](https://docs.ollama.com/capabilities/tool-calling)
- [شبکهٔ WSL](https://learn.microsoft.com/en-us/windows/wsl/networking)
