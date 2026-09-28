# اجرای Agent در Ubuntu WSL با Ollama ویندوز

Agent فرمان‌ها را داخل Ubuntu اجرا می‌کند؛ Ollama ویندوز فقط مدل را اجرا می‌کند.
برای استفاده از مدل محلی به کلید OpenAI نیاز نیست.

## ۱. مدل نصب‌شده را بررسی کن

در PowerShell ویندوز:

```powershell
ollama list
ollama show qwen3-coder:30b
```

مدل انتخابی باید قابلیت `tools` داشته باشد و در حافظه سیستم جا شود.
`qwen3-coder:30b` یک نمونه است؛ در صورت انتخاب مدل دیگر، نام دقیق آن را در
`LLM_MODEL` قرار بده. اگر فرمان `ollama` در PATH نیست، مسیر معمول نصب ویندوز:

```powershell
& "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" list
```

## ۲. فایل تنظیمات همان نصب را ویرایش کن

وارد پوشه‌ای شو که `main.py` را از آن اجرا می‌کنی، مثلاً:

```bash
cd "$HOME/server-agent"
nano .env
```

این سه مقدار را تنظیم کن و مقدار معتبر `AGENT_WEB_TOKEN` را نگه دار:

```dotenv
LLM_API_KEY=ollama
LLM_BASE_URL=http://127.0.0.1:11434/v1
LLM_MODEL=qwen3-coder:30b
```

`ollama` مقدار جایگزین کلید API محلی است؛ توکن ورود داشبورد تنظیم جداگانه‌ای است.
پسوند `/v1` را حذف نکن. آدرس با `/api` یا `/v1/chat/completions` جایگزین نشود؛
برنامه مسیر درخواست را خودش به آدرس پایه اضافه می‌کند.

اگر پروژه را در چند مسیر نصب کرده‌ای، هر مسیر فایل `.env` خودش را دارد.
برای نمونه، فایل نسخه روی `/mnt/c/...` تنظیمات `/root/server-agent` را تغییر نمی‌دهد.
سرویس systemd تنظیمات را از `/etc/server-agent.env` می‌خواند.

## ۳. خطای توکن را رفع کن

اگر خطای زیر دیده می‌شود:

```text
Set AGENT_WEB_TOKEN to a random secret of at least 32 characters.
```

در پوشه همان نصب این فرمان را اجرا کن. فقط توکن غایب، کوتاه یا placeholder
جایگزین می‌شود؛ توکن معتبر فعلی و تنظیمات دیگر حفظ می‌شوند:

```bash
.venv/bin/python - <<'PY'
from pathlib import Path
import secrets
from dotenv import dotenv_values, set_key

path = Path('.env')
if not path.is_file():
    raise SystemExit('First create .env from .env.ollama.example and configure it.')
token = dotenv_values(path).get('AGENT_WEB_TOKEN') or ''
if len(token) < 32 or token.startswith('CHANGE_ME'):
    set_key(str(path), 'AGENT_WEB_TOKEN', secrets.token_urlsafe(48), quote_mode='never')
    print('Dashboard token generated; value kept in .env.')
else:
    print('Existing valid token preserved.')
path.chmod(0o600)
PY
```

برای دیدن توکن روی ترمینال خودت:

```bash
grep '^AGENT_WEB_TOKEN=' .env
```

فقط مقدار بعد از `=` را در Access token داشبورد وارد کن. آن را در چت، issue یا
مخزن منتشر نکن. اگر مقدار قدیمی را در shell با `export` تنظیم کرده‌ای، پیش از
اجرای دستی برنامه `unset AGENT_WEB_TOKEN` بزن تا مقدار فایل خوانده شود.

## ۴. اتصال WSL به Ollama را بررسی کن

Ollama ویندوز را باز نگه دار. داخل Ubuntu:

```bash
curl --max-time 10 http://127.0.0.1:11434/v1/models
```

اگر فهرست مدل‌ها برمی‌گردد، اتصال برقرار است و نیازی به تغییر شبکه نیست.
اگر WSL در حالت NAT است، localhost لینوکس معمولاً به Ollama ویندوز وصل نمی‌شود.

در Windows 11 22H2 یا جدیدتر با WSL به‌روز، می‌توان از mirrored networking استفاده کرد.
فایل `%USERPROFILE%\.wslconfig` را در ویندوز باز کن و این تنظیم را در بخش
`[wsl2]` اضافه یا اصلاح کن؛ سایر تنظیمات موجود را حفظ کن:

```ini
[wsl2]
networkingMode=mirrored
```

پس از ذخیره کارهای باز، در PowerShell اجرا کن. `wsl --shutdown` همه پردازش‌های
در حال اجرای WSL را متوقف می‌کند:

```powershell
wsl --shutdown
wsl -d Ubuntu-26.04
```

اگر نام توزیعت متفاوت است، نام صحیح را از `wsl --list --verbose` بگیر.
سپس تست `curl` را داخل Ubuntu تکرار کن. لازم نیست برای این روش Ollama را
روی همه آدرس‌های شبکه با `0.0.0.0` منتشر کنی یا فایروال را غیرفعال کنی.

اگر از قبل یک آدرس خصوصی قابل‌دسترسی برای Ollama داری، همان میزبان را با
پسوند `/v1` استفاده کن؛ آدرس IP هر سیستم متفاوت است. دسترسی به این endpoint
باید به محیط مورد اعتماد محدود باشد، چون مقدار `LLM_API_KEY=ollama` احراز هویت
واقعی ایجاد نمی‌کند.

## ۵. اجرا

داخل پوشه نصب:

```bash
.venv/bin/python main.py
```

در مرورگر ویندوز `http://127.0.0.1:8000` را باز کن، توکن را وارد کن و Connect بزن.
برای تست بپرس: «میزان مصرف RAM این Ubuntu را بررسی کن.»

اگر از systemd استفاده می‌کنی، سه تنظیم مدل را در فایل فعال سرویس قرار بده:

```bash
sudo nano /etc/server-agent.env
sudo systemctl restart server-agent
sudo journalctl -u server-agent -n 50 --no-pager
```

فهرست‌شدن مدل‌ها فقط دسترسی API را تأیید می‌کند؛ اجرای درخواست در داشبورد،
تست واقعی پاسخ مدل و tool calling است. بارگذاری اولیه مدل بزرگ ممکن است از
مهلت درخواست بیشتر طول بکشد؛ می‌توان مدل را ابتدا در Ollama بارگذاری کرد یا
یک مدل کوچک‌تر دارای ابزار انتخاب کرد.

برای اجرای دائمی از سرویس با کاربر محدود مطابق README استفاده کن. تأیید در
داشبورد دسترسی root ایجاد نمی‌کند.

## منابع

- [رابط سازگار Ollama با OpenAI](https://docs.ollama.com/api/openai-compatibility)
- [قابلیت فراخوانی ابزار در Ollama](https://docs.ollama.com/capabilities/tool-calling)
- [شبکه WSL و حالت mirrored](https://learn.microsoft.com/en-us/windows/wsl/networking)
