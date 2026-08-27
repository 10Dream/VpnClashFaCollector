import os
import re
import yaml
import requests
import logging
import time
from bs4 import BeautifulSoup
from datetime import datetime, timedelta, timezone

# تنظیمات لاگر حرفه‌ای
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# الگوی شناسایی کانفیگ‌های پروکسی در پیام‌ها
PROXY_PATTERN = re.compile(
    r'(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|wireguard|warp|dnst|dnstt|vaydns|slipstream|stormdns|cottendns|masterdns|masterdnsvpn|noizdns|slowdns|ssh-dns|dns-ssh|ssh-over-dns|whitedns|slipnet|slipnet-enc)://[^\s"\'<>`]+|tg://(?:proxy|socks)\?[^\s"\'<>`]+|https://t\.me/(?:proxy|socks)\?[^\s"\'<>`]+',
    re.IGNORECASE
)

def load_settings():
    try:
        if not os.path.exists('config/settings.yaml'):
            logger.warning("فایل تنظیمات یافت نشد، از مقادیر پیش‌فرض استفاده می‌شود.")
            return {
                'scraping': {'lookback_days': 2, 'max_pages': 30, 'inactive_days': 7}, 
                'storage': {'base_path': 'src/telegram'}
            }
        with open('config/settings.yaml', 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"خطا در بارگذاری تنظیمات: {e}")
        return {
            'scraping': {'lookback_days': 2, 'max_pages': 30, 'inactive_days': 7}, 
            'storage': {'base_path': 'src/telegram'}
        }

def load_channels():
    if not os.path.exists('config/channels.txt'):
        logger.error("فایل config/channels.txt یافت نشد!")
        return []
    try:
        usernames = []
        with open('config/channels.txt', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    username = line.split('/')[-1].replace('@', '').split('?')[0].strip()
                    if username and username not in usernames:
                        usernames.append(username)
        return usernames
    except Exception as e:
        logger.error(f"خطا در خواندن فایل کانال‌ها: {e}")
        return []

def html_to_md(element):
    if not element: return ""
    try:
        for b in element.find_all('b'): b.replace_with(f"**{b.get_text()}**")
        for i in element.find_all('i'): i.replace_with(f"*{i.get_text()}*")
        for code in element.find_all('code'): code.replace_with(f"`{code.get_text()}`")
        for a in element.find_all('a'):
            href = a.get('href', '')
            a.replace_with(f"[{a.get_text()}]({href})")
        return element.get_text(separator='\n').strip()
    except Exception:
        return element.get_text().strip()

def validate_channel_response(username, response_text, status_code):
    """
    بررسی سلامت و معتبر بودن کانال تلگرام
    خروجی: (is_valid: bool, reason: str)
    """
    if status_code == 404:
        return False, "Channel not found (HTTP 404)"
    if status_code in {400, 403, 410}:
        return False, f"Channel inaccessible (HTTP {status_code})"
    
    soup = BeautifulSoup(response_text, 'lxml')
    page_text = soup.get_text()
    
    if f"Channel with username @{username} was not found" in page_text or f"@{username} was not found" in page_text:
        return False, "Channel username not found"
        
    if soup.find('i', class_='tgme_icon_user'):
        return False, "Username belongs to a personal user account, not a public channel"
        
    if "If you have Telegram, you can contact" in page_text or "You can contact @" in page_text:
        return False, "Account is private or does not support public channel preview"
        
    channel_info = soup.find('div', class_='tgme_channel_info')
    page_title = soup.find('div', class_='tgme_page_title')
    messages = soup.find_all('div', class_='tgme_widget_message')
    
    if not channel_info and not page_title and not messages:
        return False, "No public channel preview available"
        
    return True, "Valid"

def scrape_channel(username, lookback_days, max_pages, base_path, current_idx, total_channels):
    logger.info(f"[{current_idx}/{total_channels}] شروع پردازش کانال: @{username}")
    
    channel_dir = os.path.join(base_path, username)
    os.makedirs(channel_dir, exist_ok=True)
    
    time_threshold = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    all_messages = []
    last_msg_id = None
    reached_end = False
    pages_fetched = 0
    channel_is_valid = True
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }

    # حلقه اسکرپینگ با محدودیت زمانی و محدودیت تعداد صفحات
    while not reached_end and pages_fetched < max_pages:
        url = f"https://t.me/s/{username}"
        if last_msg_id:
            url += f"?before={last_msg_id}"
        
        try:
            pages_fetched += 1
            logger.info(f"    در حال دریافت صفحه {pages_fetched} از حداکثر {max_pages} برای @{username}...")
            
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 429:
                logger.warning(f"    محدودیت نرخ (Rate Limit) توسط تلگرام! ۵ ثانیه صبر می‌کنیم...")
                time.sleep(5)
                pages_fetched -= 1 # کسر کردن صفحه چون با موفقیت دریافت نشد
                continue
                
            # در صفحه اول، اعتبار و در دسترس بودن کانال بررسی می‌شود
            if pages_fetched == 1:
                is_val, reason = validate_channel_response(username, response.text, response.status_code)
                if not is_val:
                    logger.warning(f"⚠️ کانال @{username} نامعتبر یا دیلیت‌شده تشخیص داده شد ({reason}).")
                    channel_is_valid = False
                    break

            if response.status_code != 200:
                logger.error(f"    خطا در اتصال به @{username}: کد وضعیت {response.status_code}")
                break

            soup = BeautifulSoup(response.text, 'lxml')
            messages = soup.find_all('div', class_='tgme_widget_message')
            
            if not messages:
                logger.info(f"    پیامی در این بخش از تاریخچه @{username} یافت نشد.")
                break

            for msg in reversed(messages):
                msg_id_attr = msg.get('data-post')
                if msg_id_attr:
                    last_msg_id = msg_id_attr.split('/')[-1]

                time_element = msg.find('time', class_='time')
                if not time_element: continue
                
                msg_date = datetime.fromisoformat(time_element.get('datetime').replace('Z', '+00:00'))
                
                if msg_date < time_threshold:
                    logger.info(f"    به حد زمانی تعیین شده ({lookback_days} روز) رسیدیم.")
                    reached_end = True
                    break
                
                text_area = msg.find('div', class_='tgme_widget_message_text')
                content = html_to_md(text_area) if text_area else ""
                
                # استخراج دکمه‌های شیشه‌ای (Inline Keyboard Buttons)
                inline_buttons = msg.find_all('a', class_='tgme_widget_message_inline_button')
                btn_links = []
                for btn in inline_buttons:
                    btn_text = btn.get_text().strip()
                    btn_href = btn.get('href', '').strip()
                    if btn_href:
                        btn_links.append(f"[{btn_text}]({btn_href})")
                        
                if btn_links:
                    content = (content + "\n\n" + " | ".join(btn_links)).strip()
                    
                # استخراج لینک‌های پیش‌نمایش (Link Previews)
                preview_link = msg.find('a', class_='tgme_widget_message_link_preview')
                if preview_link and preview_link.get('href'):
                    content = (content + f"\n\n[Link Preview]({preview_link.get('href')})").strip()
                
                if content:
                    is_forwarded = msg.find('div', class_='tgme_widget_message_forwarded_from')
                    all_messages.append({
                        'date': msg_date,
                        'content': content,
                        'forwarded': is_forwarded is not None
                    })
            
            # چک کردن اینکه آیا به سقف تعداد صفحات رسیده‌ایم یا خیر
            if pages_fetched >= max_pages and not reached_end:
                logger.warning(f"    به سقف مجاز صفحات ({max_pages} صفحه) رسیدیم. توقف اسکرپینگ برای @{username}.")
                break

            if not reached_end:
                time.sleep(1.5) # وقفه ایمن برای جلوگیری از بلاک

        except Exception as e:
            logger.error(f"    خطای غیرمنتظره در پردازش صفحه: {e}")
            break

    if all_messages:
        # حذف تکراری‌ها و ذخیره
        unique_messages = []
        seen = set()
        for m in all_messages:
            identifier = f"{m['date']}_{m['content'][:50]}"
            if identifier not in seen:
                unique_messages.append(m)
                seen.add(identifier)

        try:
            # پاکسازی فایل‌های md قدیمی
            old_md_file = os.path.join(channel_dir, "messages.md")
            if os.path.exists(old_md_file):
                os.remove(old_md_file)

            # ذخیره با فرمت txt
            with open(os.path.join(channel_dir, "messages.txt"), "w", encoding="utf-8") as f:
                f.write(f"# آرشیو کانال: @{username}\n")
                f.write(f"بروزرسانی: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n")
                for m in unique_messages:
                    f.write(f"### 🕒 {m['date'].strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
                    if m['forwarded']: f.write(f"> ↪️ **Forwarded**\n\n")
                    f.write(f"{m['content']}\n\n---\n\n")
            logger.info(f"✅ موفقیت: {len(unique_messages)} پیام جدید برای @{username} ذخیره شد.")
        except Exception as e:
            logger.error(f"❌ خطا در نوشتن فایل برای @{username}: {e}")
    else:
        if channel_is_valid:
            logger.warning(f"⚠️ هیچ پیامی پیدا نشد.")

    return channel_is_valid

def analyze_and_reorder_channels(base_path="src/telegram", channels_file="config/channels.txt", inactive_days=7, removed_channels=None):
    """
    بررسی تاریخ آخرین پروکسی در پیام‌های هر کانال،
    حذف کانال‌های نامعتبر،
    انتقال کانال‌های غیرفعال بالای ۷ روز به انتهای channels.txt
    و تولید گزارش اختصاصی در sub/inactive_sources.txt و config/inactive_channels.txt
    """
    if not os.path.exists(channels_file):
        logger.error(f"فایل {channels_file} یافت نشد.")
        return
        
    with open(channels_file, "r", encoding="utf-8") as f:
        raw_lines = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        
    current_channels = []
    for line in raw_lines:
        uname = line.split('/')[-1].replace('@', '').split('?')[0].strip()
        if uname and uname not in current_channels:
            if not removed_channels or uname not in removed_channels:
                current_channels.append(uname)
                
    now = datetime.now(timezone.utc)
    active_list = []
    inactive_list = []
    
    msg_date_pattern = re.compile(r'###\s*🕒\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*UTC')
    
    for uname in current_channels:
        msg_file = os.path.join(base_path, uname, "messages.txt")
        latest_proxy_dt = None
        
        if os.path.exists(msg_file):
            try:
                with open(msg_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    
                sections = content.split("---")
                for sec in sections:
                    if PROXY_PATTERN.search(sec):
                        date_match = msg_date_pattern.search(sec)
                        if date_match:
                            try:
                                dt = datetime.strptime(date_match.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                                if latest_proxy_dt is None or dt > latest_proxy_dt:
                                    latest_proxy_dt = dt
                            except Exception:
                                pass
            except Exception as e:
                logger.warning(f"خطا در بررسی پیام‌های @{uname}: {e}")
                
        if latest_proxy_dt:
            diff_days = (now - latest_proxy_dt).days
            if diff_days <= inactive_days:
                active_list.append((uname, diff_days, latest_proxy_dt))
            else:
                inactive_list.append((uname, diff_days, latest_proxy_dt))
        else:
            # کانالی که هنوز هیچ پروکسی در آرشیو آن یافت نشده است
            inactive_list.append((uname, 999, None))
            
    # مرتب‌سازی کانال‌های غیرفعال بر اساس بیشترین روز عدم فعالیت
    inactive_list.sort(key=lambda x: x[1], reverse=True)
    
    # بازنویسی مجدد فایل config/channels.txt
    with open(channels_file, "w", encoding="utf-8") as f:
        f.write("# =========================================================================\n")
        f.write("# لیست منابع کانال‌های تلگرام (بروزرسانی خودکار بر اساس سلامت و فعالیت)\n")
        f.write(f"# تاریخ بروزرسانی: {now.strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"# کانال‌های فعال (انتشار پروکسی در {inactive_days} روز اخیر): {len(active_list)}\n")
        f.write(f"# کانال‌های غیرفعال (عدم انتشار پروکسی در بیش از {inactive_days} روز): {len(inactive_list)}\n")
        if removed_channels:
            f.write(f"# کانال‌های حذف‌شده (دیلیت/لینک خراب/خصوصی): {len(removed_channels)}\n")
        f.write("# =========================================================================\n\n")
        
        f.write("# --- کانال‌های فعال (Active Sources) ---\n")
        for u, d, dt in active_list:
            f.write(f"@{u}\n")
            
        if inactive_list:
            f.write(f"\n# --- کانال‌های غیرفعال بیش از {inactive_days} روز (Inactive Sources - انتهای لیست) ---\n")
            for u, d, dt in inactive_list:
                f.write(f"@{u}\n")
                
    # تولید گزارش متنی کانال‌های غیرفعال
    report_lines = [
        "# =========================================================================",
        f"# گزارش کانال‌های غیرفعال تلگرام (عدم انتشار پروکسی در بیش از {inactive_days} روز اخیر)",
        f"# تاریخ بروزرسانی: {now.strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"# تعداد کل کانال‌های غیرفعال: {len(inactive_list)}",
        "# =========================================================================\n"
    ]
    
    for u, d, dt in inactive_list:
        if dt:
            dt_str = dt.strftime('%Y-%m-%d %H:%M UTC')
            report_lines.append(f"@{u:<25} | ⏳ {d} روز بدون پروکسی جدید | آخرین پروکسی: {dt_str}")
        else:
            report_lines.append(f"@{u:<25} | ⏳ نامشخص (هیچ پروکسی در آرشیو یافت نشد) | آخرین پروکسی: یافت نشد")
            
    report_text = "\n".join(report_lines) + "\n"
    
    with open("config/inactive_channels.txt", "w", encoding="utf-8") as f:
        f.write(report_text)
        
    os.makedirs("sub", exist_ok=True)
    with open("sub/inactive_sources.txt", "w", encoding="utf-8") as f:
        f.write(report_text)
        
    logger.info(f"📊 پایان پایش سلامت منابع: {len(active_list)} فعال | {len(inactive_list)} غیرفعال (> {inactive_days} روز) | {len(removed_channels or [])} کانال نامعتبر حذف شد.")

def main():
    start_time = time.time()
    logger.info("🚀 شروع فرآیند اسکرپینگ و غربالگری کانال‌های تلگرام...")
    
    settings = load_settings()
    usernames = load_channels()
    
    if not usernames:
        logger.error("لیست کانال‌ها خالی است. عملیات متوقف شد.")
        return

    scraping_cfg = settings.get('scraping', {})
    lookback_days = scraping_cfg.get('lookback_days', 2)
    max_pages = scraping_cfg.get('max_pages', 30)
    inactive_days = scraping_cfg.get('inactive_days', 7)
    base_path = settings.get('storage', {}).get('base_path', 'src/telegram')
    
    total = len(usernames)
    removed_channels = set()
    
    for idx, username in enumerate(usernames, 1):
        is_valid = scrape_channel(username, lookback_days, max_pages, base_path, idx, total)
        if not is_valid:
            removed_channels.add(username)
            logger.info(f"❌ کانال @{username} از لیست منابع حذف شد.")
            
        if idx < total:
            time.sleep(2)

    # پایش سلامت، مرتب‌سازی و ثبت کانال‌های غیرفعال بالای ۷ روز
    analyze_and_reorder_channels(base_path=base_path, channels_file="config/channels.txt", inactive_days=inactive_days, removed_channels=removed_channels)

    duration = round(time.time() - start_time, 2)
    logger.info(f"🏁 عملیات با موفقیت به پایان رسید. زمان کل: {duration} ثانیه.")

if __name__ == "__main__":
    main()

