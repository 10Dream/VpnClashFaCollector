import os
import re
import base64
import logging
import html
import json
import copy
import shutil
import requests
from urllib.parse import urlparse, parse_qs
from datetime import datetime

# ==========================================
# تنظیمات لاگ‌گیری حرفه‌ای (Professional Logging)
# ==========================================
class CustomFormatter(logging.Formatter):
    grey = "\x1b[38;20m"
    green = "\x1b[32;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format_str = "%(asctime)s - [%(levelname)s] - %(message)s"

    FORMATS = {
        logging.DEBUG: grey + format_str + reset,
        logging.INFO: green + format_str + reset,
        logging.WARNING: yellow + format_str + reset,
        logging.ERROR: red + format_str + reset,
        logging.CRITICAL: bold_red + format_str + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt='%Y-%m-%d %H:%M:%S')
        return formatter.format(record)

logger = logging.getLogger("Extractor")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setFormatter(CustomFormatter())
logger.addHandler(ch)

# ==========================================
# تنظیمات کاربر (لینک‌های جهت تقسیم‌بندی)
# ==========================================
SPLIT_SOURCES = [
    {
        'url': 'https://raw.githubusercontent.com/10ium/VpnClashFaCollector/main/sub/tested/ping_passed.txt',
        'name': 'ping_passed',
        'chunk_size': 500
    },
    {
        'url': 'https://raw.githubusercontent.com/10ium/VpnClashFaCollector/main/sub/all/mixed.txt',
        'name': 'mixed',
        'chunk_size': 500
    },
    {
        'url': 'https://raw.githubusercontent.com/10ium/VpnClashFaCollector/main/sub/all/vless.txt',
        'name': 'vless',
        'chunk_size': 500
    },
    {
        'url': 'https://raw.githubusercontent.com/10ium/VpnClashFaCollector/main/sub/all/vmess.txt',
        'name': 'vmess',
        'chunk_size': 500
    },
    {
        'url': 'https://raw.githubusercontent.com/10ium/VpnClashFaCollector/main/sub/all/trojan.txt',
        'name': 'trojan',
        'chunk_size': 500
    },
    {
        'url': 'https://raw.githubusercontent.com/10ium/VpnClashFaCollector/main/sub/all/ss.txt',
        'name': 'ss',
        'chunk_size': 500
    },
]

# ==========================================
# تنظیمات پروتکل‌ها و الگوها
# ==========================================
PROTOCOLS = [
    'vmess', 'vless', 'trojan', 'ss', 'ssr', 'tuic', 'hysteria', 'hysteria2', 
    'hy2', 'juicity', 'snell', 'anytls', 'ssh', 'wireguard', 'wg', 
    'warp', 'socks', 'socks4', 'socks5', 'tg'
]

CLOUDFLARE_DOMAINS = ('.workers.dev', '.pages.dev', '.trycloudflare.com', 'chatgpt.com')

NEXT_CONFIG_LOOKAHEAD = r'(?=' + '|'.join([rf'{p}:\/\/' for p in PROTOCOLS if p != 'tg']) + r'|https:\/\/t\.me\/proxy\?|tg:\/\/proxy\?|[()\[\]"\'\s])'

# ==========================================
# توابع کمکی (Helper Functions)
# ==========================================

def get_flexible_pattern(protocol_prefix):
    if protocol_prefix == 'tg':
        prefix = rf'(?:tg:\/\/proxy\?|https:\/\/t\.me\/proxy\?)'
    else:
        prefix = rf'{protocol_prefix}:\/\/'
    return rf'{prefix}(?:(?!\s{{4,}}|[()\[\]]).)+?(?={NEXT_CONFIG_LOOKAHEAD}|$)'

def clean_telegram_link(link):
    """پاکسازی لینک تلگرام"""
    try:
        link = html.unescape(link)
        link = re.sub(r'[()\[\]\s!.,;\'"]+$', '', link)
        return link
    except Exception as e:
        logger.error(f"Error cleaning link: {e}")
        return link

def is_windows_compatible(link):
    """فیلتر سخت‌گیرانه برای ویندوز (Secret Check)"""
    try:
        secret_match = re.search(r"secret=([a-zA-Z0-9%_\-]+)", link)
        if not secret_match:
            return False
        
        secret = secret_match.group(1).lower()
        
        # 1. ویندوز کاراکترهای خاص را نمی‌خپذیرد
        if '%' in secret or '_' in secret or '-' in secret:
            return False
        # 2. ویندوز سکرت‌های obfuscated (شروع با ee) را پشتیبانی نمی‌کند
        if secret.startswith('ee'):
            return False
        # 3. چک کردن هگزادسیمال بودن
        if secret.startswith('dd'):
            actual_secret = secret[2:]
        else:
            actual_secret = secret
        
        if not re.fullmatch(r'[0-9a-f]{32}', actual_secret):
            return False
            
        return True
    except Exception:
        return False

def is_behind_cloudflare(link):
    """تشخیص کانفیگ‌های پشت کلادفلر"""
    def check_domain(domain):
        if not domain: return False
        domain = domain.lower()
        return domain == "chatgpt.com" or any(domain.endswith(d) for d in CLOUDFLARE_DOMAINS)

    try:
        if not link.startswith('vmess://'):
            parsed = urlparse(link)
            if check_domain(parsed.hostname):
                return True
            query = parse_qs(parsed.query)
            for param in ['sni', 'host', 'peer']:
                values = query.get(param, [])
                if any(check_domain(v) for v in values):
                    return True
            return False
        else:
            # دیکد کردن Vmess
            b64_str = link[8:]
            missing_padding = len(b64_str) % 4
            if missing_padding: b64_str += '=' * (4 - missing_padding)
            try:
                decoded = base64.b64decode(b64_str).decode('utf-8')
                data = json.loads(decoded)
                for field in ['add', 'host', 'sni']:
                    if check_domain(data.get(field)):
                        return True
            except:
                return False
    except:
        return False
    return False

def save_content(directory, filename, content_list):
    """ذخیره محتوا در فایل متنی و Base64"""
    if not content_list: 
        return
    
    try:
        os.makedirs(directory, exist_ok=True)
        content_sorted = sorted(list(set(content_list)))
        content_str = "\n".join(content_sorted)
        
        # ذخیره فایل عادی
        file_path = os.path.join(directory, f"{filename}.txt")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content_str)
        
        # ذخیره فایل Base64
        b64_str = base64.b64encode(content_str.encode("utf-8")).decode("utf-8")
        b64_path = os.path.join(directory, f"{filename}_base64.txt")
        with open(b64_path, "w", encoding="utf-8") as f:
            f.write(b64_str)
            
    except Exception as e:
        logger.error(f"Failed to save {filename} in {directory}: {e}")

def extract_configs_from_text(text):
    """استخراج تمام کانفیگ‌ها از متن"""
    patterns = {p: get_flexible_pattern(p) for p in PROTOCOLS}
    extracted_data = {k: set() for k in PROTOCOLS}
    
    count = 0
    for proto, pattern in patterns.items():
        matches = re.finditer(pattern, text, re.MULTILINE | re.IGNORECASE)
        for match in matches:
            raw_link = match.group(0).strip()
            clean_link = clean_telegram_link(raw_link) if proto == 'tg' else raw_link
            if clean_link:
                extracted_data[proto].add(clean_link)
                count += 1
    
    return extracted_data, count

def merge_hysteria(data_map):
    """ترکیب hy2 و hysteria2"""
    hy2_combined = set()
    if 'hysteria2' in data_map: hy2_combined.update(data_map['hysteria2'])
    if 'hy2' in data_map: hy2_combined.update(data_map['hy2'])
    
    processed_map = copy.deepcopy(data_map)
    if 'hy2' in processed_map: del processed_map['hy2']
    processed_map['hysteria2'] = hy2_combined
    return processed_map

def write_files_standard(data_map, output_dir):
    """
    نوشتن فایل‌های خروجی با جداسازی دقیق تلگرام.
    - tg_windows: فقط سازگار با دسکتاپ
    - tg_android: فقط ناسازگار با دسکتاپ (بدون اشتراک با بالا)
    - tg: همه موارد (میکس)
    """
    final_map = merge_hysteria(data_map)
    
    if not any(final_map.values()): 
        logger.debug(f"No configs to write for {output_dir}")
        return

    os.makedirs(output_dir, exist_ok=True)
    
    mixed_content = set()
    cloudflare_content = set()
    
    for proto, lines in final_map.items():
        if not lines: continue
        
        if proto != 'tg':
            # پردازش عادی سایر پروتکل‌ها
            mixed_content.update(lines)
            for line in lines:
                if is_behind_cloudflare(line):
                    cloudflare_content.add(line)
            save_content(output_dir, proto, lines)
        
        else:
            # --- منطق جداسازی تلگرام ---
            windows_tg = set()
            android_tg = set()
            
            for link in lines:
                if is_windows_compatible(link):
                    windows_tg.add(link)
                else:
                    android_tg.add(link)
            
            # ذخیره فایل‌ها
            save_content(output_dir, "tg_windows", windows_tg) # فقط ویندوز
            save_content(output_dir, "tg_android", android_tg) # فقط اندروید
            save_content(output_dir, "tg", lines)              # میکس (شامل همه)
            
            logger.info(f"Telegram Configs in {output_dir}: Total={len(lines)}, Win={len(windows_tg)}, Android={len(android_tg)}")
            
    if mixed_content:
        save_content(output_dir, "mixed", mixed_content)
    if cloudflare_content:
        save_content(output_dir, "cloudflare", cloudflare_content)

def auto_base64_all(directory):
    """تولید Base64 برای تمام فایل‌های متنی موجود"""
    if not os.path.exists(directory): return
    logger.info(f"Running Auto-Base64 on: {directory}")
    
    count = 0
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".txt") and not file.endswith("_base64.txt"):
                name_without_ext = file[:-4]
                base64_name = f"{name_without_ext}_base64.txt"
                if base64_name not in files:
                    try:
                        file_path = os.path.join(root, file)
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = f.read()
                        if content.strip():
                            b64_data = base64.b64encode(content.encode("utf-8")).decode("utf-8")
                            with open(os.path.join(root, base64_name), "w", encoding="utf-8") as f:
                                f.write(b64_data)
                            count += 1
                    except Exception as e:
                        logger.error(f"Auto-base64 error for {file}: {e}")
    logger.info(f"Generated {count} missing base64 files.")

def cleanup_legacy_hy2(directory):
    """حذف فایل‌های قدیمی hy2"""
    if not os.path.exists(directory): return
    deleted_count = 0
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file == "hy2.txt" or file == "hy2_base64.txt":
                try:
                    os.remove(os.path.join(root, file))
                    deleted_count += 1
                except Exception as e:
                    logger.error(f"Error deleting {file}: {e}")
    if deleted_count > 0:
        logger.info(f"Cleaned up {deleted_count} legacy hy2 files.")

def fetch_url_content(url):
    """دانلود محتوا از اینترنت"""
    try:
        logger.info(f"Fetching URL: {url}")
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        return response.text
    except Exception as e:
        logger.error(f"Failed to fetch {url}: {e}")
        return ""

def save_split_output(config_list, base_name, chunk_size):
    """ذخیره فایل‌های تقسیم‌بندی شده"""
    if not config_list:
        logger.warning(f"No configs found for split source: {base_name}")
        return
    
    unique_configs = sorted(list(set(config_list)))
    total_configs = len(unique_configs)
    
    path_normal = os.path.join("sub", "split", "normal", base_name)
    path_base64 = os.path.join("sub", "split", "base64", base_name)
    
    os.makedirs(path_normal, exist_ok=True)
    os.makedirs(path_base64, exist_ok=True)
    
    chunks = [unique_configs[i:i + chunk_size] for i in range(0, total_configs, chunk_size)]
    
    logger.info(f"Splitting '{base_name}': {total_configs} configs into {len(chunks)} parts.")
    
    for idx, chunk in enumerate(chunks):
        file_number = str(idx + 1)
        content_str = "\n".join(chunk)
        b64_str = base64.b64encode(content_str.encode("utf-8")).decode("utf-8")
        
        with open(os.path.join(path_normal, file_number), "w", encoding="utf-8") as f:
            f.write(content_str)
            
        with open(os.path.join(path_base64, file_number), "w", encoding="utf-8") as f:
            f.write(b64_str)

def process_split_mode():
    """اجرای حالت تقسیم‌بندی"""
    if not SPLIT_SOURCES:
        return

    logger.info("==========================================")
    logger.info("       STARTING SPLIT MODE PROCESS        ")
    logger.info("==========================================")
    
    for item in SPLIT_SOURCES:
        url = item.get('url')
        name = item.get('name')
        chunk_size = item.get('chunk_size', 50)
        
        if not url or not name: continue
        
        content = fetch_url_content(url)
        if content:
            extracted, count = extract_configs_from_text(content)
            merged_data = merge_hysteria(extracted)
            
            all_configs = []
            for proto, lines in merged_data.items():
                if proto != 'tg': 
                    all_configs.extend(lines)
            
            save_split_output(all_configs, name, chunk_size)

def main():
    logger.info("Starting Config Extractor...")
    
    # --- بخش 1: پردازش پوشه تلگرام ---
    src_dir = "src/telegram"
    out_dir = "sub"
    global_collection = {k: set() for k in PROTOCOLS}
    
    logger.info("==========================================")
    logger.info("      PROCESSING TELEGRAM DIRECTORY       ")
    logger.info("==========================================")

    if os.path.exists(src_dir):
        channels = os.listdir(src_dir)
        logger.info(f"Found {len(channels)} items in {src_dir}")
        
        for channel_name in channels:
            channel_path = os.path.join(src_dir, channel_name)
            
            # تغییر کلیدی در این قسمت انجام شد: استفاده از فایل txt به جای md
            txt_file = os.path.join(channel_path, "messages.txt")
            
            if not os.path.isfile(txt_file):
                # برای اطمینان از سازگاری با فایل‌های قدیمی که هنوز حذف نشده‌اند
                md_fallback = os.path.join(channel_path, "messages.md")
                if os.path.isfile(md_fallback):
                    txt_file = md_fallback
                else:
                    continue
                
            try:
                with open(txt_file, "r", encoding="utf-8") as f:
                    content = f.read()
                
                channel_data, count = extract_configs_from_text(content)
                logger.info(f"Channel: {channel_name} -> Found {count} configs")
                
                # اضافه کردن به کالکشن کلی
                for p, s in channel_data.items():
                    global_collection[p].update(s)
                
                # نوشتن فایل کانال
                write_files_standard(channel_data, os.path.join(out_dir, channel_name))
                
            except Exception as e:
                logger.error(f"Error processing channel {channel_name}: {e}")
        
        # نوشتن فایل All نهایی
        total_global = sum(len(v) for v in global_collection.values())
        if total_global > 0:
            logger.info(f"Writing Global Collection (Total: {total_global} configs)...")
            write_files_standard(global_collection, os.path.join(out_dir, "all"))
        else:
            logger.warning("Global collection is empty! No configs found in telegram folder.")
            
    else:
        logger.error(f"Source directory not found: {src_dir}")
        logger.error("Skipping Telegram processing. Check if 'src/telegram' exists.")
    
    # --- بخش 2: پردازش لینک‌های اسپلیت ---
    process_split_mode()

    # --- بخش 3: نهایی‌سازی و پاکسازی ---
    logger.info("==========================================")
    logger.info("           FINALIZING OUTPUTS             ")
    logger.info("==========================================")
    auto_base64_all(out_dir)
    cleanup_legacy_hy2(out_dir)
    
    logger.info("Job Completed Successfully.")

if __name__ == "__main__":
    main()
