import os, subprocess, logging, zipfile, requests, csv, base64, json, sys, re, shutil
from urllib.parse import quote, unquote, urlparse, parse_qs

# تنظیمات لاگ
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("ProxyLab")

# ثوابت و پارامترهای بهینه‌شده برای سرعت، دقت و عدم بلاک در GitHub Actions
PING_THREADS = 50
SPEED_THREADS = 8
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=2000000"  # تست دانلود سبک ۲ مگابایت
SPEED_TIMEOUT = "8000"  # مهلت ۸ ثانیه‌ای برای هر پروکسی
TARGET_SPEED_CONFIGS = 300  # هدف: جمع‌آوری دقیقاً ۳۰۰ کانفیگ با سرعت دانلود فعال
SPEED_BATCH_SIZE = 60  # پردازش دسته‌ای ۶۰تایی برای جلوگیری از مصرف بیهوده منابع

GEMINI_THREADS = 30
GEMINI_URL = "https://gemini.google.com"
GEMINI_TIMEOUT = "6000"
GEMINI_BLOCKED_COUNTRIES = {"IR", "RU", "KP", "CU", "SY"}

SPAM_QUERY_PARAMS = {
    'telegram', 'telegramid', 'channel', 'bia_telegram', 'bia_tel', 'join',
    'sponsor', 'ad', 'ads', 'promo'
}

COUNTRY_FLAGS = {
    'US': '🇺🇸', 'DE': '🇩🇪', 'NL': '🇳🇱', 'GB': '🇬🇧', 'FR': '🇫🇷', 'CA': '🇨🇦',
    'FI': '🇫🇮', 'PL': '🇵🇱', 'RU': '🇷🇺', 'TR': '🇹🇷', 'SG': '🇸🇬', 'JP': '🇯🇵',
    'KR': '🇰🇷', 'HK': '🇭🇰', 'CH': '🇨🇭', 'SE': '🇸🇪', 'NO': '🇳🇴', 'ES': '🇪🇸',
    'IT': '🇮🇹', 'AT': '🇦🇹', 'BG': '🇧🇬', 'CZ': '🇨🇿', 'ZA': '🇿🇦', 'BR': '🇧🇷',
    'LV': '🇱🇻', 'CO': '🇨🇴', 'RO': '🇷🇴', 'IR': '🇮🇷', 'IN': '🇮🇳', 'UA': '🇺🇦'
}

def to_base64(text):
    """تبدیل متن به فرمت بیس۶۴"""
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def normalize_b64(raw):
    """نرمال‌سازی و دیکد متن‌های base64"""
    if not raw:
        return None
    raw = raw.strip().replace('-', '+').replace('_', '/')
    raw += '=' * ((4 - len(raw) % 4) % 4)
    try:
        return base64.b64decode(raw).decode('utf-8', errors='ignore')
    except Exception:
        return None

def get_flag(cc):
    """تبدیل کد کشور به ایموجی پرچم"""
    cc = str(cc).upper()
    if cc in COUNTRY_FLAGS:
        return COUNTRY_FLAGS[cc]
    if len(cc) == 2 and cc.isalpha():
        return "".join(chr(127397 + ord(c)) for c in cc)
    return "🌐"

def get_engine_path():
    """مسیر باینری متناسب با سیستم‌عامل"""
    if sys.platform == "win32":
        return "xray-knife.exe" if os.path.exists("xray-knife.exe") else "xray-knife"
    return "./xray-knife" if os.path.exists("./xray-knife") else "xray-knife"

def download_engine():
    """دانلود موتور xray-knife متناسب با سیستم‌عامل (لینوکس گیت‌هاب اکشن یا ویندوز لوکال)"""
    bin_name = "xray-knife.exe" if sys.platform == "win32" else "xray-knife"
    if os.path.exists(bin_name) or (sys.platform != "win32" and os.path.exists("./xray-knife")):
        return
    
    if sys.platform == "win32":
        url = "https://github.com/lilendian0x00/xray-knife/releases/latest/download/Xray-knife-windows-64.zip"
    else:
        url = "https://github.com/lilendian0x00/xray-knife/releases/latest/download/Xray-knife-linux-64.zip"
        
    try:
        logger.info(f"Downloading xray-knife engine for {sys.platform}...")
        r = requests.get(url, timeout=30)
        with open("engine.zip", "wb") as f:
            f.write(r.content)
        with zipfile.ZipFile("engine.zip", 'r') as z:
            z.extractall("dir")
        for root, _, files in os.walk("dir"):
            for file in files:
                if file.startswith("xray-knife"):
                    target_name = "xray-knife.exe" if sys.platform == "win32" else "xray-knife"
                    if os.path.exists(target_name):
                        try: os.remove(target_name)
                        except Exception: pass
                    os.rename(os.path.join(root, file), target_name)
        if os.path.exists("xray-knife"):
            os.chmod("xray-knife", 0o755)
        if os.path.exists("engine.zip"):
            try: os.remove("engine.zip")
            except Exception: pass
        if os.path.exists("dir"):
            shutil.rmtree("dir", ignore_errors=True)
        logger.info("xray-knife engine ready.")
    except Exception as e:
        logger.error(f"Failed to download engine: {e}")

def get_proxy_core_key(link):
    """تولید کلید یکتا بر اساس سرور، پورت و شناسه احراز هویت برای جلوگیری از تکرار کانفیگ‌ها"""
    if not link:
        return None
    link = link.strip()
    low = link.lower()
    try:
        if low.startswith('vmess://'):
            payload = normalize_b64(link[8:].split('#')[0])
            if not payload: return None
            data = json.loads(payload)
            return ('vmess', str(data.get('add', '')).lower(), int(data.get('port', 0) or 0), str(data.get('id', '')).lower())

        if low.startswith('vless://'):
            u = urlparse(re.sub(r'^vless://', 'http://', link.split('#')[0], flags=re.IGNORECASE))
            return ('vless', (u.hostname or '').lower(), u.port or 0, (u.username or '').lower())

        if low.startswith('trojan://'):
            u = urlparse(re.sub(r'^trojan://', 'http://', link.split('#')[0], flags=re.IGNORECASE))
            return ('trojan', (u.hostname or '').lower(), u.port or 0, u.username or '')

        if low.startswith(('hysteria2://', 'hy2://')):
            u = urlparse(re.sub(r'^(hysteria2|hy2)://', 'http://', link.split('#')[0], flags=re.IGNORECASE))
            return ('hysteria2', (u.hostname or '').lower(), u.port or 0, u.username or '')

        if low.startswith(('wireguard://', 'wg://')):
            u = urlparse(re.sub(r'^(wireguard|wg)://', 'http://', link.split('#')[0], flags=re.IGNORECASE))
            q = parse_qs(u.query)
            pk = u.username or (q.get('publickey') or q.get('public-key') or q.get('privatekey') or [''])[0]
            return ('wireguard', (u.hostname or '').lower(), u.port or 51820, pk)

        if low.startswith('ss://'):
            ss = link[5:].split('#', 1)[0]
            if '@' in ss:
                auth, host_part = ss.split('@', 1)
                auth_decoded = normalize_b64(auth) or auth
            else:
                decoded = normalize_b64(ss)
                if not decoded or '@' not in decoded: return None
                auth_decoded, host_part = decoded.split('@', 1)
            if ':' not in auth_decoded or ':' not in host_part: return None
            method, password = auth_decoded.split(':', 1)
            server, port = host_part.rsplit(':', 1)
            return ('ss', server.lower(), int(port or 0), method, password)
    except Exception:
        return None
    return link.split('#')[0]

def clean_url_spam_params(url):
    """حذف پارامترهای اسپم تبلیغاتی از کوئری کانفیگ"""
    if '?' not in url:
        return url
    try:
        base, query = url.split('?', 1)
        hash_part = ""
        if '#' in query:
            query, hash_part = query.split('#', 1)
            hash_part = '#' + hash_part
            
        params = query.split('&')
        clean_params = []
        for p in params:
            if not p:
                continue
            k = p.split('=', 1)[0].lower()
            if k in SPAM_QUERY_PARAMS or 'telegram' in k or 'channel' in k:
                continue
            if '-----' in p or 'MARAMBASHI' in p or 'NUFiLTER' in p:
                continue
            clean_params.append(p)
            
        new_query = '&'.join(clean_params)
        return f"{base}?{new_query}{hash_part}" if new_query else f"{base}{hash_part}"
    except Exception:
        return url

def clean_remark_text(remark):
    """پاکسازی کامل نام و برچسب کانفیگ از پروتکل‌های چسبیده، تگ‌های قدیمی و متن‌های تبلیغاتی"""
    if not remark:
        return ""
    try:
        remark = unquote(remark)
    except Exception:
        pass
        
    # 1. حذف هرگونه پروتکل چسبیده درون رمارک
    proto_pattern = r'(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|wireguard|wg|socks|socks4|socks5)://[^\s"\'<>`]+'
    remark = re.sub(proto_pattern, '', remark, flags=re.IGNORECASE)
    remark = re.sub(r'(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|wireguard|wg|socks)%3[aA]%2[fF]%2[fF][^\s"\'<>`]+', '', remark, flags=re.IGNORECASE)
    
    # 2. حذف تگ‌های قدیمی تست رنک، پینگ، سرعت و مقادیر null/UN
    remark = re.sub(r'\[\d+\]\s*', '', remark)
    remark = re.sub(r'(?:✨\s*Gemini|\b\d+ms\b|\b\d+(?:\.\d+)?(?:KB|MB)\b|🌐|[🇦-🇿]{2})\s*\|?\s*', '', remark)
    remark = re.sub(r'\b(NULL|null|UN|Global)\b\s*\|?\s*', '', remark)
    
    # 3. استانداردسازی لینک‌های تلگرام درون رمارک
    remark = re.sub(r'(?:⚡️\s*)?Telegram\s*=\s*(?:https?:\/\/)?t\.me\/([A-Za-z0-9_]+)', r'@\1', remark, flags=re.IGNORECASE)
    remark = re.sub(r'https?:\/\/t\.me\/([A-Za-z0-9_]+)', r'@\1', remark, flags=re.IGNORECASE)
    
    # 4. حذف متن‌های تبلیغاتی فارسی/انگلیسی مزاحم
    spam_patterns = [
        r'برای اتصال دائمی جوین شو[^\s]*',
        r'اگه میخوای قطع نشی[^\s]*',
        r'TelegramID[^\s]*',
        r'⌲Express_freevpn[^\s]*',
        r'Free x\d+\s*@\w+',
        r'📍\d+@\w+',
        r'🥈\d+@\w+',
        r'\d+🥈@\w+',
        r'\d+🥇@\w+',
        r'\d+🥉@\w+',
        r'\*+✅\*+',
        r'Channel\s*:\s*',
        r'-----+',
    ]
    for sp in spam_patterns:
        remark = re.sub(sp, '', remark, flags=re.IGNORECASE)
        
    # 5. پاکسازی کاراکترهای جداکننده اضافی
    remark = re.sub(r'\s*\|\s*', ' | ', remark)
    remark = re.sub(r'(?:\s*\|\s*){2,}', ' | ', remark)
    remark = re.sub(r'^[\s|\-_:.,;#]+', '', remark)
    remark = re.sub(r'[\s|\-_:.,;#]+$', '', remark)
    remark = re.sub(r'\s+', ' ', remark).strip()
    
    if remark.lower() in ('server', 'null', 'none', ''):
        return ""
        
    return remark

def rename_config(link, info, rank=None):
    """تغییر نام و برچسب‌گذاری تمیز کانفیگ بر اساس نتایج تست"""
    if not link:
        return ""
    try:
        # 1. پاکسازی پارامترهای اسپم از آدرس کانفیگ
        link = clean_url_spam_params(link)
        
        # 2. تشخیص و تصحیح کد کشور
        cc = (info.get('cc') or '').strip().upper()
        if cc in ('NULL', 'NONE', 'UN', '', 'UNKNOWN'):
            flag_match = re.search(r'([🇦-🇿]{2})', link)
            if flag_match:
                flag_chars = flag_match.group(1)
                try:
                    cc = "".join(chr(ord(c) - 127397) for c in flag_chars).upper()
                except Exception:
                    cc = "UN"
            else:
                cc = "UN"
                
        flag = get_flag(cc) if cc != "UN" else "🌐"
        location_str = cc if cc != "UN" else "Global"
        
        ping = info.get('ping')
        speed = info.get('speed')
        custom_tag = info.get('custom_tag')
        
        tag_parts = []
        if rank:
            tag_parts.append(f"[{rank}]")
        if custom_tag:
            tag_parts.append(custom_tag)
        tag_parts.extend([flag, location_str])
        
        if ping and str(ping) not in ('?', '0', '5000'):
            tag_parts.append(f"{ping}ms")
        elif ping == '5000':
            tag_parts.append("Timeout")
            
        if speed and "Low" not in str(speed):
            tag_parts.append(str(speed))
            
        prefix_tag = " | ".join(tag_parts)
        
        if link.startswith("vmess://"):
            b64_str = link[8:]
            missing_padding = len(b64_str) % 4
            if missing_padding: b64_str += '=' * (4 - missing_padding)
            data = json.loads(base64.b64decode(b64_str).decode('utf-8', errors='ignore'))
            clean_rem = clean_remark_text(data.get('ps', ''))
            data['ps'] = f"{prefix_tag} | {clean_rem}" if clean_rem else prefix_tag
            return "vmess://" + base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
        elif "#" in link:
            base, original_remark = link.split("#", 1)
            clean_rem = clean_remark_text(original_remark)
            final_tag = f"{prefix_tag} | {clean_rem}" if clean_rem else prefix_tag
            return f"{base}#{quote(final_tag)}"
        else:
            return f"{link}#{quote(prefix_tag)}"
    except Exception:
        return link

def test_process(limit_for_test=None):
    """
    اجرای ۳ فاز تست:
    ۱. تست پینگ و تاخیر برای تمام کانفیگ‌ها و مرتب‌سازی از کمترین پینگ
    ۲. تست سرعت دانلود دسته‌ای برای کانفیگ‌های برتر تا رسیدن به ۳۰۰ کانفیگ فعال
    ۳. تست اختصاصی بازگشایی Google Gemini و ساخت ساب مجزا
    """
    input_file = "sub/all/mixed.txt"
    base_dir = "sub/tested"
    raw_dir = os.path.join(base_dir, "raw_results")
    os.makedirs(raw_dir, exist_ok=True)
    download_engine()

    if not os.path.exists(input_file):
        logger.error(f"Input file {input_file} not found!")
        return

    # موتور اجرایی (روی لینوکس ./xray-knife و روی ویندوز xray-knife.exe)
    knife_bin = get_engine_path()

    # آماده‌سازی فایل ورودی در صورت وجود محدودیت تست محلی
    actual_input_file = input_file
    if limit_for_test:
        with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f if line.strip()][:limit_for_test]
        actual_input_file = "sub/all/mixed_sample.txt"
        with open(actual_input_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    # =========================================================================
    # --- Phase 1: Latency / Ping Test (کمترین پینگ در اولویت) ---
    # =========================================================================
    logger.info(f"--- Phase 1: Latency Test (Threads: {PING_THREADS}) ---")
    p_csv = os.path.join(raw_dir, "ping_raw.csv")
    
    subprocess.run([
        knife_bin, "http",
        "-f", actual_input_file,
        "-t", str(PING_THREADS),
        "-o", p_csv,
        "-x", "csv"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    valid_ping_rows = []
    if os.path.exists(p_csv):
        with open(p_csv, "r", encoding="utf-8-sig", errors="ignore") as f:
            reader = list(csv.DictReader(f))
            for r in reader:
                delay = r.get('delay')
                link = r.get('link') or r.get('Config')
                if not link or not delay or not str(delay).isdigit():
                    continue
                d_int = int(delay)
                if d_int <= 0 or d_int >= 4500:
                    continue
                valid_ping_rows.append(r)
            
            # مرتب‌سازی بر اساس کمترین پینگ (صعودی)
            valid_ping_rows.sort(key=lambda x: int(x['delay']))
            
            # یکتاسازی بر اساس مشخصات اصلی سرور (حفظ بهترین پینگ)
            dedup_ping_rows = []
            seen_cores = set()
            for r in valid_ping_rows:
                link = r.get('link') or r.get('Config')
                ck = get_proxy_core_key(link)
                if ck and ck in seen_cores:
                    continue
                if ck:
                    seen_cores.add(ck)
                dedup_ping_rows.append(r)
            
            valid_ping_rows = dedup_ping_rows
            
            ping_passed_list = [
                rename_config(r.get('link') or r.get('Config'), {
                    'cc': r.get('location', 'UN'),
                    'ping': r.get('delay')
                })
                for r in valid_ping_rows
            ]
            ping_passed_text = "\n".join(filter(None, ping_passed_list))
            
            with open(os.path.join(base_dir, "ping_passed.txt"), "w", encoding="utf-8") as f:
                f.write(ping_passed_text)
            with open(os.path.join(base_dir, "ping_passed_base64.txt"), "w", encoding="utf-8") as f:
                f.write(to_base64(ping_passed_text))
            
            logger.info(f"Phase 1 Complete: {len(valid_ping_rows)} unique configs passed ping test.")

    # =========================================================================
    # --- Phase 2: Speed Test (تست سرعت دسته‌ای تا رسیدن به ۳۰۰ پروکسی فعال) ---
    # =========================================================================
    speed_results = []
    if valid_ping_rows:
        logger.info(f"--- Phase 2: Speed Test (Target: {TARGET_SPEED_CONFIGS} configs, 2MB Payload, Threads: {SPEED_THREADS}) ---")
        
        # استخراج لینک کانفیگ‌ها به ترتیب کمترین پینگ
        candidates = [r.get('link') or r.get('Config') for r in valid_ping_rows if (r.get('link') or r.get('Config'))]
        
        batch_idx = 0
        seen_speed_cores = set()
        for i in range(0, len(candidates), SPEED_BATCH_SIZE):
            if len(speed_results) >= TARGET_SPEED_CONFIGS:
                logger.info(f"Target of {TARGET_SPEED_CONFIGS} speed-verified proxies reached. Stopping Phase 2 early.")
                break
                
            chunk = candidates[i:i + SPEED_BATCH_SIZE]
            batch_idx += 1
            tmp_chunk_txt = f"speed_chunk_tmp_{batch_idx}.txt"
            tmp_chunk_csv = os.path.join(raw_dir, f"speed_chunk_{batch_idx}.csv")
            
            with open(tmp_chunk_txt, "w", encoding="utf-8") as f:
                f.write("\n".join(chunk))
                
            logger.info(f"Testing Speed Batch #{batch_idx} ({len(chunk)} configs)... [Collected so far: {len(speed_results)}/{TARGET_SPEED_CONFIGS}]")
            
            subprocess.run([
                knife_bin, "http",
                "-f", tmp_chunk_txt,
                "-t", str(SPEED_THREADS),
                "-o", tmp_chunk_csv,
                "-x", "csv",
                "-p",
                "-u", SPEED_URL,
                "-a", SPEED_TIMEOUT
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            if os.path.exists(tmp_chunk_csv):
                with open(tmp_chunk_csv, "r", encoding="utf-8-sig", errors="ignore") as f:
                    for row in csv.DictReader(f):
                        try:
                            raw_down = float(row.get('download') or 0)
                            delay = int(row.get('delay') or 0)
                            link = row.get('link') or row.get('Config')
                            # فیلتر: حداقل ۱۰ کیلوبایت بر ثانیه سرعت واقعی و عدم تایم‌اوت
                            if raw_down >= 10 and delay < 4500 and link:
                                ck = get_proxy_core_key(link)
                                if ck and ck in seen_speed_cores:
                                    continue
                                if ck:
                                    seen_speed_cores.add(ck)
                                speed_results.append({
                                    'link': link,
                                    'speed_val': raw_down,
                                    'delay': str(delay),
                                    'cc': row.get('location') or "UN"
                                })
                        except Exception:
                            continue
                try: os.remove(tmp_chunk_csv)
                except Exception: pass
                
            if os.path.exists(tmp_chunk_txt):
                try: os.remove(tmp_chunk_txt)
                except Exception: pass

        # مرتب‌سازی بر اساس بالاترین سرعت دانلود (نزولی)
        speed_results.sort(key=lambda x: x['speed_val'], reverse=True)
        top_speed_results = speed_results[:TARGET_SPEED_CONFIGS]

        final_speed_list = []
        for rank, res in enumerate(top_speed_results, 1):
            spd = res['speed_val']
            if spd >= 1024:
                f_speed = f"{spd / 1024:.2f}MB"
            elif spd > 0:
                f_speed = f"{int(spd)}KB"
            else:
                f_speed = "Low"
            
            final_speed_list.append(rename_config(
                res['link'],
                {'cc': res['cc'], 'ping': res['delay'], 'speed': f_speed},
                rank=rank
            ))

        s_text = "\n".join(filter(None, final_speed_list))
        with open(os.path.join(base_dir, "speed_passed.txt"), "w", encoding="utf-8") as f:
            f.write(s_text)
        with open(os.path.join(base_dir, "speed_passed_base64.txt"), "w", encoding="utf-8") as f:
            f.write(to_base64(s_text))
            
        logger.info(f"Phase 2 Complete: {len(top_speed_results)} unique proxies ranked by download speed.")

    # =========================================================================
    # --- Phase 3: Google Gemini AI Compatibility Test (تست بازگشایی جمنای) ---
    # =========================================================================
    if valid_ping_rows:
        logger.info(f"--- Phase 3: Google Gemini AI Compatibility Test (Threads: {GEMINI_THREADS}) ---")
        
        # تست روی کانفیگ‌های سالم فاز ۱
        gemini_candidates = [r.get('link') or r.get('Config') for r in valid_ping_rows if (r.get('link') or r.get('Config'))]
        
        gemini_tmp_txt = "gemini_candidates_tmp.txt"
        gemini_csv = os.path.join(raw_dir, "gemini_raw.csv")
        
        with open(gemini_tmp_txt, "w", encoding="utf-8") as f:
            f.write("\n".join(gemini_candidates))
            
        subprocess.run([
            knife_bin, "http",
            "-f", gemini_tmp_txt,
            "-t", str(GEMINI_THREADS),
            "-o", gemini_csv,
            "-x", "csv",
            "-u", GEMINI_URL,
            "-a", GEMINI_TIMEOUT
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        gemini_passed_results = []
        if os.path.exists(gemini_csv):
            with open(gemini_csv, "r", encoding="utf-8-sig", errors="ignore") as f:
                seen_gemini_cores = set()
                for row in csv.DictReader(f):
                    cc = (row.get('location') or 'UN').upper()
                    delay = row.get('delay')
                    code = str(row.get('code') or '')
                    status = (row.get('status') or '').lower()
                    link = row.get('link') or row.get('Config')
                    
                    if not link or not delay or not str(delay).isdigit():
                        continue
                    d_int = int(delay)
                    if d_int <= 0 or d_int >= 4500 or cc in GEMINI_BLOCKED_COUNTRIES:
                        continue
                        
                    if status == 'passed' or code in {'200', '301', '302', '307', '308'}:
                        ck = get_proxy_core_key(link)
                        if ck and ck in seen_gemini_cores:
                            continue
                        if ck:
                            seen_gemini_cores.add(ck)
                        gemini_passed_results.append({
                            'link': link,
                            'delay': d_int,
                            'cc': cc
                        })
            
            # مرتب‌سازی بر اساس کمترین پینگ
            gemini_passed_results.sort(key=lambda x: x['delay'])
            
            gemini_final_list = [
                rename_config(r['link'], {
                    'cc': r['cc'],
                    'ping': r['delay'],
                    'custom_tag': '✨ Gemini'
                })
                for r in gemini_passed_results
            ]
            
            g_text = "\n".join(filter(None, gemini_final_list))
            with open(os.path.join(base_dir, "gemini_passed.txt"), "w", encoding="utf-8") as f:
                f.write(g_text)
            with open(os.path.join(base_dir, "gemini_passed_base64.txt"), "w", encoding="utf-8") as f:
                f.write(to_base64(g_text))
                
            logger.info(f"Phase 3 Complete: {len(gemini_passed_results)} unique proxies successfully verified for Google Gemini.")
            
        if os.path.exists(gemini_tmp_txt):
            try: os.remove(gemini_tmp_txt)
            except Exception: pass
        if os.path.exists(gemini_csv):
            try: os.remove(gemini_csv)
            except Exception: pass

    if limit_for_test and os.path.exists("sub/all/mixed_sample.txt"):
        try: os.remove("sub/all/mixed_sample.txt")
        except Exception: pass

    logger.info("🎉 All testing phases completed successfully.")

if __name__ == "__main__":
    test_process()
