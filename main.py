#!/usr/bin/env python3
import re
import time
import json
import logging
import threading
import requests
from bs4 import BeautifulSoup
from telegram import Bot
from telegram.error import TelegramError
import websocket
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException

# ---------------- CONFIG ----------------
# Tabbatar an saita waɗannan daidai
# NOTE: Ka sanya hanyar da ta dace daidai da inda chromedriver yake
CHROMEDRIVER_PATH = r"C:\Users\RDP\Downloads\chromedriver.exe" 
ORANGE_EMAIL = "newbashkidbackup@gmail.com"
ORANGE_PASSWORD = "Siraiya@1.22"

# NOTE: Ka tabbatar wadannan Tokens din da Chat ID din na gaskiya ne.
TELEGRAM_BOT_TOKEN = "8201398721:AAHdXtM4PLs6ZM0fT3g4SfwgogCusW8dyDI"
TELEGRAM_CHAT_ID = "-4954506825"

LOGIN_URL = "https://www.orangecarrier.com/login"
HUB_BASE_URL = "https://hub.orangecarrier.com"
WS_BASE = "wss://hub.orangecarrier.com/socket.io/"

HEARTBEAT_INTERVAL = 15 
RECONNECT_DELAY = 15
# ----------------------------------------

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class OrangeCarrierMonitor:
    def __init__(self, email, password, bot_token, chat_id, chromedriver_path):
        self.email = email
        self.password = password
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.chromedriver_path = chromedriver_path

        # Initialize Selenium WebDriver
        self.driver = None
        self.init_selenium_driver()

        self.session = requests.Session()
        self.base_url = "https://www.orangecarrier.com"
        self.hub_base_url = HUB_BASE_URL

        # Browser-like headers for requests
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'max-age=0'
        })

        self.bot = Bot(token=bot_token)
        self.seen_calls = set()
        self.ws_token_params = None
        self._stop_event = threading.Event()
        self._ws_thread = None
        self._ws = None
        self.auth_token = None
        self.sid = None

    def init_selenium_driver(self):
        """Initialize Chrome driver with visible browser"""
        try:
            chrome_options = Options()
            # chrome_options.add_argument("--headless") # Zaka iya kashe shi idan kana so ka ga browser
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-blink-features=AutomationControlled")
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            chrome_options.add_argument("--window-size=1200,800")
            
            service = Service(executable_path=self.chromedriver_path)
            self.driver = webdriver.Chrome(
                service=service,
                options=chrome_options
            )
            
            self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            
            logging.info("✅ Chrome driver initialized successfully")
            return True
            
        except Exception as e:
            logging.error(f"❌ Failed to initialize Chrome driver: {e}")
            return False

    def selenium_login(self):
        """Login using Selenium for better handling of JavaScript and complex forms"""
        try:
            logging.info("🚀 Starting Selenium login...")
            
            self.driver.get(LOGIN_URL)
            time.sleep(3)
            
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # --- Input Fields & Button Click ---
            
            email_field = WebDriverWait(self.driver, 5).until(EC.presence_of_element_located((By.NAME, "email")))
            email_field.clear()
            email_field.send_keys(self.email)
            
            password_field = WebDriverWait(self.driver, 5).until(EC.presence_of_element_located((By.NAME, "password")))
            password_field.clear()
            password_field.send_keys(self.password)
            
            login_button = WebDriverWait(self.driver, 5).until(EC.element_to_be_clickable((By.CSS_SELECTOR, "button[type='submit']")))
            
            logging.info("🖱️ Clicking login button... (This may take a moment)")
            self.driver.execute_script("arguments[0].click();", login_button)
            
            # Wait for navigation and check for success
            time.sleep(8) 
            
            current_url = self.driver.current_url.lower()
            
            if "orangecarrier.com" in current_url and "login" not in current_url:
                logging.info("✅ Login successful - redirected to dashboard")
                
                # Ciro Token daga URL idan akwai
                auth_match = re.search(r'auth=([^&]+)', self.driver.current_url)
                if auth_match:
                    logging.info("⭐ Found 'auth' parameter in URL. This may contain the token.")
                    
                # Navigating to Hub URL don ɗaukar duk Cookies/JS Data
                if self.hub_base_url not in self.driver.current_url:
                    logging.info(f"🔄 Navigating to Hub URL: {self.hub_base_url}")
                    self.driver.get(self.hub_base_url)
                    time.sleep(5) # Bada lokaci don Hub ya gama aiki da JS
                    
                return True
            else:
                logging.error("❌ Login failed (still on login page or error page)")
                # Ƙara Screenshot don Debugging
                self.driver.save_screenshot("login_failed.png")
                return False
                
        except Exception as e:
            logging.error(f"❌ Selenium login failed: {e}")
            try: self.driver.save_screenshot("login_error.png")
            except: pass
            return False

    def transfer_cookies_to_requests(self):
        """Transfer cookies from Selenium to requests session"""
        try:
            selenium_cookies = self.driver.get_cookies()
            for cookie in selenium_cookies:
                self.session.cookies.set(
                    cookie['name'], 
                    cookie['value'], 
                    domain=cookie.get('domain'), 
                    path=cookie.get('path', '/')
                )

            logging.info(f"✅ Transferred {len(selenium_cookies)} cookies to requests session")
            return True
        except Exception as e:
            logging.error(f"❌ Failed to transfer cookies: {e}")
            return False

    def login(self):
        """Main login method using Selenium"""
        if not self.selenium_login():
            return False
            
        if not self.transfer_cookies_to_requests():
            return False
            
        return True 

    def get_websocket_token_via_selenium(self):
        """
        *** GYARAR MAHIMMANCI: Ingantacciyar hanyar ciro WebSocket token da User ID ***
        """
        try:
            logging.info("🔍 Extracting WebSocket token and User ID using JS...")
            
            # ---------------------------
            # --- 1. Ciro JWT Token ---
            # ---------------------------
            js_token = """
                let token = localStorage.getItem('auth_token') || localStorage.getItem('token') || '';
                
                // Gwajin JSON: Gwada ciro token daga auth_data (wanda yakan zama JSON)
                if (token.length < 20) {
                    try {
                        let authData = JSON.parse(localStorage.getItem('auth_data') || '{}');
                        token = authData.token || authData.auth_token || '';
                    } catch (e) {}
                }
                
                // Gano duk wani abu mai kama da Token (idan key ya canza)
                if (token.length < 20) {
                    for (let i = 0; i < localStorage.length; i++) {
                        let key = localStorage.key(i);
                        // Bincika key mai dauke da 'token' ko 'auth' kuma value mai tsayi
                        let value = localStorage.getItem(key);
                        if ((key.includes('token') || key.includes('auth')) && (value.length > 20 && value.includes('.'))) {
                            token = value;
                            break;
                        }
                    }
                }
                return token;
            """
            token = self.driver.execute_script(js_token)

            # ---------------------------
            # --- 2. Ciro User ID ---
            # ---------------------------
            js_user_id = """
                let userId = localStorage.getItem('user_id') || '';
                if (!userId) {
                    try {
                        let authData = JSON.parse(localStorage.getItem('auth_data') || '{}');
                        userId = authData.user_id || authData.id || '';
                    } catch (e) { }
                }
                if (!userId) {
                    userId = window.userId || (window.app && window.app.user_id) || '';
                }
                return userId;
            """
            user_id = self.driver.execute_script(js_user_id)
            
            # Fallback na cirowa daga page source
            if not user_id or len(user_id) < 10:
                user_match_content = re.search(r'user["\']?\s*:\s*["\']?([a-fA-F0-9]{20,})["\']?', self.driver.page_source)
                if user_match_content:
                    user_id = user_match_content.group(1)
            
            # --- Tabbatarwa ---
            token_valid = token and len(token) > 20
            user_id_valid = user_id and len(user_id) > 10
            
            if token_valid and user_id_valid:
                ws_params = f"token={token}&user={user_id}&EIO=4&transport=websocket"
                self.auth_token = token 
                logging.info(f"✅ Extracted WebSocket params successfully. Token: {token[:10]}... User ID: {user_id[:8]}...")
                return ws_params
            
            logging.error(f"❌ Could not find a valid token or user ID. Token found: {token_valid}, User ID found: {user_id_valid}")
            
            # Ƙara Screenshot don debugging
            self.driver.save_screenshot("token_extraction_failed.png")
            
            return None

        except Exception as e:
            logging.error(f"❌ Error extracting token/user ID via Selenium: {e}")
            return None
            
    def get_websocket_params(self):
        """Get WebSocket connection parameters using Selenium"""
        return self.get_websocket_token_via_selenium()

    def parse_socketio_message(self, msg):
        """Handle Socket.IO messages, especially the Ping/Pong heartbeat."""
        if not msg: return
            
        if msg == "2":
            # GYARA: Amsa Ping (2) da Pong (3) nan take.
            try:
                if self._ws:
                    self._ws.send("3")
                    logging.debug("✅ Sent pong (Heartbeat)")
            except Exception as e:
                logging.error(f"❌ Failed to send pong: {e}")
            return
            
        if msg.startswith("0"):
            try:
                data = json.loads(msg[1:])
                self.sid = data.get('sid')
                logging.info(f"🔗 Connection established with SID: {self.sid}")
                
                # Aika sako na JOIN USER ROOM don fara karban Events.
                join_msg = f'42["join_user_room",{{"room": "user: {self.email}:orange: internal"}}]'
                self._ws.send(join_msg)
                logging.info("➡️ Sent join_user_room event.")
                
            except Exception as e:
                logging.error(f"❌ Failed to parse open packet or send join room: {e}")
                
        if msg.startswith("42"):
            try:
                payload = msg[2:]
                data = json.loads(payload)
                if isinstance(data, list) and len(data) > 0:
                    event = data[0]
                    event_payload = data[1] if len(data) > 1 else {}
                    
                    if event == "new_call":
                        self.handle_new_call(event_payload)
                    elif event == "call_update":
                        self.handle_call_update(event_payload)
                    elif event in ["join_user_room", "authenticated", "connected"]:
                        logging.info(f"✅ Successfully processed event: {event}")
                    elif event == "error":
                        logging.error(f"❌ SocketIO error: {event_payload}")
                    else:
                        logging.debug(f"📢 SocketIO event: {event}")
                        
            except Exception as e:
                logging.error(f"❌ Failed to parse message: {e}")

    def handle_new_call(self, call_data):
        try:
            call_id = call_data.get('id') or f"{call_data.get('from','')}_{call_data.get('timestamp','')}"
            if call_id and call_id not in self.seen_calls:
                logging.info(f"📞 NEW CALL DETECTED: {call_data.get('from')} -> {call_data.get('to')}")
                self.send_telegram_notification(call_data)
                self.seen_calls.add(call_id)
            else:
                logging.debug(f"Call already seen or ID missing: {call_id}")
        except Exception as e:
            logging.error(f"❌ Error handling new call: {e}")

    def handle_call_update(self, call_data):
        logging.debug(f"📞 Call update: {call_data}")

    def send_telegram_notification(self, call):
        try:
            message = (
                f"📞 <b>New Call Detected</b>\n\n"
                f"⏰ <b>Time:</b> {call.get('timestamp', 'Unknown')}\n"
                f"📱 <b>From:</b> {call.get('from', 'Unknown')}\n"
                f"➡️ <b>To:</b> {call.get('to', 'Unknown')}\n"
                f"🌍 <b>Country:</b> {call.get('country', 'Unknown')}\n"
                f"⏱️ <b>Duration:</b> {call.get('duration', '0s')}\n\n"
                f"🔔 <i>Orange Carrier Monitor</i>"
            )
            self.bot.send_message(chat_id=self.chat_id, text=message, parse_mode='HTML')
            logging.info("✅ Telegram notification sent successfully!")
        except TelegramError as e:
            logging.error(f"❌ Failed to send telegram (TelegramError): {e.message}")
        except Exception as e:
            logging.error(f"❌ Failed to send telegram: {e}")

    def _build_ws_headers(self):
        """Tabbatar an saka cookies masu mahimmanci da kuma Authorization header."""
        cookies = self.session.cookies.get_dict()
        
        filtered_cookies = {k: v for k, v in cookies.items() if k in ['laravel_session', 'XSRF-TOKEN', 'jwt', 'user_session', 'token']}
        cookie_header = "; ".join(f"{k}={v}" for k, v in filtered_cookies.items())

        headers = {
            "User-Agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            "Origin": self.hub_base_url,
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
        }
        
        if cookie_header:
            headers["Cookie"] = cookie_header

        # Saka Authorization header idan an samo token
        if self.auth_token:
             headers['Authorization'] = f'Bearer {self.auth_token}'
                 
        return [f"{k}: {v}" for k, v in headers.items()]

    def on_ws_open(self, ws):
        logging.info("🔌 WebSocket connection opened")

    def on_ws_error(self, ws, error):
        if isinstance(error, Exception):
             logging.error(f"❌ WebSocket error: {error}")
        else:
             logging.error(f"❌ WebSocket error: {error}")

    def on_ws_close(self, ws, close_status_code, close_msg):
        logging.warning(f"🔌 WebSocket closed: Code={close_status_code}, Message={close_msg}")
        self.sid = None

    def _ws_loop(self):
        """WebSocket main loop for reconnection and heartbeat settings."""
        while not self._stop_event.is_set():
            ws_params = self.get_websocket_params()
            if not ws_params:
                logging.error("❌ Failed to get WebSocket parameters. Reconnecting soon.")
                time.sleep(RECONNECT_DELAY)
                continue
                
            self.ws_token_params = ws_params
            ws_url = f"{WS_BASE}?{self.ws_token_params}"
            logging.info(f"🔗 Connecting to: {ws_url}")
            
            try:
                self._ws = websocket.WebSocketApp(
                    ws_url,
                    header=self._build_ws_headers(),
                    on_message=lambda ws, msg: self.parse_socketio_message(msg),
                    on_error=self.on_ws_error,
                    on_close=self.on_ws_close,
                    on_open=self.on_ws_open
                )
                
                self._ws.run_forever(
                    ping_interval=HEARTBEAT_INTERVAL, 
                    ping_timeout=5, 
                    sslopt={"cert_reqs": None} # An kashe SSL checks saboda matsalolin TLS.
                )
                
            except Exception as e:
                logging.error(f"❌ WebSocket exception in run_forever: {e}")
            finally:
                if not self._stop_event.is_set():
                    logging.info(f"🔄 Reconnecting in {RECONNECT_DELAY}s...")
                    time.sleep(RECONNECT_DELAY)

    def start_websocket_monitoring(self):
        if self._ws_thread and self._ws_thread.is_alive(): return True
            
        self._stop_event.clear()
        self._ws_thread = threading.Thread(target=self._ws_loop, daemon=True)
        self._ws_thread.start()
        logging.info("🚀 WebSocket monitoring started")
        return True

    def stop_websocket_monitoring(self):
        self._stop_event.set()
        if self._ws:
            try: self._ws.close()
            except: pass

    def close_driver(self):
        """Close the Selenium driver"""
        if self.driver:
            try:
                self.driver.quit()
                logging.info("✅ Chrome driver closed")
            except:
                pass

    def monitor_calls(self):
        logging.info("🎯 Starting Orange Carrier Monitor with Selenium...")

        if not self.login():
            logging.error("❌ Failed to login")
            return False

        if not self.start_websocket_monitoring():
            logging.error("❌ Failed to start monitor")
            return False
            
        return True

def main():
    monitor = OrangeCarrierMonitor(
        email=ORANGE_EMAIL,
        password=ORANGE_PASSWORD,
        bot_token=TELEGRAM_BOT_TOKEN,
        chat_id=TELEGRAM_CHAT_ID,
        chromedriver_path=CHROMEDRIVER_PATH
    )

    try:
        success = monitor.monitor_calls()
        if success:
            logging.info("✅ Monitor started successfully!")
            logging.info("👀 Browser is visible - you can monitor the process")
            logging.info("⏹️  Press Ctrl+C to stop the monitor")
            
            # Keep main thread alive while background WS thread runs
            while True:
                time.sleep(1)
        else:
            logging.error("❌ Failed to start monitor")
            
    except KeyboardInterrupt:
        logging.info("🛑 Interrupted by user, stopping...")
    except Exception as e:
        logging.error(f"❌ Unexpected error: {e}")
    finally:
        monitor.stop_websocket_monitoring()
        monitor.close_driver()

if __name__ == "__main__":
    main()
