import sqlite3, logging, time, requests
from flask import Flask, render_template, request
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Updater, CommandHandler, CallbackQueryHandler, CallbackContext

# === CONFIG ===
TOKEN = 'YOUR_BOT_TOKEN'
CMC_KEY = 'YOUR_CMC_API_KEY'
ADMIN_ID = 123456789
DB_FILE = 'alerts.db'

# === DB SETUP ===
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    coin TEXT,
    threshold REAL
)''')
conn.commit()

# === BOT SETUP ===
logging.basicConfig(level=logging.INFO)
updater = Updater(TOKEN)
dp = updater.dispatcher

def get_price(coin):
    url = f'https://pro-api.coinmarketcap.com/v1/cryptocurrency/quotes/latest'
    headers = {'X-CMC_PRO_API_KEY': CMC_KEY}
    params = {'symbol': coin.upper()}
    r = requests.get(url, headers=headers, params=params)
    data = r.json()
    try:
        return data['data'][coin.upper()]['quote']['USD']['price']
    except:
        return None

def start(update: Update, context: CallbackContext):
    keyboard = [
        [InlineKeyboardButton("Track BTC", callback_data='track_BTC')],
        [InlineKeyboardButton("Track ETH", callback_data='track_ETH')],
        [InlineKeyboardButton("Visit Panel", url="http://localhost:5000")]
    ]
    update.message.reply_text("Welcome! Choose a coin to track:", reply_markup=InlineKeyboardMarkup(keyboard))

def track_coin(update: Update, context: CallbackContext):
    query = update.callback_query
    query.answer()
    coin = query.data.split("_")[1]
    user_id = query.from_user.id
    c.execute("INSERT INTO alerts (user_id, coin, threshold) VALUES (?, ?, ?)", (user_id, coin, 0))
    conn.commit()
    query.edit_message_text(f"You are now tracking {coin}.\nUse /set <coin> <price> to set alert.")

def set_alert(update: Update, context: CallbackContext):
    try:
        user_id = update.effective_user.id
        coin = context.args[0].upper()
        price = float(context.args[1])
        c.execute("UPDATE alerts SET threshold=? WHERE user_id=? AND coin=?", (price, user_id, coin))
        conn.commit()
        update.message.reply_text(f"Alert set for {coin} at ${price}")
    except:
        update.message.reply_text("Use format: /set BTC 50000")

def check_alerts():
    while True:
        c.execute("SELECT * FROM alerts")
        for row in c.fetchall():
            alert_id, user_id, coin, threshold = row
            price = get_price(coin)
            if price and price >= threshold and threshold != 0:
                updater.bot.send_message(chat_id=user_id, text=f"🚨 {coin} hit ${price:.2f} (Target: {threshold})")
                c.execute("UPDATE alerts SET threshold=0 WHERE id=?", (alert_id,))
                conn.commit()
        time.sleep(60)

dp.add_handler(CommandHandler("start", start))
dp.add_handler(CommandHandler("set", set_alert))
dp.add_handler(CallbackQueryHandler(track_coin))
