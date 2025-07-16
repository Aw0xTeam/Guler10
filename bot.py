import logging, os, time, requests, threading
from dotenv import load_dotenv
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Updater, CommandHandler, CallbackQueryHandler, CallbackContext
from models import Session, Alert, Log

load_dotenv()
TOKEN = os.getenv("BOT_TOKEN")
CMC_KEY = os.getenv("CMC_KEY")

updater = Updater(TOKEN)
dp = updater.dispatcher
session = Session()

logging.basicConfig(level=logging.INFO)

def get_price(coin):
    url = "https://pro-api.coinmarketcap.com/v1/cryptocurrency/quotes/latest"
    headers = {"X-CMC_PRO_API_KEY": CMC_KEY}
    params = {"symbol": coin.upper()}
    r = requests.get(url, headers=headers, params=params)
    data = r.json()
    try:
        return data["data"][coin.upper()]["quote"]["USD"]["price"]
    except:
        return None

def start(update: Update, context: CallbackContext):
    keyboard = [
        [InlineKeyboardButton("Track BTC", callback_data="track_BTC")],
        [InlineKeyboardButton("Track ETH", callback_data="track_ETH")],
        [InlineKeyboardButton("Visit Admin Panel", url="http://localhost:5000")]
    ]
    update.message.reply_text("Welcome! Choose a coin to track:", reply_markup=InlineKeyboardMarkup(keyboard))

def handle_track(update: Update, context: CallbackContext):
    query = update.callback_query
    query.answer()
    coin = query.data.split("_")[1]
    user_id = query.from_user.id

    exists = session.query(Alert).filter_by(user_id=user_id, coin=coin).first()
    if not exists:
        session.add(Alert(user_id=user_id, coin=coin, threshold=0))
        session.commit()

    query.edit_message_text(f"You are now tracking {coin}. Use /set {coin} <price> to set alert.")

def set_alert(update: Update, context: CallbackContext):
    try:
        user_id = update.effective_user.id
        coin = context.args[0].upper()
        price = float(context.args[1])
        alert = session.query(Alert).filter_by(user_id=user_id, coin=coin).first()
        if alert:
            alert.threshold = price
        else:
            alert = Alert(user_id=user_id, coin=coin, threshold=price)
            session.add(alert)
        session.commit()
        update.message.reply_text(f"📌 Alert set for {coin} at ${price}")
    except:
        update.message.reply_text("❌ Use format: /set BTC 50000")

def check_alerts():
    while True:
        alerts = session.query(Alert).all()
        for alert in alerts:
            price = get_price(alert.coin)
            if price and alert.threshold and price >= alert.threshold:
                updater.bot.send_message(chat_id=alert.user_id,
                    text=f"🚨 {alert.coin} hit ${price:.2f} (Target: {alert.threshold})")
                log = Log(user_id=alert.user_id, coin=alert.coin, price=price)
                alert.threshold = 0
                session.add(log)
                session.commit()
        time.sleep(60)

dp.add_handler(CommandHandler("start", start))
dp.add_handler(CommandHandler("set", set_alert))
dp.add_handler(CallbackQueryHandler(handle_track))

if __name__ == "__main__":
    threading.Thread(target=check_alerts, daemon=True).start()
    updater.start_polling()
    updater.idle()
