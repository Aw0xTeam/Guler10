# 🪙 Crypto Price Alert Bot

A Telegram bot that alerts users when cryptocurrencies hit target prices using CoinMarketCap API.

## Features
- 🧠 SQLite storage for user alerts
- 📈 Coin tracking & price fetching via CMC API
- ⚙️ Telegram inline buttons
- 🖥 Admin panel (Flask web interface)
- 🔔 Price alert notifications

## Setup

```bash
git clone https://github.com/yourusername/crypto-bot.git
cd crypto-bot
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

Create a .env file:

BOT_TOKEN=your_bot_token
CMC_KEY=your_coinmarketcap_key

Run the bot:

python bot.py

Run the admin panel:

python web.py

Visit: http://localhost:5000

---
