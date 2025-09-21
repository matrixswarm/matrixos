import requests

PAIR_MAP = {
    "BTC/USDT": "XBTUSDT",
    "ETH/USDT": "ETHUSDT",
    "SOL/USDT": "SOLUSDT",
    "ADA/USDT": "ADAUSDT",
    "XRP/USDT": "XRPUSDT",
    "LTC/USDT": "LTCUSDT",
    "DOGE/USDT": "DOGEUSDT",
    "AVAX/USDT": "AVAXUSDT",
    "DOT/USDT": "DOTUSDT",
    "ARB/USDT": "ARBUSDT",
    "OP/USDT": "OPUSDT",
    "MATIC/USDT": "MATICUSDT",
    "UNI/USDT": "UNIUSDT",
    "AAVE/USDT": "AAVEUSDT",
    "SNX/USDT": "SNXUSDT",
    "CRV/USDT": "CRVUSDT",
    "SHIB/USDT": "SHIBUSDT",
    "PEPE/USDT": "PEPEUSDT"
}

class Exchange:
    def __init__(self, agent):
        self.agent = agent

    def get_price(self, pair):
        symbol = PAIR_MAP.get(pair.upper())
        if not symbol:
            self.agent.log(f"[KRAKEN] ⚠️ Unmapped pair: {pair}")
            return None

        try:
            url = f"https://api.kraken.com/0/public/Ticker?pair={symbol}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                result = data.get("result", {})
                for key in result:
                    price_str = result[key]["c"][0]  # 'c' = last trade closed
                    return float(price_str)
        except Exception as e:
            self.agent.log("[KRAKEN] ❌ Failed to fetch price", error=e)

        return None
