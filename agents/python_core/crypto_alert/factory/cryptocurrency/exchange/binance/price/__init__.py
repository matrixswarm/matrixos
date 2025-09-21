import requests

PAIR_MAP = {
    "BTC/USDT": "BTCUSDT",
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
        try:


            symbol = PAIR_MAP.get(pair.upper())
            if not symbol:
                self.agent.log(f"[BINANCE] ⚠️ Unmapped pair: {pair}")
                return None

            url = f"https://api.binance.com/api/v3/ticker/price?symbol={symbol}"
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                return float(resp.json().get("price"))
            if resp.status_code == 429:
                self.agent.log("Binance rate limit hit", block="EXCHANGE")
        except Exception as e:
            self.agent.log(f"[BINANCE][ERROR]", error=e )
        return None