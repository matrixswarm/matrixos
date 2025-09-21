import requests
PAIR_MAP = {
                "BTC/USDT": "BTC-USD",
                "ETH/USDT": "ETH-USD",
                "SOL/USDT": "SOL-USD",
                "ADA/USDT": "ADA-USD",
                "XRP/USDT": "XRP-USD",
                "LTC/USDT": "LTC-USD",
                "DOGE/USDT": "DOGE-USD",
                "AVAX/USDT": "AVAX-USD",
                "DOT/USDT": "DOT-USD",
                "ARB/USDT": "ARB-USD",
                "OP/USDT": "OP-USD",
                "MATIC/USDT": "MATIC-USD",
                "UNI/USDT": "UNI-USD",
                "AAVE/USDT": "AAVE-USD",
                "SNX/USDT": "SNX-USD",
                "CRV/USDT": "CRV-USD",
                "SHIB/USDT": "SHIB-USD",
                "PEPE/USDT": "PEPE-USD"
            }
class Exchange:
    def __init__(self, agent):
        self.agent = agent

    def get_price(self, pair):
        try:

            symbol = PAIR_MAP.get(pair.upper())
            if not symbol:
                self.agent.log(f"[Coinbase] ⚠️ Unmapped pair: {pair}")
                return None

            url = f"https://api.coinbase.com/v2/prices/{symbol}/spot"
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                return float(resp.json()["data"]["amount"])
        except Exception as e:
            self.agent.log(f"[COINBASE][ERROR] {e}")
        return None
