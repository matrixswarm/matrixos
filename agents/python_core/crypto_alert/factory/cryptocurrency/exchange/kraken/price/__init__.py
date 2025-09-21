import requests

class Exchange:
    def __init__(self, agent):
        self.agent = agent

    def get_price(self, pair):
        try:
            mapping = {
                "BTC/USDT": "XBTUSDT",
                "ETH/USDT": "ETHUSDT"
            }
            kraken_pair = mapping.get(pair)
            if not kraken_pair:
                return None
            url = f"https://api.kraken.com/0/public/Ticker?pair={kraken_pair}"
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                data = resp.json().get("result", {})
                first = next(iter(data.values()))
                return float(first["c"][0])  # Close price
        except Exception as e:
            self.agent.log(f"[KRAKEN][ERROR] {e}")
        return None