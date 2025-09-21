import requests
PAIR_MAP = {
                "BTC/USDT": "bitcoin",
                "ETH/USDT": "ethereum",
                "SOL/USDT": "solana",
                "ADA/USDT": "cardano",
                "XRP/USDT": "ripple",
                "LTC/USDT": "litecoin",
                "DOGE/USDT": "dogecoin",
                "AVAX/USDT": "avalanche-2",
                "DOT/USDT": "polkadot",
                "ARB/USDT": "arbitrum",
                "OP/USDT": "optimism",
                "MATIC/USDT": "matic-network",
                "UNI/USDT": "uniswap",
                "AAVE/USDT": "aave",
                "SNX/USDT": "synthetix-network-token",
                "CRV/USDT": "curve-dao-token",
                "SHIB/USDT": "shiba-inu",
                "PEPE/USDT": "pepe"
            }
class Exchange:
    def __init__(self, agent):
        self.agent = agent

    def get_price(self, pair):
        try:

            symbol = PAIR_MAP.get(pair.upper())
            if not symbol:
                self.agent.log(f"[Coingecko] ⚠️ Unmapped pair: {pair}")
                return None

            url = f"https://api.coingecko.com/api/v3/simple/price?ids={symbol}&vs_currencies=usd"
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                return resp.json().get(symbol, {}).get("usd")

        except Exception as e:
            self.agent.log(f"[COINGECKO][ERROR] {e}")
        return None