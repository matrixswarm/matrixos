import websocket
from PyQt5.QtCore import QObject, pyqtSignal, QThread


class WebSocketListener(QThread):
    # Signal to send messages back to the main application
    message_received = pyqtSignal(object)

    def __init__(self, ws_url):
        super().__init__()
        self.ws_url = ws_url
        self.running = True

    def run(self):
        # Open the WebSocket connection and listen for messages
        self.ws = websocket.WebSocketApp(
            self.ws_url,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close
        )
        while self.running:
            self.ws.run_forever()

    def on_message(self, ws, message):
        # Emit the received message (use a signal to communicate with the GUI)
        self.message_received.emit(message)

    def on_error(self, ws, error):
        print(f"WebSocket Error: {error}")

    def on_close(self, ws, close_status_code, close_msg):
        print(f"WebSocket Closed: {close_msg}")

    def stop(self):
        self.running = False
        self.ws.close()
