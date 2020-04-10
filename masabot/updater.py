# this process runs separately from the main bot and handles shutting it down when necessary
from . import ipc
import asyncio

if __name__ == "__main__":
	def handle_message(message, peer_info):
		print("Received " + str(message) + " from " + peer_info)
		return None, False

	cl = ipc.MasaprotoClient('127.0.0.1', 3140, handle_message)

	msg = ipc.StopMessage()
	asyncio.run(cl.send(msg))
