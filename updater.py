# this process runs separately from the main bot and handles shutting it down when necessary
from masabot import ipc
import asyncio

if __name__ == "__main__":
	def handle_message(message, peer_info):
		print("Received " + str(message) + " from " + repr(peer_info))
		return None, False

	cl = ipc.MasaprotoClient('127.0.0.1', 3140, handle_message)

	msg = ipc.StopMessage()

	# this wakeup method is a way to handle the bizarre behavior in windows where ctrl-c is ignored by asyncio
	# see here: https://stackoverflow.com/questions/24774980/why-cant-i-catch-sigint-when-asyncio-event-loop-is-running/24775107#24775107
	def wakeup():
		asyncio.get_event_loop().call_later(1, wakeup)

	async def run_updater():
		asyncio.get_event_loop().call_later(1, wakeup)
		await cl.send(msg)
	try:
		asyncio.run(run_updater())
	except KeyboardInterrupt:
		print("Exit")
