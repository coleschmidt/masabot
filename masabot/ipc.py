import asyncio
import struct
import sys
import logging
from typing import Callable, Optional, Tuple
from enum import IntEnum, auto


_log = logging.getLogger(__name__)
_log.setLevel(logging.DEBUG)


# signature is libra + scorpio with some liberties taken to encode it in hex
MASAPROTO_SIGNATURE = bytes([0x11, 0xb1, 0x24, 0x05, 0xc0, 0x12, 0x1d, 0x10])

MASAPROTO_CURRENT_VERSION = 1


class MessageDecodingError(ValueError):
	def __init__(self, msg):
		super().__init__(msg)


class MessageType(IntEnum):
	GET_REASON = auto()
	STOP = auto()
	REPLY = auto()


class MessageStatus(IntEnum):
	SUCCESS = auto()
	FAILURE = auto()


class Message:
	def __init__(self, version: int, message_type: MessageType):
		self.version = version
		self.type = message_type

	def encode(self) -> bytes:
		#[mnum][len][version][type]
		encoded = struct.pack('>II', self.version, self.type)
		encoded += self._encode_args()

		encoded = struct.pack('>I', len(encoded)) + encoded
		encoded = MASAPROTO_SIGNATURE + encoded

		return encoded

	def _encode_args(self) -> bytes:
		return bytes()

	def __str__(self):
		return "<Message v{:d} type={:s}>".format(self.version, self.type.name)


class GetReasonMessage(Message):
	def __init__(self, version: int = MASAPROTO_CURRENT_VERSION):
		super().__init__(version, MessageType.GET_REASON)


class StopMessage(Message):
	def __init__(self, version: int = MASAPROTO_CURRENT_VERSION):
		super().__init__(version, MessageType.STOP)


class ReplyMessage(Message):
	def __init__(self, status: MessageStatus, info: str = None, version: int = MASAPROTO_CURRENT_VERSION):
		super().__init__(version, MessageType.REPLY)
		self.status = status
		self.info = info

	def _encode_args(self):
		info_bytes = bytes()
		info_size = 0
		if self.info is not None:
			info_bytes = self.info.encode('utf-8')
			info_size = len(info_bytes)
		encoded = struct.pack('>II', self.status, info_size) + info_bytes
		return encoded


def _decode_reply_message(version: int, remaining_bytes: bytes) -> ReplyMessage:
	unpack_size = struct.calcsize('>II')
	status, info_size = struct.unpack('>II', remaining_bytes[:unpack_size])
	info = None
	if info_size > 0:
		str_bytes = remaining_bytes[unpack_size:unpack_size + info_size]
		info = str_bytes.decode('utf-8')
	return ReplyMessage(status, info, version)


def decode_message(message_bytes: bytes) -> Message:
	if len(message_bytes) < len(MASAPROTO_SIGNATURE):
		raise MessageDecodingError("message length too short to be a masaproto message")
	if message_bytes[:len(MASAPROTO_SIGNATURE)] != MASAPROTO_SIGNATURE:
		raise MessageDecodingError("first 8 bytes do not contain the masaproto signature")
	message_bytes = message_bytes[len(MASAPROTO_SIGNATURE):]

	len_size = struct.calcsize('>I')
	if len(message_bytes) < len_size:
		raise MessageDecodingError("message length too short to be a masaproto v1 message")
	given_length = struct.unpack('>I', message_bytes[:len_size])[0]
	message_bytes = message_bytes[len_size:]
	if given_length != len(message_bytes):
		msg = "message length given was " + str(given_length) + " but actual length is " + str(len(message_bytes))
		raise MessageDecodingError(msg)

	# now that we have reached the message size and validated it,
	# we no longer need to check sizes before unpacking
	version = struct.unpack('>I', message_bytes[:struct.calcsize('>I')])[0]
	message_bytes = message_bytes[struct.calcsize('>I'):]

	if version == 1:
		message_type = MessageType(struct.unpack('>I', message_bytes[:struct.calcsize('>I')])[0])
		message_bytes = message_bytes[struct.calcsize('>I'):]

		if message_type == MessageType.GET_REASON:
			return GetReasonMessage(version=version)
		elif message_type == MessageType.STOP:
			return StopMessage(version=version)
		elif message_type == MessageType.REPLY:
			return _decode_reply_message(version, message_bytes)
		else:
			raise MessageDecodingError("unknown message type " + repr(message_type.name))

	else:
		raise MessageDecodingError("incompatible masaproto message version: " + str(version))


async def _read_inbound_messages(reader, writer, peer_addr, message_handler):
	stay_open = True
	while stay_open:
		data = bytes()
		while len(data) < len(MASAPROTO_SIGNATURE):
			buf = await reader.read(len(MASAPROTO_SIGNATURE) - len(data))
			if len(buf) == 0:
				# we got EOF; reset the stream
				writer.close()
				if sys.version_info >= (3, 7):
					await writer.wait_closed()
				return
			data += buf

		# okay we got something that should be the length of the signature, now check it
		if data != MASAPROTO_SIGNATURE:
			_log.debug("Received non-masaproto message from %s; discarding", peer_addr)

		message_bytes = data
		data = bytes()
		# if we are this far, it IS a masaproto message. now read the length
		while len(data) < struct.calcsize('>I'):
			buf = await reader.read(struct.calcsize('>I') - len(data))
			if len(buf) == 0:
				# at EOF; close
				_log.warning("Peer %s sent incomplete masaproto message", peer_addr)
				writer.close()
				if sys.version_info >= (3, 7):
					await writer.wait_closed()
				return
			data += buf
		content_len = struct.unpack('>I', data)[0]
		message_bytes += data

		# now that we have the length, read the rest of the message and parse it
		starting_len = len(message_bytes)
		while len(message_bytes) - starting_len < content_len:
			buf = await reader.read(content_len - (len(message_bytes) - starting_len))
			if len(buf) == 0:
				# at EOF; close
				_log.warning("Peer %s sent incomplete masaproto message", peer_addr)
				writer.close()
				if sys.version_info >= (3, 7):
					await writer.wait_closed()
				return
			message_bytes += buf

		message = decode_message(message_bytes)
		_log.debug("Received message from masaproto client %s: %s", peer_addr, str(message))
		response, stay_open = message_handler(message, peer_addr)
		if response is not None:
			writer.write(response.encode())
			await writer.drain()

	writer.close()
	if sys.version_info >= (3, 7):
		await writer.wait_closed()


class MasaprotoClient:

	def __init__(
			self,
			remote_address: str,
			port: int,
			message_handler: Callable[[Message, str], Tuple[Optional[Message], bool]]
	):
		self._remote_address = remote_address
		self._port = port
		self._message_handler = message_handler

	async def send(self, message: Message):
		reader, writer = await asyncio.open_connection(self._remote_address, self._port)
		writer.write(message.encode())
		await writer.drain()

		await _read_inbound_messages(reader, writer, writer.get_extra_info('peername'), self._message_handler)


class MasaprotoServer:

	def __init__(
			self,
			bind_address: str,
			port: int,
			message_handler: Callable[[Message, str], Tuple[Optional[Message], bool]]
	):
		self._port = port
		self._bind_address = bind_address
		self._message_handler = message_handler

	async def start(self):
		server = await asyncio.start_server(self._handle_connection, self._bind_address, self._port)
		async with server:
			await server.serve_forever()

	async def _handle_connection(self, reader, writer):
		peer_addr = writer.get_extra_info('peername')
		await _read_inbound_messages(reader, writer, peer_addr, self._message_handler)