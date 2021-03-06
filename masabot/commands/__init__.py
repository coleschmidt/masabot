import datetime
import os.path
import logging
import pathlib

from typing import Optional, Sequence, Tuple
from .. import util

__all__ = [
	'karma',
	'animeme',
	'translate',
	'roll',
	'animelist'
]


_log = logging.getLogger(__name__)
_log.setLevel(logging.DEBUG)


def mention_target_any():
	return {'target_type': 'any'}


def mention_target_specific(
		*user_ids: Tuple[int, ...],
		role_ids: Optional[Sequence[int]] = None,
		channel_ids: Optional[Sequence[int]] = None):
	return {'target_type': 'specific', 'users': user_ids, 'roles': role_ids, 'channels': channel_ids}


def mention_target_self():
	return {'target_type': 'self'}


class MentionTrigger(object):
	def __init__(self, target=None):
		self.trigger_type = 'MENTION'
		if target is None:
			self.mention_targets = mention_target_self()
		else:
			self.mention_targets = target


class InvocationTrigger(object):
	def __init__(self, invocation):
		self.trigger_type = 'INVOCATION'
		self.invocation = invocation


class RegexTrigger(object):
	def __init__(self, regex):
		self.trigger_type = 'REGEX'
		self.regex = regex


class TimerTrigger(object):
	def __init__(self, days=0, seconds=0, minutes=0, hours=0, weeks=0):
		self.trigger_type = 'TIMER'
		self.timer_duration = datetime.timedelta(days=days, seconds=seconds, minutes=minutes, hours=hours, weeks=weeks)


class BotBehaviorModule(object):
	def __init__(self, bot_api, name, desc, help_text, triggers, resource_root, has_state=False):
		"""
		Create a new BotBehaviorModule instance.

		:type bot_api: masabot.bot.MasaBot
		:param bot_api: The interface back to the bot that is executing the module.
		:type name: str
		:param name: The name of the module. Must be unique among all loaded modules.
		:type desc: str
		:param desc: A brief description of what the command does. Should fit on a single line. This is displayed next
		to the command when `help` lists all modules.
		:type help_text: str
		:param help_text: A full help text including all information on the command. This is shown when the help for
		this particular module is displayed.
		:type triggers: list[InvocationTrigger | RegexTrigger | MentionTrigger | TimerTrigger]
		:param triggers: All possible triggers that cause this module to be executed.
		:type resource_root: str
		:param resource_root: The root directory that resources are to be placed in.
		:type has_state: bool
		:param has_state: Whether this module has state. If this is true, then the module should define get_state()
		set_state() methods for saving state to a dict and setting state from a dict.
		"""
		self.help_text = help_text
		self.description = desc
		self.name = name
		self.has_state = has_state
		self.triggers = triggers
		self.bot_api = bot_api
		self._resource_dir = os.path.join(resource_root, name)
		if not os.path.exists(self._resource_dir):
			os.mkdir(self._resource_dir)

	def remove_resource(self, resource):
		"""
		Removes an existing resource. If the resource does not already exist, this function has no effect.

		:type resource: str
		:param resource: The resource to remove.
		"""
		path = os.path.normpath(resource)
		full_path = os.path.join(self._resource_dir, path)
		if os.path.exists(full_path):
			os.remove(full_path)

	def open_resource(self, resource, for_writing=False):
		"""
		Open a resource in binary mode and get the file pointer for it. All resources are opened in binary mode; if text
		mode is needed, module state should be used instead.

		All resources exist within a generic 'resource store'; each module has its own separate resource store that
		no other module can access. The specific details of how the resource store functions is up to the
		implementation, and callers should not rely on such details. The current implementation stores resources as
		files on the filesystem, but this may change in the future.

		The resource should be given as relative to the module's resource store, which is automatically set up by this
		module and can be depended on to already exist. I.e. If a module needed the resource located in
		<module_store>/images/my_image.png, the path "images/my_image.png" should be used. The 'flavor' of path used is
		platform-agnostic; unix-style paths should always be used.

		:type resource: str
		:param resource: The path to the resource to open.
		:type for_writing: bool
		:param for_writing: Whether to open the resource for writing instead. Defaults to False.
		Defaults to False.
		:rtype: io.BytesIO
		:return: The file like object ready for use.
		"""
		if resource.endswith('/'):
			raise ValueError("Resource cannot end in a '/' character.")
		if resource.startswith('/'):
			raise ValueError("Resource cannot start with a '/' character.")

		path = os.path.normpath(resource)

		if for_writing:
			self._create_resource_dirs(path)
			mode = 'wb'
		else:
			mode = 'rb'

		full_path = os.path.join(self._resource_dir, path)
		return open(full_path, mode)

	def list_resources(self, pattern='**/*'):
		"""
		List the paths to all resources that this module has access to.

		:type pattern: str
		:param pattern: Limits the returned resources to those that match the globbing pattern. '**' is any number of
		sub-paths. By default, this is set to '**/*', which returns all resources, but it can be changed to another
		pattern to alter what is returned; e.g. "**/*.txt" would return all resources that end in .txt, and "*.txt"
		would return all resources that end in '.txt' that are not in a sub-path.
		:rtype: list[str]
		:return: A list of the paths of all resources that currently exist, and are accessible to this module.
		"""
		return pathlib.Path(self._resource_dir).glob(pattern)

	def load_config(self, config):
		pass

	def get_state(self):
		pass

	def set_state(self, state):
		pass

	async def on_invocation(self, context, metadata, command, *args):
		"""
		:type context: masabot.bot.BotContext
		:type metadata: masabot.util.MessageMetadata
		:type command: str
		:type args: str
		"""
		pass

	async def on_mention(self, context, metadata, message, mentions: Sequence[util.Mention]):
		"""
		:type context: masabot.bot.BotContext
		:type metadata: masabot.util.MessageMetadata
		:type message: str
		:param mentions: The mentions, not necessarily in order.
		"""
		pass

	async def on_regex_match(self, context, metadata, *match_groups):
		"""
		:type context: masabot.bot.BotContext
		:type metadata: masabot.util.MessageMetadata
		:type match_groups: str
		"""
		pass

	async def on_timer_fire(self):
		pass

	def _create_resource_dirs(self, resource_path):
		path_dirs = []
		parent_dir = os.path.split(resource_path)[0]

		while parent_dir != '':
			parent_dir, cur_dir = os.path.split(parent_dir)
			path_dirs.insert(0, cur_dir)

		cur_create_dir = self._resource_dir
		for new_dir in path_dirs:
			cur_create_dir = os.path.join(cur_create_dir, new_dir)
			if not os.path.exists(cur_create_dir):
				os.mkdir(cur_create_dir)
