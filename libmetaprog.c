/**
purple-metaprog - a Metaprog Online plugin for Pidgin
Copyright (C) 2020 Bohdan Horbeshko
Based on essentials of IcyQue plugin
Copyright (C) 2018-2019 Eion Robb

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <glib.h>
#include <gmodule.h>
#include <purple.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

#include "purple2compat/purple-socket.h"
#include "purplecompat.h"

#ifndef PURPLE_PLUGINS
#	define PURPLE_PLUGINS
#endif

#ifndef _
#	define _(a) (a)
#	define N_(a) (a)
#endif

#define BUF_SIZE 1024

#define SERVER_ADDRESS "server-address"
#define SERVER_PORT "server-port"

#define POLL_INTERVAL 10000
#define POLL_TIMEOUT 60

enum METAPROG_CONNECTION
{
	METAPROG_CONNECTION_STATE_FAILURE = 1,
	METAPROG_CONNECTION_STATE_WRONG_PASSWORD = 2,
	METAPROG_CONNECTION_STATE_USER_NOT_FOUND = 6,
	METAPROG_CONNECTION_STATE_CONNECTED = 7
};

enum METAPROG_CMD
{
	METAPROG_CMD_PROBE = 0,
	METAPROG_CMD_REQUEST_CHATS = 3,
	//METAPROG_CMD_REQUEST_CHATS = 10,
};


static guchar*
metaprog_guint32_to_char(guchar* offset, guint32 src)
{
	*(offset++) = src >> 24;
	*(offset++) = (src >> 16) & 0xff;
	*(offset++) = (src >> 8) & 0xff;
	*(offset++) = src & 0xff;

	return offset;
}

static guint32
metaprog_char_to_guint32(guchar* src)
{
	return (*src << 24) | (*(src+1) << 16) | (*(src+2) << 8) | *(src+3);
}


typedef struct {
	PurpleAccount *account;
	PurpleConnection *pc;
	PurpleSocket *socket;
	PurpleGroup *default_group;

	const char *host;
	int port;

	GQueue *cmd_queue;
	gboolean connection_closed;
	guint32 connection_state;

	guchar *auth_string;
	size_t auth_string_len;

	GHashTable *chats_list;
} MetaprogAccount;

typedef struct {
	enum METAPROG_CMD cmd;
	char *payload;
	guint delay;

	MetaprogAccount *ma;
} MetaprogCmdObject;

typedef struct {
	gchar* name;
	guint32 unread_count;
} MetaprogChat;



/*static void
metaprog_util_free_gchar(gpointer data)
{
	gchar *ch = data;
	g_free(ch);
}*/

static void
metaprog_util_free_chat(gpointer data)
{
	MetaprogChat *chat = data;
	g_free(chat->name);
	g_free(chat);
}



static PurpleGroup*
metaprog_get_or_create_default_group(const gchar *group_name)
{
	if (group_name == NULL) {
		group_name = "Metaprog Online";
	}

	PurpleGroup *metaprog_group = purple_blist_find_group(group_name);

	if (!metaprog_group) {
		metaprog_group = purple_group_new(group_name);
		purple_blist_add_group(metaprog_group, NULL);
	}

	return metaprog_group;
}

static const char *
metaprog_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "metaprog";
}

static GList *
metaprog_chat_info(PurpleConnection *pc)
{
	GList *m = NULL;
	PurpleProtocolChatEntry *pce;

	pce = g_new0(PurpleProtocolChatEntry, 1);
	pce->label = _("Chat ID");
	pce->identifier = "id";
	pce->required = TRUE;
	m = g_list_append(m, pce);

	pce = g_new0(PurpleProtocolChatEntry, 1);
	pce->label = _("Chat name");
	pce->identifier = "name";
	pce->required = TRUE;
	m = g_list_append(m, pce);

	return m;
}

static GHashTable *
metaprog_chat_info_new(PurpleConnection *pc, guint32 id, const char* name)
{
	GHashTable *ht = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

	g_hash_table_insert(ht, "id", g_strdup_printf("%d", id));
	if (name != NULL)
	{
		g_hash_table_insert(ht, "name", g_strdup(name));
	}

	return ht;
}

static GHashTable *
metaprog_chat_info_defaults(PurpleConnection *pc, const char *chatname)
{
	GHashTable *defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

	g_hash_table_insert(defaults, "id", "0");
	if (chatname != NULL)
	{
		g_hash_table_insert(defaults, "name", g_strdup(chatname));
	}

	return defaults;
}

static GList *
metaprog_status_types(PurpleAccount *account)
{
	GList *types = NULL;
	PurpleStatusType *status;
	
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE, "online", _("Online"), TRUE, TRUE, FALSE, "message", _("Status"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, "offline", _("Offline"), TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	return types;
}

static gchar *
metaprog_status_text(PurpleBuddy *buddy)
{
	const gchar *message = purple_status_get_attr_string(purple_presence_get_active_status(purple_buddy_get_presence(buddy)), "message");
	
	if (message == NULL) {
		return NULL;
	}
	
	return g_markup_printf_escaped("%s", message);
}

static void
metaprog_tooltip_text(PurpleBuddy *buddy, PurpleNotifyUserInfo *user_info, gboolean full)
{
	PurplePresence *presence;
	PurpleStatus *status;
	const gchar *message;
	
	g_return_if_fail(buddy != NULL);
	
	presence = purple_buddy_get_presence(buddy);
	status = purple_presence_get_active_status(presence);
	purple_notify_user_info_add_pair_html(user_info, _("Status"), purple_status_get_name(status));
	
	message = purple_status_get_attr_string(status, "message");
	if (message != NULL) {
		purple_notify_user_info_add_pair_html(user_info, _("Message"), message);
	}
}

static gchar *
metaprog_get_chat_name(GHashTable *data)
{
	gchar *temp;

	if (data == NULL)
		return NULL;
	
	temp = g_hash_table_lookup(data, "name");

	if (temp == NULL)
		return NULL;

	return g_strdup(temp);
}

static int
metaprog_send_msg(MetaprogAccount *ia, const gchar *to, const gchar *message)
{
	return 1;
}	

static int
metaprog_send_im(PurpleConnection *pc,
#if PURPLE_VERSION_CHECK(3, 0, 0)
				PurpleMessage *msg)
{
	const gchar *who = purple_message_get_recipient(msg);
	const gchar *message = purple_message_get_contents(msg);
#else
				const gchar *who, const gchar *message, PurpleMessageFlags flags)
{
#endif
	
	MetaprogAccount *ia = purple_connection_get_protocol_data(pc);
	
	return metaprog_send_msg(ia, who, message);
}

static gint
metaprog_chat_send(PurpleConnection *pc, gint id, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleMessage *msg)
{
	const gchar *message = purple_message_get_contents(msg);
#else
const gchar *message, PurpleMessageFlags flags)
{
#endif
	
	MetaprogAccount *ia = purple_connection_get_protocol_data(pc);
	PurpleChatConversation *chatconv = purple_conversations_find_chat(pc, id);
	const gchar *sn = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "sn");
	
	if (!sn) {
		sn = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
		g_return_val_if_fail(sn, -1);
	}
	
	return metaprog_send_msg(ia, sn, message);
}

/*static void
metaprog_get_chat_history(MetaprogAccount *ia, const gchar* chatId, const gchar* fromMsg, gint64 count, gpointer user_data)
{
}*/

static void
metaprog_send_cmd(enum METAPROG_CMD cmd, MetaprogAccount *ma, guint delay)
{
	MetaprogCmdObject *co = g_new0(MetaprogCmdObject, 1);
	co->cmd = cmd;
	co->delay = delay;

	co->ma = ma;

	g_queue_push_head(ma->cmd_queue, co);
}

static void
metaprog_auth_string(MetaprogAccount *ma)
{
	const char *username = purple_account_get_username(ma->account);
	const char *password = purple_account_get_password(ma->account);

	guint32 username_len = (guint32)(strlen(username));
	guint32 password_len = (guint32)(strlen(password));

	ma->auth_string_len = 18 + username_len + password_len;
	ma->auth_string = g_new0(char, ma->auth_string_len);

	guchar *offset = ma->auth_string + 10;
	memcpy(offset, &username_len, sizeof(username_len));

	offset = metaprog_guint32_to_char(offset, username_len);

	memcpy(offset, username, username_len);
	offset += username_len;

	offset = metaprog_guint32_to_char(offset, password_len);

	memcpy(offset, password, password_len);

	/*for (int i = 0; i < ma->auth_string_len; i ++) {
		purple_debug_warning("metaprog", "guf[%d] = %x\n", i, ma->auth_string[i]);
	}*/
}

static void metaprog_socket_init(MetaprogCmdObject *co);

static gboolean
metaprog_cmd_delay_callback(gpointer user_data)
{
	MetaprogCmdObject *co = user_data;
	if (!co->ma->connection_closed) {
		PurpleConnection *pc = purple_account_get_connection(co->ma->account);
		co->ma->socket = purple_socket_new(pc);
		metaprog_socket_init(co);
	}

	// prevent repeated calls
	return FALSE;
}

static void
metaprog_next_cmd(MetaprogAccount *ma)
{
	MetaprogCmdObject *co = g_queue_pop_tail(ma->cmd_queue);

	if (co == NULL) return;

	if (co->delay) {
		purple_timeout_add_seconds(co->delay, metaprog_cmd_delay_callback, co);
	} else {
		metaprog_cmd_delay_callback(co);
	}
}

static void
metaprog_populate_buddy_list(gpointer key, gpointer value, gpointer user_data)
{
	guint32 id = GPOINTER_TO_UINT(key);
	MetaprogChat *chat = value;
	MetaprogAccount *ma = user_data;

	char *string_id = g_strdup_printf("%d", id);

	PurpleChat *purple_chat = purple_blist_find_chat(ma->account, string_id);

	if (purple_chat == NULL) {
		purple_chat = purple_chat_new(ma->account, chat->name, metaprog_chat_info_new(ma->pc, id, chat->name));

		purple_blist_add_chat(purple_chat, ma->default_group, NULL);
	} else {
		// TODO: update the chat label, if API allows it at all
	}

	g_free(string_id);
}

static void
metaprog_socket_read_chats_list(guchar *buf, gssize size, MetaprogAccount *ma, GError **error)
{
	if (size < 8) return;

	guint32 chat_count = metaprog_char_to_guint32(buf + 4);

	guint offset = 8;

	guint32 chat_id;
	guint32 unread_count;
	gpointer chat_id_pointer;
	guint32 name_length;
	gchar *name;
	MetaprogChat *chat;

	for (int i = 0; i < chat_count; i ++) {
		if (offset + 12 > size) break;

		chat_id = metaprog_char_to_guint32(buf + offset);
		unread_count = metaprog_char_to_guint32(buf + offset + 4);
		name_length = metaprog_char_to_guint32(buf + offset + 8);

		offset += 12;

		if (offset + name_length > size) break;

		name = g_convert(buf + offset, name_length, "UTF-8", "Cp1251", NULL, NULL, error);
		if ((*error) != NULL) {
			break;
		}

		chat_id_pointer = GUINT_TO_POINTER(chat_id);
		chat = (MetaprogChat*)g_hash_table_lookup(ma->chats_list, chat_id_pointer);
		if (chat == NULL) {
			chat = g_new0(MetaprogChat, 1);
			g_hash_table_insert(ma->chats_list, chat_id_pointer, chat);
		}

		chat->unread_count = unread_count;
		if (g_strcmp0(name, chat->name)) {
			g_free(chat->name);
			chat->name = name;
		} else {
			g_free(name);
		}

		offset += name_length;
	}

	// TODO: fetch next chunks if all chats don't fit in one buffer
	/*while ((size = purple_socket_read(ma->socket, buf, BUF_SIZE)) > 0) {
	}*/

	g_hash_table_foreach(ma->chats_list, metaprog_populate_buddy_list, ma);
}

static void
metaprog_socket_connect_callback(PurpleSocket *ps, const gchar *error, gpointer user_data)
{
	if (error != NULL) {
		PurpleConnection *pc = purple_socket_get_connection(ps);
		purple_connection_error(pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, error);
		return;
	}

	MetaprogCmdObject *co = user_data;
	MetaprogAccount *ma = co->ma;

	gssize size;

	// send command
	char *cmd_string = (char*)g_memdup(ma->auth_string, ma->auth_string_len);
	cmd_string[9] = co->cmd & 0xff;

	size = purple_socket_write(ps, cmd_string, ma->auth_string_len);

	if (size != ma->auth_string_len) {
		if (size == -1) {
			purple_debug_error("metaprog", "Socket write error: %d\n", errno);
		} else {
			purple_debug_error("metaprog", "The socket has choked! Feed it carefully! %d %d\n", size, ma->auth_string_len);
		}
	}

	g_free(cmd_string);

	// process the response
	guchar buf[BUF_SIZE];
	gboolean read_finished = FALSE;

	int fd = purple_socket_get_fd(ps);
	struct pollfd fds[1] = { fd, POLLIN, 0 };

	for (;;) {
		while ((size = purple_socket_read(ps, buf, BUF_SIZE)) > 0) {
			// looks like auth result
			if (co->cmd == METAPROG_CMD_PROBE && size == 10) {
				gboolean known_auth = TRUE;

				enum METAPROG_CONNECTION auth_result = (int)metaprog_char_to_guint32(buf + 6);

				switch (auth_result) {
				case METAPROG_CONNECTION_STATE_FAILURE:
					purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Generic authentication error (0x01)"));
				break;
				case METAPROG_CONNECTION_STATE_WRONG_PASSWORD:
					purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Wrong password"));
				break;
				case METAPROG_CONNECTION_STATE_USER_NOT_FOUND:
					purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_INVALID_USERNAME, _("User not found"));
				break;
				case METAPROG_CONNECTION_STATE_CONNECTED:
					purple_connection_set_state(ma->pc, PURPLE_CONNECTION_CONNECTED);
				break;
				default:
					known_auth = FALSE;
				break;
				}

				purple_debug_info("metaprog", "auth_result = %d\n", auth_result);

				if (known_auth) {
					metaprog_send_cmd(METAPROG_CMD_REQUEST_CHATS, ma, 0);
					read_finished = TRUE;
					break;
				}
			}
			else if (co->cmd == METAPROG_CMD_REQUEST_CHATS) {
				GError *error = NULL;

				metaprog_socket_read_chats_list(buf, size, ma, &error);
				read_finished = TRUE;

				if (error != NULL) {
					purple_debug_error("metaprog", error->message);
					g_free(error);
				}

				break;
			}

			purple_debug_error("metaprog", "Unknown incoming data, please report this to developers:");
			for (int i = 0; i < size; i ++) {
				purple_debug_error("metaprog", "buf[%d] = %x\n", i, buf[i]);
			}
			read_finished = TRUE;
			break;
		}

		if (read_finished) break;

		if (size < 0 && errno != EAGAIN) {
			purple_debug_error("metaprog", "errno = %d\n", errno);
			break;
		}

		usleep(POLL_INTERVAL);
		poll(fds, 1, POLL_TIMEOUT);

		if (ma->connection_closed) break;
	}

	g_free(co->payload);
	g_free(co);

	if (!ma->connection_closed) {
		purple_socket_destroy(ps);
	}

	metaprog_next_cmd(ma);
}

static void
metaprog_socket_init(MetaprogCmdObject *co) {
	purple_socket_set_host(co->ma->socket, co->ma->host);
	purple_socket_set_port(co->ma->socket, co->ma->port);

	purple_socket_connect(co->ma->socket, metaprog_socket_connect_callback, co);
}

static void
metaprog_session_start(MetaprogAccount *ma)
{
	ma->host = purple_account_get_string(ma->account, SERVER_ADDRESS, NULL);
	ma->port = purple_account_get_int(ma->account, SERVER_PORT, 0);

	if (!g_strcmp0(ma->host, "") || ma->host == NULL) {
		purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, "No server address specified");
		return;
	}
	if (ma->port < 0 || ma->port > 0xffff) {
		purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, "Wrong port specified");
		return;
	}

	metaprog_send_cmd(METAPROG_CMD_PROBE, ma, 0);
	metaprog_next_cmd(ma);
}

static void
metaprog_login(PurpleAccount *account)
{
	MetaprogAccount *ma;
	PurpleConnection *pc = purple_account_get_connection(account);
	
	ma = g_new0(MetaprogAccount, 1);
	purple_connection_set_protocol_data(pc, ma);
	ma->account = account;
	ma->pc = pc;

	ma->cmd_queue =	g_queue_new();

	ma->default_group = metaprog_get_or_create_default_group(NULL);

	ma->connection_closed = FALSE;

	metaprog_auth_string(ma);

	ma->chats_list = g_hash_table_new_full(g_direct_hash, g_str_equal, NULL, metaprog_util_free_chat);

	metaprog_session_start(ma);
	
	purple_connection_set_state(pc, PURPLE_CONNECTION_CONNECTING);
}


static void
metaprog_close(PurpleConnection *pc)
{
	MetaprogAccount *ma = purple_connection_get_protocol_data(pc);

	g_return_if_fail(ma != NULL);

	ma->connection_closed = TRUE;

	MetaprogCmdObject *co;
	while ((co = g_queue_pop_tail(ma->cmd_queue)) != NULL) {
		g_free(co->payload);
		g_free(co);
	}
	g_queue_free(ma->cmd_queue);
	
	g_free(ma->auth_string);
	g_hash_table_destroy(ma->chats_list);
	g_free(ma);
}

static gboolean
plugin_load(PurplePlugin *plugin, GError **error)
{
	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin, GError **error)
{
	purple_signals_disconnect_by_handle(plugin);

	return TRUE;
}

/* Purple2 Plugin Load Functions */
#if !PURPLE_VERSION_CHECK(3, 0, 0)

// Normally set in core.c in purple3
void _purple_socket_init(void);
void _purple_socket_uninit(void);

static gboolean
libpurple2_plugin_load(PurplePlugin *plugin)
{
	_purple_socket_init();
	
	return plugin_load(plugin, NULL);
}

static gboolean
libpurple2_plugin_unload(PurplePlugin *plugin)
{
	_purple_socket_uninit();
	
	return plugin_unload(plugin, NULL);
}

static void
plugin_init(PurplePlugin *plugin)
{	
	PurplePluginInfo *info;
	PurplePluginProtocolInfo *prpl_info = g_new0(PurplePluginProtocolInfo, 1);
	PurpleAccountOption *opt;

	opt = purple_account_option_string_new(_("Server address"), SERVER_ADDRESS, NULL);
	prpl_info->protocol_options = g_list_append(prpl_info->protocol_options, opt);

	opt = purple_account_option_int_new(_("Server port"), SERVER_PORT, 9090);
	prpl_info->protocol_options = g_list_append(prpl_info->protocol_options, opt);

	info = plugin->info;

	if (info == NULL) {
		plugin->info = info = g_new0(PurplePluginInfo, 1);
	}

	info->extra_info = prpl_info;
#if PURPLE_MINOR_VERSION >= 5
	prpl_info->struct_size = sizeof(PurplePluginProtocolInfo);
#endif
#if PURPLE_MINOR_VERSION >= 8
	// prpl_info->add_buddy_with_invite = metaprog_add_buddy_with_invite;
#endif

	prpl_info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_INVITE_MESSAGE | OPT_PROTO_PASSWORD_OPTIONAL;
	// prpl_info->protocol_options = metaprog_add_account_options(prpl_info->protocol_options);
	prpl_info->icon_spec.format = "png,gif,jpeg";
	prpl_info->icon_spec.min_width = 0;
	prpl_info->icon_spec.min_height = 0;
	prpl_info->icon_spec.max_width = 96;
	prpl_info->icon_spec.max_height = 96;
	prpl_info->icon_spec.max_filesize = 0;
	prpl_info->icon_spec.scale_rules = PURPLE_ICON_SCALE_DISPLAY;

	// prpl_info->get_account_text_table = metaprog_get_account_text_table;
	// prpl_info->list_emblem = metaprog_list_emblem;
	prpl_info->status_text = metaprog_status_text;
	prpl_info->tooltip_text = metaprog_tooltip_text;
	prpl_info->list_icon = metaprog_list_icon;
	// prpl_info->set_status = metaprog_set_status;
	// prpl_info->set_idle = metaprog_set_idle;
	prpl_info->status_types = metaprog_status_types;
	prpl_info->chat_info = metaprog_chat_info;
	prpl_info->chat_info_defaults = metaprog_chat_info_defaults;
	prpl_info->login = metaprog_login;
	prpl_info->close = metaprog_close;
	prpl_info->send_im = metaprog_send_im;
	// prpl_info->send_typing = metaprog_send_typing;
	// prpl_info->join_chat = metaprog_join_chat;
	prpl_info->get_chat_name = metaprog_get_chat_name;
	// prpl_info->find_blist_chat = metaprog_find_chat;
	// prpl_info->chat_invite = metaprog_chat_invite;
	prpl_info->chat_send = metaprog_chat_send;
	// prpl_info->set_chat_topic = metaprog_chat_set_topic;
	// prpl_info->get_cb_real_name = metaprog_get_real_name;
	// prpl_info->add_buddy = metaprog_add_buddy;
	// prpl_info->remove_buddy = metaprog_buddy_remove;
	// prpl_info->group_buddy = metaprog_fake_group_buddy;
	// prpl_info->rename_group = metaprog_fake_group_rename;
	// prpl_info->get_info = metaprog_get_info;
	// prpl_info->add_deny = metaprog_block_user;
	// prpl_info->rem_deny = metaprog_unblock_user;

	// prpl_info->roomlist_get_list = metaprog_roomlist_get_list;
	// prpl_info->roomlist_room_serialize = metaprog_roomlist_serialize;
}

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	/*	PURPLE_MAJOR_VERSION,
		PURPLE_MINOR_VERSION,
	*/
	2, 1,
	PURPLE_PLUGIN_PROTOCOL,			/* type */
	NULL,							/* ui_requirement */
	0,								/* flags */
	NULL,							/* dependencies */
	PURPLE_PRIORITY_DEFAULT,		/* priority */
	"prpl-bodqhrohro-metaprog",			/* id */
	"Metaprog Online",					/* name */
	"0.0.1",							/* version */
	"",								/* summary */
	"",								/* description */
	"Bohdan Horbeshko <bodqhrohro@gmail.com>", /* author */
	"https://github.com/bodqhrohro/purple-metaprog/",		/* homepage */
	libpurple2_plugin_load,			/* load */
	libpurple2_plugin_unload,		/* unload */
	NULL,							/* destroy */
	NULL,							/* ui_info */
	NULL,							/* extra_info */
	NULL,							/* prefs_info */
	NULL,							/* actions */
	NULL,							/* padding */
	NULL,
	NULL,
	NULL
};

PURPLE_INIT_PLUGIN(metaprog, plugin_init, info);

#else

G_MODULE_EXPORT GType metaprog_protocol_get_type(void);
#define METAPROG_TYPE_PROTOCOL			(metaprog_protocol_get_type())
#define METAPROG_PROTOCOL(obj)			(G_TYPE_CHECK_INSTANCE_CAST((obj), METAPROG_TYPE_PROTOCOL, MetaprogProtocol))
#define METAPROG_PROTOCOL_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST((klass), METAPROG_TYPE_PROTOCOL, MetaprogProtocolClass))
#define METAPROG_IS_PROTOCOL(obj)		(G_TYPE_CHECK_INSTANCE_TYPE((obj), METAPROG_TYPE_PROTOCOL))
#define METAPROG_IS_PROTOCOL_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), METAPROG_TYPE_PROTOCOL))
#define METAPROG_PROTOCOL_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS((obj), METAPROG_TYPE_PROTOCOL, MetaprogProtocolClass))

typedef struct _MetaprogProtocol
{
	PurpleProtocol parent;
} MetaprogProtocol;

typedef struct _MetaprogProtocolClass
{
	PurpleProtocolClass parent_class;
} MetaprogProtocolClass;

static void
metaprog_protocol_client_iface_init(PurpleProtocolClientIface *prpl_info)
{
	prpl_info->status_text = metaprog_status_text;
	prpl_info->tooltip_text = metaprog_tooltip_text;
	//prpl_info->buddy_free = metaprog_buddy_free;
 	//prpl_info->offline_message = metaprog_offline_message;
}

static void
metaprog_protocol_server_iface_init(PurpleProtocolServerIface *prpl_info)
{
	// prpl_info->get_info = metaprog_get_info;
	// prpl_info->set_status = metaprog_set_status;
	//prpl_info->set_idle = metaprog_set_idle;
	// prpl_info->add_buddy = metaprog_add_buddy_with_invite;
}

static void
metaprog_protocol_privacy_iface_init(PurpleProtocolPrivacyIface *prpl_info)
{
	// prpl_info->add_deny = metaprog_block_user;
	// prpl_info->rem_deny = metaprog_unblock_user;
}

static void 
metaprog_protocol_im_iface_init(PurpleProtocolIMIface *prpl_info)
{
	prpl_info->send = metaprog_send_im;
	// prpl_info->send_typing = metaprog_send_typing;
}

static void 
metaprog_protocol_chat_iface_init(PurpleProtocolChatIface *prpl_info)
{
	prpl_info->send = metaprog_chat_send;
	prpl_info->info = metaprog_chat_info;
	prpl_info->info_defaults = metaprog_chat_info_defaults;
	// prpl_info->join = metaprog_join_chat;
	prpl_info->get_name = metaprog_get_chat_name;
	// prpl_info->invite = metaprog_chat_invite;
	//prpl_info->set_topic = metaprog_chat_set_topic;
}

static void 
metaprog_protocol_media_iface_init(PurpleProtocolMediaIface *prpl_info)
{
	//prpl_info->get_caps = metaprog_get_media_caps;
	//prpl_info->initiate_session = metaprog_initiate_media;
}

static void 
metaprog_protocol_roomlist_iface_init(PurpleProtocolRoomlistIface *prpl_info)
{
	//prpl_info->get_list = metaprog_roomlist_get_list;
}

static PurpleProtocol *metaprog_protocol;

PURPLE_DEFINE_TYPE_EXTENDED(
	MetaprogProtocol, metaprog_protocol, PURPLE_TYPE_PROTOCOL, 0,

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_IM_IFACE,
	                                  metaprog_protocol_im_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CHAT_IFACE,
	                                  metaprog_protocol_chat_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CLIENT_IFACE,
	                                  metaprog_protocol_client_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_SERVER_IFACE,
	                                  metaprog_protocol_server_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_PRIVACY_IFACE,
	                                  metaprog_protocol_privacy_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_MEDIA_IFACE,
	                                  metaprog_protocol_media_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_ROOMLIST_IFACE,
	                                  metaprog_protocol_roomlist_iface_init)
);

static gboolean
libpurple3_plugin_load(PurplePlugin *plugin, GError **error)
{
	// metaprog_protocol_register_type(plugin);
	metaprog_protocol = purple_protocols_add(METAPROG_TYPE_PROTOCOL, error);
	if (!metaprog_protocol)
		return FALSE;

	return plugin_load(plugin, error);
}

static gboolean
libpurple3_plugin_unload(PurplePlugin *plugin, GError **error)
{
	if (!plugin_unload(plugin, error))
		return FALSE;

	if (!purple_protocols_remove(metaprog_protocol, error))
		return FALSE;

	return TRUE;
}

static PurplePluginInfo *
plugin_query(GError **error)
{
	return purple_plugin_info_new(
		"id",          "prpl-bodqhrohro-metaprog",
		"name",        "Metaprog Online",
		"version",     "0.0.1",
		"category",    N_("Protocol"),
		"summary",     N_("Metaprog Online Plugin."),
		"description", N_("Adds Metaprog Online support to libpurple."),
		"website",     "https://github.com/bodqhrohro/purple-metaprog/",
		"abi-version", PURPLE_ABI_VERSION,
		"flags",       PURPLE_PLUGIN_INFO_FLAGS_INTERNAL |
		               PURPLE_PLUGIN_INFO_FLAGS_AUTO_LOAD,
		NULL
	);
}

PURPLE_PLUGIN_INIT(metaprog, plugin_query,
		libpurple3_plugin_load, libpurple3_plugin_unload);

#endif	
