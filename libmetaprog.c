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

#define PLUGIN_VERSION "0.0.2"

#define SERVER_ADDRESS "server-address"
#define SERVER_PORT "server-port"
#define CONNECTION_RETRY_NUMBER "connection-retry-number"
#define LAST_MESSAGE "last-message"
#define LAST_MESSAGE_INDEX "last-message-index"

#define POLL_INTERVAL 10000 // µs
#define POLL_TIMEOUT 60 // s
#define CONNECTION_FAIL_RETRY_INTERVAL 5 // s

#define EAGAIN_THRESHOLD 100

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
	METAPROG_CMD_SEND_MESSAGE = 4,
	METAPROG_CMD_REQUEST_CHAT_FULL = 5,
	METAPROG_CMD_REQUEST_CHAT_UPDATE = 6,
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

static guint
metaprog_metaprog_string_to_c_string(char *src, guint offset, guint safe_size, char **dest, guint32 *length, GError **error) {
	if (safe_size > -1 && safe_size < offset + 4) {
		g_set_error_literal(error, G_CONVERT_ERROR, G_CONVERT_ERROR_PARTIAL_INPUT, "Can't read the string length");
		return offset;
	}

	guint32 string_length = metaprog_char_to_guint32(src + offset);
	offset += 4;

	if (safe_size > -1 && safe_size < offset + string_length) {
		g_set_error_literal(error, G_CONVERT_ERROR, G_CONVERT_ERROR_PARTIAL_INPUT, "Can't read the string content");
		return offset;
	}

	*dest = g_convert(src + offset, string_length, "UTF-8", "Cp1251", NULL, NULL, error);
	offset += string_length;

	if (length != NULL) {
		*length = string_length;
	}

	return offset;
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
	gint reconnect_threshold;

	guchar *auth_string;
	size_t auth_string_len;

	GHashTable *chats_list;
} MetaprogAccount;

typedef struct {
	enum METAPROG_CMD cmd;
	char *payload;
	guint32 payload_size;
	guint delay;

	MetaprogAccount *ma;
} MetaprogCmdObject;

typedef struct {
	gchar* name;
	guint32 unread_count;
	gboolean is_history_fetched;
	gchar* last_message_index_key;
	gchar* last_message_key;
} MetaprogChat;



static void
metaprog_util_free_gchar(gpointer data)
{
	gchar *ch = data;
	g_free(ch);
}

static void
metaprog_util_free_chat(gpointer data)
{
	MetaprogChat *chat = data;
	g_free(chat->last_message_index_key);
	g_free(chat->last_message_key);
	g_free(chat->name);
	g_free(chat);
}

static void
metaprog_util_free_cmd_object(MetaprogCmdObject *co)
{
	g_free(co->payload);
	g_free(co);
}

static PurpleChat*
metaprog_blist_find_chat_by_name(PurpleAccount *account, const char* name)
{
	g_return_val_if_fail(name != NULL, NULL);

	PurpleChat *chat;
	PurpleBlistNode *node, *group;
	GHashTable *components;
	gchar *chat_name;

	PurpleBuddyList *blist = purple_get_blist();

	g_return_val_if_fail(blist != NULL, NULL);

	for (group = blist->root; group != NULL; group = group->next) {
		for (node = group->child; node != NULL; node = node->next) {
			if (PURPLE_BLIST_NODE_IS_CHAT(node)) {
				chat = (PurpleChat*)node;

				if (account != chat->account) continue;

				components = purple_chat_get_components(chat);
				gchar *chat_name = g_hash_table_lookup(components, "name");
				if (!g_strcmp0(name, chat_name)) {
					return chat;
				}
			}
		}
	}

	return NULL;
}

static MetaprogChat *
metaprog_chat_new(guint32 id)
{
	MetaprogChat *chat = g_new0(MetaprogChat, 1);
	char *string_id = g_strdup_printf("%d", id);

	chat->last_message_index_key = g_strjoin(NULL, LAST_MESSAGE_INDEX, string_id, NULL);
	chat->last_message_key = g_strjoin(NULL, LAST_MESSAGE, string_id, NULL);

	g_free(string_id);

	return chat;
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

	g_hash_table_insert(ht, g_strdup("id"), g_strdup_printf("%d", id));
	if (name != NULL)
	{
		g_hash_table_insert(ht, g_strdup("name"), g_strdup(name));
	}

	return ht;
}

static GHashTable *
metaprog_chat_info_defaults(PurpleConnection *pc, const char *chatname)
{
	GHashTable *defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

	g_hash_table_insert(defaults, g_strdup("id"), g_strdup("0"));
	if (chatname != NULL)
	{
		g_hash_table_insert(defaults, g_strdup("name"), g_strdup(chatname));
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

/*static void
metaprog_get_chat_history(MetaprogAccount *ia, const gchar* chatId, const gchar* fromMsg, gint64 count, gpointer user_data)
{
}*/

static void
metaprog_send_cmd(MetaprogAccount *ma, enum METAPROG_CMD cmd, gchar *payload, guint32 payload_size, gint delay)
{
	MetaprogCmdObject *co = g_new0(MetaprogCmdObject, 1);
	co->cmd = cmd;
	co->payload = payload;
	co->payload_size = payload_size;
	co->delay = (delay > 0) ? delay : 0;

	co->ma = ma;

	// negative delay means immediate
	if (delay < 0) {
		g_queue_push_tail(ma->cmd_queue, co);
	} else {
		g_queue_push_head(ma->cmd_queue, co);
	}
}

static int
metaprog_send_msg(MetaprogAccount *ma, guint32 id, const gchar *message)
{
	gchar *stripped = purple_markup_strip_html(message);

	GError *error = NULL;
	gchar *win = g_convert_with_fallback(stripped, -1, "Cp1251", "UTF-8", "?", NULL, NULL, &error);
	g_free(stripped);

	if (error != NULL) {
		purple_debug_error("metaprog", error->message);
		g_free(error);

		return -1;
	}

	guint32 win_length = strlen(win);

	guint32 msg_payload_size = 8 + win_length;
	gchar *msg_payload = g_new(char, msg_payload_size);

	metaprog_guint32_to_char(msg_payload, id);

	metaprog_guint32_to_char(msg_payload + 4, win_length);
	memcpy(msg_payload + 8, win, win_length);

	metaprog_send_cmd(ma, METAPROG_CMD_SEND_MESSAGE, msg_payload, msg_payload_size, -1);

	g_free(win);

	// due to the the async approach, we can't now for sure if the message was sent now :(
	return 1;
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
	
	MetaprogAccount *ma = purple_connection_get_protocol_data(pc);
	PurpleChatConversation *chatconv = purple_conversations_find_chat(pc, id);
	PurpleConversation *conv = purple_conv_chat_get_conversation(chatconv);

	guint32 chat_id = GPOINTER_TO_UINT(purple_conversation_get_data(conv, "id"));

	if (!chat_id) {
		// the chat's probably opened manually, falling back to a quirky way
		const gchar *chat_name = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));

		g_return_val_if_fail(chat_name, -1);

		PurpleChat *purple_chat = metaprog_blist_find_chat_by_name(ma->account, chat_name);

		g_return_val_if_fail(purple_chat, -1);

		GHashTable *components = purple_chat_get_components(purple_chat);
		gchar *id_string = g_hash_table_lookup(components, "id");

		g_return_val_if_fail(id_string, -1);

		chat_id = (guint32)g_ascii_strtoll(id_string, NULL, 10);
	}

	return metaprog_send_msg(ma, chat_id, message);
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
		if (co->delay % 1000) {
			purple_timeout_add(co->delay, metaprog_cmd_delay_callback, co);
		} else {
			// that's better for timer grouping
			purple_timeout_add_seconds(co->delay / 1000, metaprog_cmd_delay_callback, co);
		}
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

	gchar *string_id = g_strdup_printf("%d", id);

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
	gchar *chat_id_string;
	gchar *name;
	MetaprogChat *chat;

	for (int i = 0; i < chat_count; i ++) {
		if (offset + 8 > size) break;

		chat_id_string = (gchar*)g_memdup(buf + offset, 4);
		chat_id = metaprog_char_to_guint32(chat_id_string);

		unread_count = metaprog_char_to_guint32(buf + offset + 4);

		offset += 8;

		offset = metaprog_metaprog_string_to_c_string(buf, offset, size, &name, NULL, error);
		if ((*error) != NULL) {
			break;
		}

		chat_id_pointer = GUINT_TO_POINTER(chat_id);
		chat = (MetaprogChat*)g_hash_table_lookup(ma->chats_list, chat_id_pointer);
		if (chat == NULL) {
			chat = metaprog_chat_new(chat_id);
			g_hash_table_insert(ma->chats_list, chat_id_pointer, chat);
		}

		chat->unread_count = unread_count;

		if (g_strcmp0(name, chat->name)) {
			g_free(chat->name);
			chat->name = name;
		} else {
			g_free(name);
		}

		metaprog_send_cmd(ma,
			chat->is_history_fetched
				? METAPROG_CMD_REQUEST_CHAT_UPDATE
				: METAPROG_CMD_REQUEST_CHAT_FULL
			, chat_id_string, 4, 300);
	}

	g_hash_table_foreach(ma->chats_list, metaprog_populate_buddy_list, ma);

	// delay the next query
	metaprog_send_cmd(ma, METAPROG_CMD_REQUEST_CHATS, NULL, 0, 1000);
}

static void
metaprog_socket_read_chat_update(guchar *buf, gssize size, MetaprogAccount *ma, guint32 chat_id, GError **error)
{
	if (size < 4) return;

	guint32 response_size = metaprog_char_to_guint32(buf);

	PurpleConnection *pc = purple_socket_get_connection(ma->socket);

	// TODO: fetch all the chunks
	if (response_size + 4 > size) {
		purple_connection_error(pc, PURPLE_CONNECTION_ERROR_OTHER_ERROR, _("Chat info buffer overflow"));
		return;
	}

	// read the chat name
	guint offset = 4;

	gchar *new_name;
	offset = metaprog_metaprog_string_to_c_string(buf, offset, size, &new_name, NULL, error);
	if ((*error) != NULL) {
		return;
	}

	// retrieve the corresponding chat data
	gchar *string_id = g_strdup_printf("%d", chat_id);

	PurpleChat *purple_chat = purple_blist_find_chat(ma->account, string_id);

	g_free(string_id);

	if (purple_chat == NULL) {
		purple_connection_error(pc, PURPLE_CONNECTION_ERROR_OTHER_ERROR, "Chat list is corrupted, aborting");
		return;
	}

	GHashTable *components = purple_chat_get_components(purple_chat);
	gchar *name = g_hash_table_lookup(components, "name");

	// update the chat name if it has changed
	if (g_strcmp0(name, new_name)) {
		g_hash_table_replace(components, "name", new_name);

		// this will be freed instead
		new_name = name;

		name = g_hash_table_lookup(components, "name");
	}

	g_free(new_name);

	// pop the conversation or find the existing one
	gpointer chat_id_pointer = GUINT_TO_POINTER(chat_id);
	MetaprogChat* chat = (MetaprogChat*)g_hash_table_lookup(ma->chats_list, chat_id_pointer);

	PurpleConversation *purple_conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, name, ma->account);
	PurpleConvChat *chat_data;

	gboolean is_new_conversation = purple_conv == NULL ? TRUE : FALSE;

	// resurrect the conversations on every reconnect
	if (purple_conv == NULL || (chat != NULL && !chat->is_history_fetched)) {
		chat_data = purple_serv_got_joined_chat(pc, chat_id, name);
		purple_conv = purple_conv_chat_get_conversation(chat_data);
	} else {
		chat_data = PURPLE_CONV_CHAT(purple_conv);
	}

	purple_conversation_set_data(purple_conv, "id", GINT_TO_POINTER(chat_id));

	if (is_new_conversation) {
		purple_conversation_present(purple_conv);
	}

	// collect new messages
	int i;

	guint32 messages_count = metaprog_char_to_guint32(buf + offset);
	offset += 4;

	gchar *message;
	GQueue *messages = g_queue_new();
	for (i = 0; i < messages_count; i ++) {
		offset = metaprog_metaprog_string_to_c_string(buf, offset, size, &message, NULL, error);
		if ((*error) != NULL) {
			return;
		}

		g_queue_push_tail(messages, message);
	}

	guint32 senders_count = metaprog_char_to_guint32(buf + offset);
	offset += 4;

	g_return_if_fail(messages_count == senders_count);

	if (messages_count != senders_count) {
		purple_connection_error(pc, PURPLE_CONNECTION_ERROR_OTHER_ERROR, _("Mismatch of messages and senders number, aborting"));
		g_queue_free_full(messages, metaprog_util_free_gchar);
		return;
	}

	gchar *sender;
	GQueue *senders = g_queue_new();
	for (i = 0; i < messages_count; i ++) {
		offset = metaprog_metaprog_string_to_c_string(buf, offset, size, &sender, NULL, error);
		if ((*error) != NULL) {
			return;
		}

		g_queue_push_tail(senders, sender);
	}

	// history consistence check
	guint new_history_size = g_queue_get_length(messages);

	g_return_if_fail(new_history_size == messages_count);

	if (chat != NULL && !chat->is_history_fetched) {
		const char *last_msg = purple_account_get_string(ma->account, chat->last_message_key, NULL);
		int last_msg_i = purple_account_get_int(ma->account, chat->last_message_index_key, -1);

		if (last_msg_i > -1 && new_history_size >= last_msg_i) {
			char *matching_last_msg = (char*)g_queue_peek_nth(messages, last_msg_i);
			if (g_strcmp0(last_msg, matching_last_msg)) {
				// something went wrong, ditch the history and show everything again
				purple_debug_error("metaprog", _("History is broken or edited on the server, re-fetching competely\n"));
				purple_account_set_int(ma->account, chat->last_message_index_key, -1);
				purple_account_set_string(ma->account, chat->last_message_key, NULL);
			} else {
				// skip the already logged messages
				purple_debug_info("metaprog", _("Skipping %d messages\n"), last_msg_i);

				// the last message is intentionally left to keep context, so no <= here
				for (int i = 0; i < last_msg_i; i ++) {
					g_queue_pop_head(messages);
					g_queue_pop_head(senders);
				}
			}
		}
	}

	// show the new messages
	gchar *last_new_msg = NULL;
	gchar *escaped_msg = NULL;
	for (;;) {
		message = g_queue_pop_head(messages);
		sender = g_queue_pop_head(senders);

		if (message == NULL) break;

		char *escaped_msg = purple_markup_escape_text(message, -1);
		purple_serv_got_chat_in(pc, chat_id, sender, 0, escaped_msg, time(NULL));
		g_free(escaped_msg);

		g_free(last_new_msg);
		last_new_msg = message;

		g_free(sender);
	}

	g_queue_free(messages);
	g_queue_free(senders);

	// save the new history position
	// (partial updates are not reliable, so they should be re-fetched on the next reconnect)
	if (chat != NULL && !chat->is_history_fetched) {
		purple_account_set_int(ma->account, chat->last_message_index_key, new_history_size-1);
		purple_account_set_string(ma->account, chat->last_message_key, last_new_msg);
	}

	g_free(last_new_msg);

	// update the room roster
	guint32 members_count = metaprog_char_to_guint32(buf + offset);
	offset += 4;

	gchar* member_name;
	guint8 status;

	PurpleConvChatBuddyFlags flags;

	for (i = 0; i < members_count; i ++) {
		offset = metaprog_metaprog_string_to_c_string(buf, offset, size, &member_name, NULL, error);
		if ((*error) != NULL) {
			return;
		}

		status = buf[offset ++];
		flags = status > 0 ? PURPLE_CBFLAGS_VOICE : PURPLE_CBFLAGS_AWAY;

		if (purple_conv_chat_find_user(chat_data, member_name)) {
			purple_conv_chat_user_set_flags(chat_data, member_name, flags);
		} else {
			purple_chat_conversation_add_user(chat_data, member_name, NULL, flags, FALSE);
		}

		g_free(member_name);
	}

	if (chat != NULL && !chat->is_history_fetched && new_history_size > 0) {
		chat->is_history_fetched = TRUE;
	}
}

static guint32
metaprog_get_required_packet_size(MetaprogCmdObject *co, gchar* buf, guint size) {
	if (co->cmd == METAPROG_CMD_PROBE) {
		return 10;
	}
	else if (co->cmd == METAPROG_CMD_REQUEST_CHATS
			|| co->cmd == METAPROG_CMD_REQUEST_CHAT_FULL
			|| co->cmd == METAPROG_CMD_REQUEST_CHAT_UPDATE) {
		if (size < 4) return -1;

		return metaprog_char_to_guint32(buf);
	}
	else if (co->cmd == METAPROG_CMD_SEND_MESSAGE) {
		return 0;
	}

	// not enough information yet
	return -1;
}

static void
metaprog_retry_cmd(MetaprogCmdObject *co, const gchar *error)
{
	MetaprogAccount *ma = co->ma;

	if (ma->connection_closed) return;

	if (ma->reconnect_threshold == -1) {
		ma->reconnect_threshold = purple_account_get_int(ma->account, CONNECTION_RETRY_NUMBER, 5);
	}

	if (--ma->reconnect_threshold < 0) {
		metaprog_util_free_cmd_object(co);

		PurpleConnection *pc = purple_socket_get_connection(ma->socket);
		purple_connection_error(pc, PURPLE_CONNECTION_ERROR_OTHER_ERROR, error);
	} else {
		purple_socket_destroy(ma->socket);
		purple_timeout_add_seconds(CONNECTION_FAIL_RETRY_INTERVAL, metaprog_cmd_delay_callback, co);
	}
}

static void
metaprog_socket_connect_callback(PurpleSocket *ps, const gchar *error, gpointer user_data)
{
	MetaprogCmdObject *co = user_data;

	if (error != NULL) {
		metaprog_retry_cmd(co, error);
		return;
	}

	MetaprogAccount *ma = co->ma;
	ma->reconnect_threshold = -1;

	gssize size;

	// send command
	char *cmd_string;
	//if (co->cmd == METAPROG_CMD_REQUEST_CHAT_UPDATE) {
		//cmd_string = g_new(char, ma->auth_string_len + 4);
		//memcpy(cmd_string, ma->auth_string, ma->auth_string_len);
		//memcpy(cmd_string + ma->auth_string_len, co->payload, 4);
	//} else {
		cmd_string = (char*)g_memdup(ma->auth_string, ma->auth_string_len);
	//}
	cmd_string[9] = co->cmd & 0xff;

	size = purple_socket_write(ps, cmd_string, ma->auth_string_len);

	if (size != ma->auth_string_len) {
		if (size == -1) {
			purple_debug_error("metaprog", "Socket write error: %d\n", errno);
		} else {
			purple_debug_error("metaprog", "The socket has choked! Feed it carefully! %d %d\n", size, ma->auth_string_len);
		}
	}
	if (co->cmd == METAPROG_CMD_SEND_MESSAGE
			|| co->cmd == METAPROG_CMD_REQUEST_CHAT_FULL
			|| co->cmd == METAPROG_CMD_REQUEST_CHAT_UPDATE) {
		size = purple_socket_write(ps, co->payload, co->payload_size);
		if (size != co->payload_size) {
			if (size == -1) {
				purple_debug_error("metaprog", "Socket write error: %d\n", errno);
			} else {
				purple_debug_error("metaprog", "The socket has choked! Feed it carefully! %d %d\n", size, co->payload_size);
			}
		}
	}

	g_free(cmd_string);

	// process the response
	guchar buf[BUF_SIZE];
	GArray *packet = g_array_new(FALSE, FALSE, 1);

	int fd = purple_socket_get_fd(ps);
	struct pollfd fds[1] = { fd, POLLIN, 0 };

	guint32 required_size = metaprog_get_required_packet_size(co, packet->data, 0);
	gboolean successful_read = TRUE;

	guint8 eagain_number = 0;

	for (;;) {
		while ((size = purple_socket_read(ps, buf, BUF_SIZE)) > 0) {
			g_array_append_vals(packet, buf, size);
		}

		if (size == 0 && errno == EAGAIN) {
			eagain_number++;
		} else {
			eagain_number = 0;
		}

		if ((size < 0 && errno != EAGAIN) || eagain_number > EAGAIN_THRESHOLD) {
			purple_debug_error("metaprog", "errno = %d\n", errno);
			successful_read = FALSE;
			break;
		}

		if (required_size == -1) {
			required_size = metaprog_get_required_packet_size(co, packet->data, packet->len);
		}

		if (packet->len >= required_size) break;

		usleep(POLL_INTERVAL);
		poll(fds, 1, POLL_TIMEOUT);

		if (ma->connection_closed) {
			successful_read = FALSE;
			break;
		}
	}

	if (successful_read) {
		GError *error = NULL;

		if (co->cmd == METAPROG_CMD_PROBE) {
			gboolean known_auth = TRUE;

			enum METAPROG_CONNECTION auth_result = (int)metaprog_char_to_guint32(packet->data + 6);

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
				metaprog_send_cmd(ma, METAPROG_CMD_REQUEST_CHATS, NULL, 0, 0);
			}
		}
		else if (co->cmd == METAPROG_CMD_REQUEST_CHATS) {
			metaprog_socket_read_chats_list(packet->data, packet->len, ma, &error);

			if (error != NULL) {
				purple_debug_error("metaprog", error->message);
				g_free(error);
			}
		}
		else if (co->cmd == METAPROG_CMD_REQUEST_CHAT_FULL || co->cmd == METAPROG_CMD_REQUEST_CHAT_UPDATE) {
			metaprog_socket_read_chat_update(packet->data, packet->len, ma, metaprog_char_to_guint32(co->payload), &error);

			if (error != NULL) {
				purple_debug_error("metaprog", error->message);
				g_free(error);
			}
		}
		else if (co->cmd == METAPROG_CMD_SEND_MESSAGE) {
			// noop
		}
		else {
			purple_debug_error("metaprog", "Unknown incoming data, please report this to developers:");
			for (int i = 0; i < packet->len; i ++) {
				purple_debug_error("metaprog", "buf[%d] = %x\n", i, packet->data[i]);
			}
		}
	} else {
		metaprog_retry_cmd(co, _("Socket read failure"));
		return;
	}

	g_array_free(packet, TRUE);

	if (!ma->connection_closed) {
		purple_socket_destroy(ps);
	}

	if (successful_read) {
		metaprog_util_free_cmd_object(co);

		metaprog_next_cmd(ma);
	}
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

	metaprog_send_cmd(ma, METAPROG_CMD_PROBE, NULL, 0, 0);
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
	ma->reconnect_threshold = -1;

	ma->cmd_queue =	g_queue_new();

	ma->default_group = metaprog_get_or_create_default_group(NULL);

	ma->connection_closed = FALSE;

	metaprog_auth_string(ma);

	ma->chats_list = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, metaprog_util_free_chat);

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
		metaprog_util_free_cmd_object(co);
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

	opt = purple_account_option_int_new(_("Connection retry number"), CONNECTION_RETRY_NUMBER, 5);
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
	// prpl_info->send_im = metaprog_send_im;
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
	PLUGIN_VERSION,							/* version */
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
	// prpl_info->send = metaprog_send_im;
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
		"version",     PLUGIN_VERSION,
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
