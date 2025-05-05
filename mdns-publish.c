/*
 * mDNS service publishing
 */

#include <stdio.h>
#include <stdlib.h>

#include <avahi-client/client.h>
#include <avahi-client/publish.h>

#include <avahi-common/alternative.h>
#include <avahi-common/thread-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/timeval.h>

#include "amidi2net.h"

struct am2n_mdns_ctx {
	struct am2n_server_ctx *server;
	AvahiClient *client;
	AvahiThreadedPoll *apoll;
	AvahiEntryGroup *group;
	char *name;
};

static void create_services(struct am2n_mdns_ctx *ctx, AvahiClient *c);
static void rename_service(struct am2n_mdns_ctx *ctx);

static void entry_group_callback(AvahiEntryGroup *g, AvahiEntryGroupState state,
				 void *userdata)
{
	struct am2n_mdns_ctx *ctx = userdata;

	ctx->group = g;
	switch (state) {
	case AVAHI_ENTRY_GROUP_COLLISION:
		rename_service(ctx);
		create_services(ctx, avahi_entry_group_get_client(g));
		break;

	case AVAHI_ENTRY_GROUP_FAILURE:
		log("Entry group failure: %s\n",
		    avahi_strerror(avahi_client_errno(avahi_entry_group_get_client(g))));
		avahi_threaded_poll_quit(ctx->apoll);
		break;
	default:
		break;
	}
}

/* A service name collision with a remote service, pick up a new name */
static void rename_service(struct am2n_mdns_ctx *ctx)
{
	char *n;

	n = avahi_alternative_service_name(ctx->name);
	avahi_free(ctx->name);
	ctx->name = n;

	log("Service name collision, renaming service to '%s'\n", ctx->name);
}

static void create_services(struct am2n_mdns_ctx *ctx, AvahiClient *c)
{
	char epname[150];
	char prodid[150];
	int proto;
	int ret;

	snprintf(epname, sizeof(epname), "UMPEndpointName=%s",
		 ctx->server->core.ep_name);
	snprintf(prodid, sizeof(prodid), "ProductInstanceId=%s",
		 ctx->server->core.prod_id);

 again:
	if (!ctx->group) {
		ctx->group = avahi_entry_group_new(c, entry_group_callback, ctx);
		if (!ctx->group) {
			log("avahi_entry_group_new() failed: %s\n",
			    avahi_strerror(avahi_client_errno(c)));
			goto fail;
		}
	}

	if (!avahi_entry_group_is_empty(ctx->group))
		return;

	if (ctx->server->ipv6.sockfd >= 0)
		proto = AVAHI_PROTO_UNSPEC;
	else
		proto = AVAHI_PROTO_INET;

	ret = avahi_entry_group_add_service(ctx->group, AVAHI_IF_UNSPEC, proto,
					    0, ctx->name, "_midi2._udp",
					    NULL, NULL,
					    ctx->server->ipv4.port,
					    epname, prodid, NULL);
	if (ret < 0) {
		if (ret == AVAHI_ERR_COLLISION) {
			rename_service(ctx);
			avahi_entry_group_reset(ctx->group);
			goto again;
		}

		log("Failed to add _midi2._udp service: %s\n",
		    avahi_strerror(ret));
		goto fail;
	}

	ret = avahi_entry_group_commit(ctx->group);
	if (ret < 0) {
		log("Failed to commit entry group: %s\n",
		    avahi_strerror(ret));
		goto fail;
	}

	return;

fail:
	avahi_threaded_poll_quit(ctx->apoll);
}

static void client_callback(AvahiClient *c, AvahiClientState state,
			    void *userdata)
{
	struct am2n_mdns_ctx *ctx = userdata;

	switch (state) {
	case AVAHI_CLIENT_S_RUNNING:
		create_services(ctx, c);
		break;

	case AVAHI_CLIENT_FAILURE:
		log("Client failure: %s\n",
		    avahi_strerror(avahi_client_errno(c)));
		avahi_threaded_poll_quit(ctx->apoll);
		break;

	case AVAHI_CLIENT_S_COLLISION:
	case AVAHI_CLIENT_S_REGISTERING:
		if (ctx->group)
			avahi_entry_group_reset(ctx->group);
		break;
	default:
		break;
	}
}

static void free_ctx(struct am2n_mdns_ctx *ctx)
{
	if (ctx->client)
		avahi_client_free(ctx->client);
	if (ctx->apoll)
		avahi_threaded_poll_free(ctx->apoll);
	avahi_free(ctx->name);
	free(ctx);
}

struct am2n_mdns_ctx *
am2n_server_publish_mdns(struct am2n_server_ctx *server, const char *service)
{
	struct am2n_mdns_ctx *ctx;
	int error;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->server = server;

	ctx->apoll = avahi_threaded_poll_new();
	if (!ctx->apoll) {
		log("Failed to create poll object.\n");
		free(ctx);
		return NULL;
	}

	ctx->name = avahi_strdup(service);

	ctx->client = avahi_client_new(avahi_threaded_poll_get(ctx->apoll), 0,
				       client_callback, ctx, &error);
	if (!ctx->client) {
		log("Failed to create client: %s\n", avahi_strerror(error));
		free_ctx(ctx);
		return NULL;
	}

	avahi_threaded_poll_start(ctx->apoll);
	return ctx;
}

void am2n_server_quit_mdns(struct am2n_mdns_ctx *ctx)
{
	avahi_threaded_poll_stop(ctx->apoll);
	free_ctx(ctx);
}
