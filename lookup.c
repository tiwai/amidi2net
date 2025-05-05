/*
 * mDNS service lookup
 */

#include "amidi2net.h"

#include <avahi-common/simple-watch.h>
#include <avahi-client/client.h>
#include <avahi-client/lookup.h>

static AvahiSimplePoll *simple_poll;
static AvahiClient *client;
static int browsing = 0;

static am2n_lookup_callback_t _priv_callback;
static void *_priv_data;
static int _ignore_local;

#define SERVICE_TYPE	"_midi2._udp"

#define EP_NAME_PFX	"UMPEndpointName="
#define PROD_ID_PFX	"ProductInstanceId="

static void service_resolver_callback(AvahiServiceResolver *r,
				      AvahiIfIndex interface,
				      AvahiProtocol protocol,
				      AvahiResolverEvent event,
				      const char *name,
				      const char *type,
				      const char *domain,
				      const char *host_name,
				      const AvahiAddress *a,
				      uint16_t port,
				      AvahiStringList *txt,
				      AvahiLookupResultFlags flags,
				      void *userdata)
{
	char address[AVAHI_ADDRESS_STR_MAX];
	const char *ep_name = NULL;
	const char *prod_id = NULL;
	AvahiStringList *t;

	switch (event) {
	case AVAHI_RESOLVER_FOUND:
		avahi_address_snprint(address, sizeof(address), a);

		for (t = txt; t; t = t->next) {
			if (!strncmp(t->text, EP_NAME_PFX, sizeof(EP_NAME_PFX) - 1))
				ep_name = t->text + sizeof(EP_NAME_PFX) - 1;
			else if (!strncmp(t->text, PROD_ID_PFX, sizeof(PROD_ID_PFX) - 1))
				prod_id = t->text + sizeof(PROD_ID_PFX) - 1;
		}

		if (_priv_callback(name, address, port,
				   protocol == AVAHI_PROTO_INET6,
				   ep_name, prod_id, _priv_data))
			avahi_simple_poll_quit(simple_poll);
		break;
	default:
		break;
	}

	avahi_service_resolver_free(r);
}

static void service_browser_callback(AvahiServiceBrowser *b,
				     AvahiIfIndex interface,
				     AvahiProtocol protocol,
				     AvahiBrowserEvent event,
				     const char *name,
				     const char *type,
				     const char *domain,
				     AvahiLookupResultFlags flags,
				     void *userdata)
{
	switch (event) {
	case AVAHI_BROWSER_NEW:
		if (_ignore_local && (flags & AVAHI_LOOKUP_RESULT_LOCAL))
			break;
		avahi_service_resolver_new(client, interface,
					   protocol, name, type,
					   domain, AVAHI_PROTO_UNSPEC, 0,
					   service_resolver_callback,
					   NULL);
		break;
	case AVAHI_BROWSER_FAILURE:
		avahi_simple_poll_quit(simple_poll);
		break;
	default:
		break;
	}
}

static void client_callback(AvahiClient *c, AvahiClientState state,
			    void *userdata)
{
	switch (state) {
	case AVAHI_CLIENT_FAILURE:
		avahi_simple_poll_quit(simple_poll);
		break;
	case AVAHI_CLIENT_S_REGISTERING:
	case AVAHI_CLIENT_S_RUNNING:
	case AVAHI_CLIENT_S_COLLISION:
		if (!browsing) {
			if (!avahi_service_browser_new(c, AVAHI_IF_UNSPEC,
						       AVAHI_PROTO_UNSPEC,
						       SERVICE_TYPE,
						       NULL,
						       0,
						       service_browser_callback,
						       NULL))
				avahi_simple_poll_quit(simple_poll);
			browsing = 1;
		}
		break;
	default:
		break;
	}
}

static time_t base_time;
static uint64_t cur_time(struct timeval *tv)
{
	return (uint64_t)(tv->tv_sec - base_time) * 1000000UL + tv->tv_usec;
}

int am2n_mdns_lookup_service(int timeout_msec, bool ignore_local,
			     am2n_lookup_callback_t callback, void *data)
{
	uint64_t timeout;
	int64_t n;
	struct timeval tv;
	int error;

	_priv_callback = callback;
	_priv_data = data;
	_ignore_local = ignore_local;

	simple_poll = avahi_simple_poll_new();
	if (!simple_poll) {
		fprintf(stderr, "Can't create avahi simple poll\n");
		return -1;
	}

	client = avahi_client_new(avahi_simple_poll_get(simple_poll), 0,
				  client_callback, NULL, &error);
	if (!client) {
		fprintf(stderr, "Can't create avahi client\n");
		return -1;
	}

	gettimeofday(&tv, NULL);
	base_time = tv.tv_sec;
	timeout = cur_time(&tv) + timeout_msec * 1000UL;

	while (!avahi_simple_poll_iterate(simple_poll, timeout_msec)) {
		gettimeofday(&tv, NULL);
		n = timeout - cur_time(&tv);
		if (n <= 0)
			break;
		timeout_msec = (n + 999) / 1000;
	}

	return 0;
}
