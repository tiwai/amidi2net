/*
 * amidinet2: Network MIDI2 client
 */

#include "amidi2net.h"
#include "options.h"
#include <getopt.h>
#include <netdb.h>

#define DEFAULT_EP_NAME		"amidi2net-client"
#define DEFAULT_PROD_ID		VERSION

static struct am2n_config config;
static sock_addr_t host_addr;

static void usage(void)
{
	printf("amidi2net-client: ALSA Network MIDI 2.0 UDP client program\n\n"
	       "usage:\n"
	       "amidi2net-client [options] <server-address> <port>\n"
	       "  <server-address> = IP address or name of the Network MIDI server host\n"
	       "  <port> = UDP port of the Network MIDI host\n\n"
#ifdef SUPPORT_MDNS
	       "amidi2net-client [options] -l <service-name>\n"
	       "  <service-name> = mDNS service name\n\n"
#endif
	       "options:\n"
	       CLIENT_CONFIG_USAGE
	       );
}

#ifdef SUPPORT_MDNS
#define MDNS_OPT "l:"
#else
#define MDNS_OPT ""
#endif

static const struct option long_opts[] = {
#ifdef SUPPORT_AUTH
	{"user", 1, 0, 'u'},
	{"secret", 1, 0, 'x'},
#endif
	CLIENT_CONFIG_GETOPT_LONG,
#ifdef SUPPORT_MDNS
	{"lookup", 1, 0, 'l'},
#endif
	{}
};

static int get_addr(const char *server, const char *port, bool ipv6, void *addr)
{
	struct addrinfo hints;
	struct addrinfo *result;
	int len;

	memset(&hints, 0, sizeof(hints));
	if (ipv6)
		hints.ai_family = AF_INET6;
	else
		hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	if (getaddrinfo(server, port, &hints, &result) < 0 || !result)
		return -1;

	len = result->ai_addrlen;
	memcpy(addr, result->ai_addr, len);
	freeaddrinfo(result);
	return len;
}

#ifdef SUPPORT_MDNS
static const char *target_name;
static bool target_found;

static int mdns_callback(const char *name, const char *address,
			 int port, bool ipv6, const char *ep_name,
			 const char *prod_id, void *priv_data)
{
	char port_name[16];

	if (strcmp(name, target_name))
		return 0;

	snprintf(port_name, sizeof(port_name), "%d", port);
	if (get_addr(address, port_name, ipv6, &host_addr) < 0) {
		error("Cannot get IP address for %s:%s", address, port_name);
	} else {
		log("host %s port %d found for service %s", address, port, name);
		target_found = 1;
		config.ipv6 = ipv6;
	}
	return 1;
}
#endif /* SUPPORT_MDNS */

int main(int argc, char **argv)
{
	struct am2n_client_ctx *client;
	const char *server;
	const char *port;
	int c, opt_idx, err;
#ifdef SUPPORT_MDNS
	const char *lookup = NULL;
#endif

	am2n_config_init(&config);
	config.ep_name = DEFAULT_EP_NAME;
	config.prod_id = DEFAULT_PROD_ID;

	while ((c = getopt_long(argc, argv, CLIENT_CONFIG_GETOPT MDNS_OPT,
				long_opts, &opt_idx)) != -1) {
		err = am2n_config_parse_option(&config, false, c, optarg);
		if (err < 0)
			return 1;
		else if (err > 0)
			continue;
		switch (c) {
#ifdef SUPPORT_MDNS
		case 'l':
			lookup = optarg;
			break;
#endif
		default:
			usage();
			return 1;
		}
	}

#ifdef SUPPORT_MDNS
	if (lookup) {
		target_name = lookup;
		am2n_mdns_lookup_service(1500, false, mdns_callback, NULL);
		if (!target_found) {
			error("Cannot find service %s", lookup);
			return 1;
		}
	} else
#endif
	{
		if (optind + 1 >= argc) {
			usage();
			return 1;
		}
		server = argv[optind];
		port = argv[optind + 1];
		if (get_addr(server, port, config.ipv6, &host_addr) < 0) {
			error("Cannot get IP address for %s:%s", server, port);
			return 1;
		}
	}

	client = am2n_client_init(&host_addr, &config);
	if (!client) {
		error("Client allocation error");
		return 1;
	}

	if (am2n_auth_init(&client->core) < 0)
		goto error;

	if (am2n_io_init(&client->core) < 0) {
		error("Unable to set up I/O backend");
		goto error;
	}

	if (am2n_client_handshake(client) < 0) {
		error("Failed handshaking");
		goto error;
	}

	am2n_client_loop(client);

	am2n_client_free(client);
	return 0;

 error:
	am2n_client_free(client);
	return 1;
}
