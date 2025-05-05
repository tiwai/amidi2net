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

static void usage(void)
{
	printf("usage: amidi2net-client [options] server port\n"
	       "options:\n"
	       CLIENT_CONFIG_USAGE
#ifdef SUPPORT_AUTH
	       "  -u,--user=<NAME>: use user-authentication with the given name\n"
	       "  -x,--secret=<STR>: secret / password for authentication\n"
#endif
	       );
}

#ifdef SUPPORT_AUTH
#define AUTH_OPT "u:x:"
#else
#define AUTH_OPT ""
#endif

static const struct option long_opts[] = {
#ifdef SUPPORT_AUTH
	{"user", 1, 0, 'u'},
	{"secret", 1, 0, 'x'},
#endif
	SERVER_CONFIG_GETOPT_LONG,
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

int main(int argc, char **argv)
{
	struct am2n_client_ctx *client;
	const char *server;
	const char *port;
	sock_addr_t addr;
	int c, opt_idx, err;
#ifdef SUPPORT_AUTH
	const char *username = NULL;
	const char *secret = NULL;
#endif

	am2n_config_init(&config);
	config.ep_name = DEFAULT_EP_NAME;
	config.prod_id = DEFAULT_PROD_ID;

	while ((c = getopt_long(argc, argv, CLIENT_CONFIG_GETOPT AUTH_OPT,
				long_opts, &opt_idx)) != -1) {
		err = am2n_config_parse_option(&config, false, c, optarg);
		if (err < 0)
			return 1;
		else if (err > 0)
			continue;
		switch (c) {
#ifdef SUPPORT_AUTH
		case 'u':
			username = optarg;
			if (strlen(username) > 64) {
				error("Too long user name");
				return 1;
			}
			break;
		case 'x':
			secret = optarg;
			break;
#endif
		default:
			usage();
			return 1;
		}
	}

	if (optind + 1 >= argc) {
		usage();
		return 1;
	}

#ifdef SUPPORT_AUTH
	if (username && !secret) {
		error("Set the password with --secret option");
		return 1;
	}
#endif

	server = argv[optind];
	port = argv[optind + 1];

	if (get_addr(server, port, config.ipv6, &addr) < 0) {
		error("Cannot get IP address for %s:%s", server, port);
		return 1;
	}

	client = am2n_client_init(&addr, &config);
	if (!client) {
		error("Client allocation error");
		return 1;
	}

#ifdef SUPPORT_AUTH
	am2n_set_auth(&client->core, username, secret, false);
#endif

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
