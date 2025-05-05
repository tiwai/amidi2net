/*
 * amidinet2-server: Network MIDI2 server
 */

#include "amidi2net.h"
#include "options.h"
#include <getopt.h>

#define DEFAULT_EP_NAME		"amidi2net-server"
#define DEFAULT_PROD_ID		VERSION

#define DEFAULT_PORT		0	/* automatic assignment */
static int port = DEFAULT_PORT;

#ifdef SUPPORT_MDNS
#define DEFAULT_SERVICE_NAME	"amidi2net"
static const char *service_name = DEFAULT_SERVICE_NAME;
#endif

#ifdef SUPPORT_AUTH
static const char *username;
static const char *secret;
static bool auth_forced;
#endif

static struct am2n_config config;

static void usage(void)
{
	printf("usage: amidi2net-server [options] device-name\n"
	       "options:\n"
	       SERVER_CONFIG_USAGE
	       "  -n,--service-name=<NAME>: service name string\n"
	       "  -p,--port=<PORT>: use the specific UDP port number\n"
#ifdef SUPPORT_AUTH
	       "  -u,--user=<NAME>: use user-authentication with the given name\n"
	       "  -x,--secret=<STR>: secret / password for authentication\n"
	       "  --auth-forced: no fallback authentication\n"
#endif
	       );
}

enum {
	OPT_AUTH_FORCED = 0x2000,
};

#ifdef SUPPORT_MDNS
#define MDNS_OPT "n"
#else
#define MDNS_OPT ""
#endif

#ifdef SUPPORT_AUTH
#define AUTH_OPT "u:x:"
#else
#define AUTH_OPT ""
#endif

static const struct option long_opts[] = {
	{"port", 1, 0, 'p'},
#ifdef SUPPORT_MDNS
	{"service-name", 1, 0, 'n'},
#endif
#ifdef SUPPORT_AUTH
	{"user", 1, 0, 'u'},
	{"secret", 1, 0, 'x'},
	{"auth-forced", 0, 0, OPT_AUTH_FORCED},
#endif
	SERVER_CONFIG_GETOPT_LONG,
	{}
};

int main(int argc, char **argv)
{
	struct am2n_server_ctx *server;
	struct am2n_mdns_ctx *mdns;
	int c, opt_idx, err;

	am2n_config_init(&config);
	config.ep_name = DEFAULT_EP_NAME;
	config.prod_id = DEFAULT_PROD_ID;

	while ((c = getopt_long(argc, argv, "p:" SERVER_CONFIG_GETOPT MDNS_OPT AUTH_OPT,
				long_opts, &opt_idx)) != -1) {
		err = am2n_config_parse_option(&config, true, c, optarg);
		if (err < 0)
			return 1;
		else if (err > 0)
			continue;
		switch (c) {
		case 'p':
			port = atoi(optarg);
			break;
#ifdef SUPPORT_MDNS
		case 'n':
			service_name = optarg;
			break;
#endif
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
		case OPT_AUTH_FORCED:
			auth_forced = true;
			break;
#endif
		default:
			usage();
			return 1;
		}
	}

#ifdef SUPPORT_AUTH
	if (username && !secret) {
		error("Set the password with --secret option");
		return 1;
	}
#endif

	server = am2n_server_init(&config);
	if (!server) {
		error("Unable to create server context");
		return 1;
	}

#ifdef SUPPORT_AUTH
	am2n_set_auth(&server->core, username, secret, auth_forced);
#endif

	if (am2n_io_init(&server->core) < 0) {
		error("Unable to set up I/O backend");
		goto error;
	}

	if (am2n_server_open_socket(server, port, false) < 0) {
		error("Unable to open socket for ipv4");
		goto error;
	}
	if (config.ipv6 && am2n_server_open_socket(server, server->ipv4.port, true) < 0) {
		error("Unable to open socket for ipv6");
		goto error;
	}

#ifdef SUPPORT_MDNS
	mdns = am2n_server_publish_mdns(server, service_name);
	if (!mdns) {
		error("ERROR: Unable to publish mDNS");
		goto error;
	}
#endif

	am2n_server_loop(server);

#ifdef SUPPORT_MDNS
	am2n_server_quit_mdns(mdns);
#endif
	am2n_server_free(server);
	return 0;

 error:
	am2n_server_free(server);
	return 1;
}
