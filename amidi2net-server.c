/*
 * amidinet2-server: Network MIDI2 server
 */

#include "amidi2net.h"
#include "options.h"
#include "packet.h"
#include <getopt.h>

#define DEFAULT_EP_NAME		"amidi2net-server"
#define DEFAULT_PROD_ID		VERSION

#define DEFAULT_PORT		0	/* automatic assignment */
static int port = DEFAULT_PORT;

#define DEFAULT_SERVICE_NAME	"amidi2net"
static const char *service_name = DEFAULT_SERVICE_NAME;

static struct am2n_config config;

static void usage(void)
{
	printf("amidi2net-server: ALSA Network MIDI 2.0 UDP server program\n\n"
	       "usage:\n"
	       "amidi2net-server [options]\n\n"
	       "options:\n"
	       SERVER_CONFIG_USAGE
	       "  -p,--port=<PORT>: use the specific UDP port number\n"
	       "  -n,--service-name=<NAME>: mDNS service name string\n"
	       );
}

enum {
	OPT_AUTH_FORCED = 0x2000,
};

#define MDNS_OPT "n:"

static const struct option long_opts[] = {
	{"port", 1, 0, 'p'},
	{"service-name", 1, 0, 'n'},
	SERVER_CONFIG_GETOPT_LONG,
	{}
};

int main(int argc, char **argv)
{
	struct am2n_server_ctx *server;
	struct am2n_mdns_ctx *mdns;
	int c, opt_idx, err;

	am2n_config_init(&config, true);
	config.ep_name = DEFAULT_EP_NAME;
	config.prod_id = DEFAULT_PROD_ID;

	while ((c = getopt_long(argc, argv, "p:" SERVER_CONFIG_GETOPT,
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
		case 'n':
			service_name = optarg;
			break;
		case 'h':
		default:
			usage();
			return 1;
		}
	}

	server = am2n_server_init(&config);
	if (!server) {
		error("Unable to create server context");
		return 1;
	}

	if (am2n_auth_init(&server->core) < 0)
		goto error;

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

	mdns = am2n_server_publish_mdns(server, service_name);
	if (!mdns) {
		error("ERROR: Unable to publish mDNS");
		goto error;
	}

	am2n_server_loop(server);

	am2n_server_quit_mdns(mdns);
	am2n_server_free(server);
	return 0;

 error:
	am2n_server_free(server);
	return 1;
}
