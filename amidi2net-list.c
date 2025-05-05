/*
 * mDNS service browsing
 */

#include "amidi2net.h"
#include <getopt.h>

static void usage(void)
{
	printf("amidi2net-list: Browse Network MIDI 2.0 UDP servers\n\n"
	       "usage: amidi2net-list [options]\n\n"
	       "options:\n"
	       "  -t,--timeout=<MSEC>: exit timeout in msec\n"
	       "  -a,--all: browse also local host\n");
}

static const struct option long_opts[] = {
	{"timeout", 1, 0, 't'},
	{"all", 1, 0, 'a'},
	{}
};

static int list_callback(const char *name, const char *address,
			 int port, bool ipv6, const char *ep_name,
			 const char *prod_id, void *priv_data)
{
	printf("%s\n", name);
	printf("  Protocol: %s\n", ipv6 ? "ipv6" : "ipv4");
	printf("  Host: %s\n", address);
	printf("  Port: %u\n", port);
	if (ep_name)
		printf("  Endpoint: %s\n", ep_name);
	if (prod_id)
		printf("  Product-Id: %s\n", prod_id);
	fflush(stdout);
	return 0;
}

int main(int argc, char **argv)
{
	unsigned int timeout_msec = 1500;
	int ignore_local = 1;
	int c, opt_idx;

	while ((c = getopt_long(argc, argv, "t:a",
				long_opts, &opt_idx)) != -1) {
		switch (c) {
		case 't':
			timeout_msec = atoi(optarg);
			break;
		case 'a':
			ignore_local = 0;
			break;
		default:
			usage();
			return 1;
		}
	}

	am2n_mdns_lookup_service(timeout_msec, ignore_local, list_callback,
				 NULL);
	return 0;
}
