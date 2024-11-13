#include <bpf/libbpf.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include "simple_filter.bpf.skel.h"

static bool quit = false;

void sigint(int unused)
{
	quit = true;
}

int main(int argc, char *argv[])
{
	int ifindex, key=0, count, ret, prog_fd;
	struct simple_filter *skel;

	signal(SIGINT, sigint);

	skel = simple_filter__open_and_load();
	if (!skel)
		exit(EXIT_FAILURE);

	prog_fd = bpf_program__fd(skel->progs.drop_icmp);
	ifindex = if_nametoindex("lo");
	ret = bpf_xdp_attach(ifindex, prog_fd, 0, NULL);

	while(!quit){
		ret = bpf_map__lookup_elem(skel->maps.drop_count, &key, sizeof(int),
				&count, sizeof(int), 0);
		if (!ret)
			fprintf(stdout, "%d packets dropped\n", count);
		sleep(2);
	}
	bpf_xdp_detach(ifindex, 0, NULL);
	simple_filter__destroy(skel);

	return 0;
}

