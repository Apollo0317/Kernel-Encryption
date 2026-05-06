#include "nl4_route.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

int nl4_infer_src_ip(const struct in_addr *remote_addr,
		     struct in_addr *src_addr)
{
	char remote_ip[INET_ADDRSTRLEN];
	char cmd[128];
	char line[512];
	FILE *fp;
	char *token;
	int ret = -EINVAL;

	if (!inet_ntop(AF_INET, remote_addr, remote_ip, sizeof(remote_ip)))
		return -EINVAL;

	snprintf(cmd, sizeof(cmd), "ip route get %s", remote_ip);
	fp = popen(cmd, "r");
	if (!fp)
		return -errno;

	if (!fgets(line, sizeof(line), fp)) {
		pclose(fp);
		return -EINVAL;
	}
	for (token = strtok(line, " \t\r\n"); token;
	     token = strtok(NULL, " \t\r\n")) {
		if (strcmp(token, "src") == 0) {
			char *src = strtok(NULL, " \t\r\n");

			if (src && inet_pton(AF_INET, src, src_addr) == 1)
				ret = 0;
			break;
		}
	}
	pclose(fp);
	return ret;
}
