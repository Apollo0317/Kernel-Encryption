#include "nl4_common.h"

#include <errno.h>
#include <string.h>

const char *nl4_service_side_name(uint8_t side)
{
	switch (side) {
	case NL4_SERVICE_REMOTE:
		return "remote-service";
	case NL4_SERVICE_LOCAL:
		return "local-service";
	case NL4_SERVICE_ALL_PORTS:
		return "all-ports";
	default:
		return "unknown";
	}
}

int nl4_parse_service_side_name(const char *name, uint8_t *side)
{
	if (strcmp(name, "remote-service") == 0)
		*side = NL4_SERVICE_REMOTE;
	else if (strcmp(name, "local-service") == 0)
		*side = NL4_SERVICE_LOCAL;
	else if (strcmp(name, "all-ports") == 0)
		*side = NL4_SERVICE_ALL_PORTS;
	else
		return -EINVAL;

	return 0;
}
