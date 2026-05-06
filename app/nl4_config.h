#ifndef NL4_CONFIG_H
#define NL4_CONFIG_H

#include "nl4_common.h"

#include <sys/types.h>

struct nl4_rule_vec {
	struct nl4_rule_cfg *items;
	size_t len;
	size_t cap;
};

void nl4_rule_vec_free(struct nl4_rule_vec *rules);
int nl4_rule_vec_push(struct nl4_rule_vec *rules,
		      const struct nl4_rule_cfg *rule);
ssize_t nl4_find_rule_index(const struct nl4_rule_vec *rules,
			    const struct in_addr *remote_addr,
			    uint8_t service_side, uint16_t service_port);
int nl4_load_rules(struct nl4_rule_vec *rules);
int nl4_save_rules(const struct nl4_rule_vec *rules);
int nl4_config_flush(void);
int nl4_config_list(void);

#endif
