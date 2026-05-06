#include "nl4_module.h"

#include "nl4_common.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

bool nl4_module_is_loaded(void)
{
	FILE *fp;
	char name[128];
	bool loaded = false;

	fp = fopen("/proc/modules", "r");
	if (!fp)
		return false;

	while (fscanf(fp, "%127s%*[^\n]\n", name) == 1) {
		if (strcmp(name, NL4_MODULE_NAME) == 0) {
			loaded = true;
			break;
		}
	}
	fclose(fp);
	return loaded;
}

static const char *find_module_path(void)
{
	static const char *paths[] = {
		"kmod/nl4_bypass.ko",
		"./nl4_bypass.ko",
		"../kmod/nl4_bypass.ko",
	};
	const char *env_path = getenv("NL4_MODULE_PATH");
	size_t i;

	if (env_path && access(env_path, R_OK) == 0)
		return env_path;
	for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		if (access(paths[i], R_OK) == 0)
			return paths[i];
	}
	return NULL;
}

static int run_program(const char *path, char *const argv[])
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return -errno;
	if (pid == 0) {
		execvp(path, argv);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) < 0)
		return -errno;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -EIO;

	return 0;
}

int nl4_module_on(bool do_apply, int (*apply_fn)(void))
{
	int err;

	if (nl4_module_is_loaded()) {
		printf("module already loaded\n");
		if (!do_apply)
			return 0;
	} else {
		const char *module_path = find_module_path();
		char *const insmod_argv[] = {
			"insmod",
			(char *)module_path,
			NULL,
		};

		if (!module_path) {
			fprintf(stderr, "nl4enc: module file not found; run make build-krn first\n");
			return NL4_ERR_QUIET;
		}
		err = run_program("insmod", insmod_argv);
		if (err < 0)
			return err;
		if (do_apply)
			printf("module loaded\n");
	}

	if (do_apply)
		return apply_fn();

	printf("module loaded; run `nl4enc apply` to activate configured rules.\n");
	return 0;
}

int nl4_module_stop(void)
{
	char *const rmmod_argv[] = {
		"rmmod",
		NL4_MODULE_NAME,
		NULL,
	};

	if (!nl4_module_is_loaded()) {
		printf("module not loaded\n");
		return 0;
	}

	return run_program("rmmod", rmmod_argv);
}
