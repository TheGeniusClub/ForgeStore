/*
 * This file is part of ForgeStore
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program;
 * if not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2026 TheGeniusClub
 */

#include <unistd.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>

static volatile sig_atomic_t should_exit = 0;

static void signal_handler(int sig) {
    (void)sig;
    should_exit = 1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <daemon> [args...]\n", argv[0]);
        return 1;
    }

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    const char *daemon_path = argv[1];
    char **daemon_argv = &argv[1];

    int backoff_ms = 500;

    while (!should_exit) {
        struct timespec child_start;
        clock_gettime(CLOCK_MONOTONIC, &child_start);

        pid_t pid = fork();

        if (pid < 0) {
            perror("updaemon: fork failed");
            usleep(100000);
            continue;
        }

        if (pid == 0) {
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            setpriority(PRIO_PROCESS, 0, 10);
            execv(daemon_path, daemon_argv);
            perror("updaemon: execv failed");
            _exit(127);
        }

        int status;
        waitpid(pid, &status, 0);

        if (should_exit) break;

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long lived_ms = (now.tv_sec - child_start.tv_sec) * 1000 +
                        (now.tv_nsec - child_start.tv_nsec) / 1000000;

        if (lived_ms > 30000) {
            backoff_ms = 500;
        } else {
            usleep(backoff_ms * 1000);
            if (backoff_ms < 30000) backoff_ms *= 2;
        }
    }

    return 0;
}
