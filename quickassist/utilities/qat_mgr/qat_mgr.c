/*****************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
 * 
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 * 
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 * 
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *   The full GNU General Public License is included in this distribution
 *   in the file called LICENSE.GPL.
 * 
 *   Contact Information:
 *   Intel Corporation
 * 
 *   BSD LICENSE
 * 
 *   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
 *   All rights reserved.
 * 
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 * 
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * 
 *
 *****************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/un.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/poll.h>
#include <stddef.h>
#include <libgen.h>
#include <getopt.h>
#include <sys/resource.h>
#include <signal.h>
#include "icp_platform.h"
#include "qat_log.h"
#include "qat_mgr.h"

static char *sock_file = QATMGR_SOCKET;
static int parent_pipe = 0;

#define PIDFILE_ENV "PIDFILE"
#define PIDFILE_DEFAULT "/run/qat/qatmgr.pid"

#define QUEUE_LENGTH 5
#define MAX_CLIENTS 3

#define MAX_DEVS 256

#define POLICY_MIN 0
#define POLICY_MAX MAX_DEVS

#define DEBUG_LEVEL_MIN 0
#define DEBUG_LEVEL_MAX 2

#define CLIENT_TIMEOUT_DEFAULT_MS 1000

#define MAX_ERR_STRING_LEN 1024

struct ucred
{
    pid_t pid; /* process ID of the sending process */
    uid_t uid; /* user ID of the sending process */
    gid_t gid; /* group ID of the sending process */
};

void *handle_client(void *arg)
{
    int bytes_r;
    int bytes_w = 0;
    int index = -1;
    pid_t tid;
    int conn_fd;
    struct qatmgr_msg_req msgreq;
    struct qatmgr_msg_rsp msgrsp;
    char *section_name = NULL;
    struct pollfd fd;
    int ret = -1;

    conn_fd = (intptr_t)arg;
    tid = pthread_self();

    qat_log(LOG_LEVEL_DEBUG,
            "connect_fd %d, tid %ul, client_timeout %d ms\n",
            conn_fd,
            tid,
            CLIENT_TIMEOUT_DEFAULT_MS);

    memset(&fd, 0, sizeof(fd));
    fd.fd = conn_fd;
    fd.events = POLLIN;

    ret = poll(&fd, 1, CLIENT_TIMEOUT_DEFAULT_MS);
    if (ret > 0)
    {
        while ((bytes_r = read(conn_fd, (void *)&msgreq, sizeof(msgreq))) > 0)
        {
            qat_log(LOG_LEVEL_DEBUG,
                    "tid %d, Received %u bytes: Message type %d, length %d\n",
                    tid,
                    bytes_r,
                    msgreq.hdr.type,
                    msgreq.hdr.len);

            handle_message(&msgreq, &msgrsp, &section_name, tid, &index);

            /* Send response */
            bytes_w = write(conn_fd, (const void *)&msgrsp, msgrsp.hdr.len);
            if (bytes_w < 0)
                break;

            if (bytes_w < msgrsp.hdr.len)
                qat_log(LOG_LEVEL_ERROR, "Socket write incomplete\n");
        }

        /* If the socket is closed while a section is still held then release it
         */
        if (index >= 0 && section_name)
        {
            qat_log(
                LOG_LEVEL_INFO, "Force release of section %s\n", section_name);
            release_section(index,
                            tid,
                            section_name,
                            strnlen(section_name, QATMGR_MAX_STRLEN));
            free(section_name);
        }

        if (bytes_r < 0 || bytes_w < 0)
        {
            qat_log(LOG_LEVEL_ERROR, "Socket read/write error %d\n", errno);
        }
        else if (bytes_r == 0)
        {
            qat_log(LOG_LEVEL_INFO, "EOF tid %d\n", tid);
        }
    }
    else if (ret == 0)
    {
        qat_log(LOG_LEVEL_ERROR,
                "qatmgr timed out waiting on data from the client, connect_fd "
                "%d, tid %ul\n",
                conn_fd,
                tid);
    }
    else
    {
        qat_log(LOG_LEVEL_ERROR, "Failed to poll client fd\n");
    }

    close(conn_fd);
    return NULL;
}

void usage(char *prog)
{
    printf("Usage: %s  [options]\n", prog);
    printf(" -h, -help\n");
    printf(" -d, --debug=LEVEL (%d..%d)\n", DEBUG_LEVEL_MIN, DEBUG_LEVEL_MAX);
    printf(" -f, --foreground\n");
    printf(" -p, --policy=POLICY\n");
    printf("    0 (default) - One VF from each PF per process\n");
    printf("    1           - One VF per process\n");
    printf("    >1          - n VFs per process\n");
    printf("    max value   - %d\n", MAX_DEVS);
    printf(" -v, --version\n");
}

static void version(char *prog)
{
    char qatmgr_ver_str[VER_STR_LEN];
    VER_STR(THIS_LIB_VERSION, qatmgr_ver_str);
    printf("%s %d.%02d.%d\n",
           prog,
           SAL_INFO2_DRIVER_SW_VERSION_MAJ_NUMBER,
           SAL_INFO2_DRIVER_SW_VERSION_MIN_NUMBER,
           SAL_INFO2_DRIVER_SW_VERSION_PATCH_NUMBER);
}

static int check_pidfile(const char *filename, char **err_string)
{
    FILE *pidfile;
    int pid;
    int num;

    if (!(pidfile = fopen(filename, "r")))
        return 0;

    num = fscanf(pidfile, "%d", &pid);
    fclose(pidfile);

    if (num != 1)
        return 0;

    if (getsid(pid) < 0)
        return 0;

    *err_string = malloc(MAX_ERR_STRING_LEN);
    if (*err_string)
        snprintf(*err_string,
                 MAX_ERR_STRING_LEN,
                 "Another qatmgr may be running -- pid=%d",
                 pid);
    return 1;
}

static int write_pidfile(const char *filename, char **err_string)
{
    FILE *pidfile;

    if (!(pidfile = fopen(filename, "w")))
    {
        *err_string = malloc(MAX_ERR_STRING_LEN);
        if (*err_string)
            snprintf(*err_string,
                     MAX_ERR_STRING_LEN,
                     "Cannot open %s, %s\n",
                     filename,
                     strerror(errno));
        return 1;
    }

    fprintf(pidfile, "%d\n", (int)getpid());
    fclose(pidfile);
    return 0;
}

static void daemonise(void)
{
    int pid;
    int fd;
    int pipefd[2];
    struct rlimit rl;

    /* Pipe used to indicate success/failure from child */
    if (pipe(pipefd))
    {
        qat_log(
            LOG_LEVEL_ERROR, "Failed to create pipe. %s\n", strerror(errno));
        exit(1);
    }

    pid = fork();

    if (pid < 0)
    {
        qat_log(LOG_LEVEL_ERROR, "Failed to fork. %s\n", strerror(errno));
    }
    else if (pid > 0)
    {
        /* Parent */
        char msg[64];
        int len;

        close(pipefd[1]);
        memset(msg, 0, sizeof(msg));
        len = read(pipefd[0], msg, sizeof(msg) - 1);
        if (len > 0)
        {
            /* Error from the child */
            qat_log(LOG_LEVEL_ERROR, "%s\n", msg);
            exit(1);
        }
        else if (len < 0)
        {
            qat_log(LOG_LEVEL_ERROR, "Pipe error %s\n", strerror(errno));
            exit(1);
        }
        else
        {
            exit(0);
        }
    }
    else
    {
        /* Child */
        close(pipefd[0]);
        parent_pipe = pipefd[1];
        setsid();

        /* Fork a second time */
        pid = fork();

        if (pid < 0)
        {
            qat_log(LOG_LEVEL_ERROR, "Failed to fork. %s\n", strerror(errno));
        }
        else if (pid > 0)
        {
            exit(0);
        }
        else
        {
            /* Final daemon process */

            if (chdir("/") < 0)
            {
                qat_log(
                    LOG_LEVEL_ERROR, "Failed to chdir. %s\n", strerror(errno));
            }
#define MAX_FILES 1024
            if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
                rl.rlim_max = MAX_FILES;
            else if (rl.rlim_max == RLIM_INFINITY)
                rl.rlim_max = MAX_FILES;

            /* Close descriptors except for pipe */
            for (fd = 3; fd < rl.rlim_max; fd++)
            {
                if (fd != pipefd[1])
                    close(fd);
            }

            umask(0117);
        }
    }
}

static int write_parent(int fd, char *buf)
{
    int len;

    if (!buf)
        return -1;

    len = strnlen(buf, MAX_ERR_STRING_LEN);
    if (len < MAX_ERR_STRING_LEN)
        return write(fd, buf, len + 1);
    else
        return -1;
}

static int parse_and_validate_arg(char *arg, int *val, int min, int max)
{
    if (!arg)
        return -EINVAL;

    char *end_ptr;
    long long temp = strtoll(arg, &end_ptr, 10);

    if (errno == ERANGE || *arg == 0 || *end_ptr != 0 || temp < min ||
        temp > max)
        return -EINVAL;

    *val = (int)temp;
    return 0;
}

void signal_handler(int sig_num)
{
    if (sig_num == SIGPIPE)
    {
        qat_log(LOG_LEVEL_DEBUG, "qatmgr received SIGPIPE signal\n");
    }
}

int main(int argc, char **argv)
{
    struct sockaddr_un sockaddr;
    int listen_fd;
    int connect_fd;
    int ret;
    pthread_t client_tid;
    struct ucred ucred;
    unsigned len;
    unsigned num_devices;
    struct qatmgr_dev_data dev_list[MAX_DEVS];
    unsigned list_size = ARRAY_SIZE(dev_list);
    int i;
    const char *mgr_opts = "hvd:p:f";
    const struct option mgr_optl[] = {{"help", 0, NULL, 'h'},
                                      {"version", 0, NULL, 'v'},
                                      {"debug", 1, NULL, 'd'},
                                      {"policy", 1, NULL, 'p'},
                                      {"foreground", 0, NULL, 'f'},
                                      {NULL, 0, NULL, 0}};
    int opt;
    int policy = 0;
    int foreground = 0;
    char *env;
    char pid_filename[256];
    char *err_string;

    env = getenv(PIDFILE_ENV);
    if (env)
        strncpy(pid_filename, env, sizeof(pid_filename) - 1);
    else
        strncpy(pid_filename, PIDFILE_DEFAULT, sizeof(pid_filename) - 1);
    pid_filename[sizeof(pid_filename) - 1] = 0;

    opt = getopt_long(argc, argv, mgr_opts, mgr_optl, NULL);
    while (opt != -1)
    {
        switch (opt)
        {
            case '?':
                usage(argv[0]);
                exit(1);
            case 'h':
                usage(argv[0]);
                exit(0);
            case 'v':
                version(argv[0]);
                exit(0);
            case 'd':
                if (parse_and_validate_arg(
                        optarg, &debug_level, DEBUG_LEVEL_MIN, DEBUG_LEVEL_MAX))
                {
                    printf("Invalid debug level %s\n", optarg);
                    exit(1);
                }
                break;
            case 'f':
                foreground = 1;
                break;
            case 'p':
                if (parse_and_validate_arg(
                        optarg, &policy, POLICY_MIN, POLICY_MAX))
                {
                    printf("Invalid policy %s\n", optarg);
                    exit(1);
                }
                break;
            default:
                printf("Unknown argument\n");
        }
        opt = getopt_long(argc, argv, mgr_opts, mgr_optl, NULL);
    }

    if (!foreground)
    {
        daemonise();
        if (check_pidfile(pid_filename, &err_string) ||
            write_pidfile(pid_filename, &err_string))
        {
            if (err_string)
            {
                ret = write_parent(parent_pipe, err_string);
                free(err_string);
            }
            else
            {
                ret = write_parent(parent_pipe, "Unable to set pidfile");
            }
            if (ret)
                perror("Failed to write error string");
            exit(-1);
        }
    }

    signal(SIGPIPE, signal_handler);

    if (qat_mgr_get_dev_list(&num_devices, dev_list, list_size, 0))
    {
        printf("get_dev_list failed\n");
    }

    if (num_devices == 0)
    {
        if (foreground)
            qat_log(LOG_LEVEL_ERROR, "No QAT device found");
        else
            write_parent(parent_pipe, "No QAT device found");

        exit(-1);
    }

    for (i = 0; i < num_devices; i++)
    {
        qat_log(LOG_LEVEL_INFO,
                "Device %d, %X,  %04x:%02x:%02x.%01x\n",
                i,
                dev_list[i].bdf,
                BDF_NODE(dev_list[i].bdf),
                BDF_BUS(dev_list[i].bdf),
                BDF_DEV(dev_list[i].bdf),
                BDF_FUN(dev_list[i].bdf));
    }

    if ((ret = qat_mgr_build_data(dev_list, num_devices, policy, 0)))
    {
        if (foreground)
            qat_log(
                LOG_LEVEL_ERROR, "Failed qat_mgr_build_data. ret %d\n", ret);
        else
            write_parent(parent_pipe, "Failed qat_mgr_build_data");
        exit(ret);
    }

    listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0)
    {
        perror("socket error");
        qat_mgr_cleanup_cfg();
        exit(-1);
    }

    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sun_family = AF_UNIX;
    strncpy(sockaddr.sun_path, sock_file, sizeof(sockaddr.sun_path) - 1);
    sockaddr.sun_path[sizeof(sockaddr.sun_path) - 1] = 0;

    /* Remove an existing file if it exists */
    unlink(sock_file);

    ret = bind(listen_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (ret < 0)
    {
        perror("bind error");
        qat_mgr_cleanup_cfg();
        exit(-1);
    }

    ret = listen(listen_fd, QUEUE_LENGTH);
    if (ret < 0)
    {
        perror("listen error");
        qat_mgr_cleanup_cfg();
        exit(-1);
    }

    if (init_section_data_mutex())
    {
        perror("init section_data mutex error");
        qat_mgr_cleanup_cfg();
        exit(-1);
    }

    if (!foreground)
        close(parent_pipe);

    while (1)
    {
        connect_fd = accept(listen_fd, NULL, NULL);
        if (connect_fd < 0)
        {
            perror("accept error");
            continue;
        }
        len = sizeof(struct ucred);
        ret = getsockopt(connect_fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len);
        if (ret < 0)
            perror("getsockopt error");
        else
            qat_log(LOG_LEVEL_DEBUG, "Client pid %ld\n", (long)ucred.pid);

        ret = pthread_create(
            &client_tid, NULL, handle_client, (void *)(intptr_t)connect_fd);
        pthread_detach(client_tid);
        qat_log(LOG_LEVEL_DEBUG, "Child thread %lu\n", client_tid);
    }

    destroy_section_data_mutex();
    qat_mgr_cleanup_cfg();
    return 0;
}
