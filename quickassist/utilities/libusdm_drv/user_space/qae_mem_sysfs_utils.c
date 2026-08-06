/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/
/**
 ****************************************************************************
 * @file qae_mem_sysfs_utils.c
 *
 * Helpers to read hugepage counters from sysfs and to initialise the
 * per-process hugepage configuration from environment variables.
 *
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include "qae_mem_utils.h"
#include "qae_mem_user_utils.h"
#include "qae_mem_utils_common.h"
#include "qae_mem_sysfs_utils.h"
#include "qae_mem_hugepage_utils.h"

/* Max environment variable value 64k */
#define MAX_ENV_VAL (0x10000)

/* Read the current free 2M hugepage count from sysfs. */
API_LOCAL
int __qae_read_free_hugepages(void)
{
    unsigned long val = 0;

    if (parse_sysfs_value(SYSFS_2M_FREE_HUGEPAGES, &val) < 0)
        return -EIO;

    return val;
}

/* parse_uint32_env - parse an env var string as uint32_t.
 *
 * NULL or empty string (var exported without a value) → *out = 0.
 * Non-empty malformed string                          → *out = 0 (warn).
 * Non-empty valid decimal integer ≤ MAX_ENV_VAL → *out = parsed value.
 */
static void parse_uint32_env(const char *name, const char *env, uint32_t *out)
{
    char *endptr = NULL;
    unsigned long val;

    /* used only in CMD_DEBUG, suppress warning in non-debug builds */
    UNUSED(name);

    *out = 0;
    if (!env || *env == '\0')
        return;

    errno = 0;
    val = strtoul(env, &endptr, 10);
    if (errno != 0 || endptr == env || *endptr != '\0' || val > MAX_ENV_VAL)
    {
        CMD_DEBUG("%s: invalid %s value '%s', treating as zero\n",
                  __func__,
                  name,
                  env);
        return;
    }
    *out = (uint32_t)val;
}

/* __qae_hugepage_config_init - Read QAT_MAX_2M_HPG_PER_PROCESS env var to
 * determine hugepage mode and set per-process page budget.
 *
 * Decision rules:
 *   - Var not exported                   → 4K mode (return 0)
 *   - Var exported, zero (or no value)   → 4K mode (return 0)
 *   - Var non-zero, nr_hugepages=0       → error (return -EINVAL)
 *   - Var non-zero, nr_hugepages>0       → 2M mode, budget=env value
 *
 * Returns the env variable value as budget on success, 0 for 4K mode,
 * or -EINVAL on error.  The caller must propagate a negative return.
 */
API_LOCAL
int __qae_hugepage_config_init(void)
{
    const char *env_2m = getenv("QAT_MAX_2M_HPG_PER_PROCESS");
    uint32_t val_2m = 0;

    if (!env_2m)
    {
        CMD_DEBUG("%s: no hugepage env var set, defaulting to 4K mode.\n",
                  __func__);
        return 0;
    }

    parse_uint32_env("QAT_MAX_2M_HPG_PER_PROCESS", env_2m, &val_2m);

    if (val_2m > 0)
    {
        DIR *hp_dir = qae_opendir(SYSFS_2M_HUGEPAGES_DIR);
        unsigned long nr_hp = 0;

        if (!hp_dir)
        {
            CMD_ERROR("%s: No 2M huge pages configured in the system\n",
                      __func__);
            return -EINVAL;
        }
        closedir(hp_dir);

        if (parse_sysfs_value(SYSFS_2M_NR_HUGEPAGES, &nr_hp) < 0)
            return -EIO;

        if (!nr_hp)
        {
            CMD_ERROR("%s: No 2M huge pages configured in the system\n",
                      __func__);
            return -EINVAL;
        }
        CMD_DEBUG("%s: 2M mode: nr_hugepages=%lu budget=%u\n",
                  __func__,
                  nr_hp,
                  val_2m);
        return (int32_t)val_2m;
    }
    else
    {
        CMD_DEBUG("%s: hugepage env var is zero, defaulting to 4K mode.\n",
                  __func__);
        return 0;
    }
}

/* Parse a sysfs (or other) file containing one unsigned long value.
 * Returns 0 on success, -EINVAL on error.
 */
int parse_sysfs_value(const char *filename, unsigned long *val)
{
    FILE *f;
    char buf[BUFSIZ];
    char *end = NULL;

    if ((f = qae_fopen(filename, "r")) == NULL)
    {
        CMD_ERROR("%s(): qae_fopen failed for %s\n", __func__, filename);
        return -EINVAL;
    }

    if (qae_fgets(buf, sizeof(buf), f) == NULL)
    {
        CMD_ERROR(
            "%s(): qae_fgets failed for sysfs value %s\n", __func__, filename);
        fclose(f);
        return -EINVAL;
    }
    errno = 0;
    *val = strtoul(buf, &end, 0);
    if (errno != 0 || (buf[0] == '\0') || (end == NULL) ||
        ((*end != '\n') && (*end != '\0')) || (*val > MAX_ENV_VAL))
    {
        CMD_ERROR("%s(): cannot parse sysfs value %s\n", __func__, filename);
        fclose(f);
        return -EINVAL;
    }
    fclose(f);
    return 0;
}
