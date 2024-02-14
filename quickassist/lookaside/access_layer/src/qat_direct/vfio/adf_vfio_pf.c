/*****************************************************************************
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
 *****************************************************************************/
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <linux/vfio.h>
#include <libgen.h>
#include <sys/stat.h>

#include "adf_kernel_types.h"

#include "cpa.h"
#include "icp_accel_devices.h"
#include "icp_platform.h"
#include "qat_mgr.h"
#include "qat_log.h"

#define DEVVFIO_DIR "/sys/bus/pci/drivers/4xxx"
#define DEVVFIO_DIR_420XX "/sys/bus/pci/drivers/420xx"

static int filter_pf_in_use(const struct dirent *entry)
{
    unsigned node, bus, dev, func;

    /* Deduce the entry is a PF if the name has 4 parts in format n:b:d.f */
    if (sscanf(entry->d_name, "%x:%x:%x.%x", &node, &bus, &dev, &func) != 4)
        return 0;

    return 1;
}

Cpa32S adf_vfio_init_pfs_info(icp_accel_pf_info_t *pf_info, size_t pf_info_len)
{
    unsigned node, bus, dev, func;
    struct dirent **namelist;
    char *devvfio_dir;
    int32_t i, number_of_pfs;
    struct stat st = { 0 };

    ICP_CHECK_FOR_NULL_PARAM(pf_info);

    if (stat(DEVVFIO_DIR, &st) == 0)
    {
        number_of_pfs =
            scandir(DEVVFIO_DIR, &namelist, &filter_pf_in_use, alphasort);
        devvfio_dir = DEVVFIO_DIR;
    }
    else if (stat(DEVVFIO_DIR_420XX, &st) == 0)
    {
        number_of_pfs =
            scandir(DEVVFIO_DIR_420XX, &namelist, &filter_pf_in_use, alphasort);
        devvfio_dir = DEVVFIO_DIR_420XX;
    }
    else
    {
        /* This shows stat DIR failed, assume dir does not exist. */
        ADF_DEBUG("None of %s and %s paths exists in the system,"
                  " unable to detect PFs\n",
                  DEVVFIO_DIR,
                  DEVVFIO_DIR_420XX);
        return 0;
    }

    /* This shows scandir dir failed. */
    if (number_of_pfs < 0)
    {
        ADF_DEBUG("Failed to scan directory %s\n", devvfio_dir);
        return CPA_STATUS_FAIL;
    }

    if (pf_info_len < number_of_pfs)
    {
        ADF_ERROR(
            "Given pf info array length is too small for %d number of PFs\n",
            number_of_pfs);
        for (i = 0; i < number_of_pfs; i++)
        {
            free(namelist[i]);
        }
        free(namelist);
        return CPA_STATUS_INVALID_PARAM;
    }

    for (i = 0; i < number_of_pfs; i++)
    {
        sscanf(namelist[i]->d_name, "%x:%x:%x.%x", &node, &bus, &dev, &func);
        pf_info[i].pkg_id = i;
        pf_info[i].domain = node;
        pf_info[i].bdf = (node << 16) + ((0xFF & bus) << 8) +
                         ((0x1F & dev) << 3) + (0x07 & func);
        strcpy(pf_info[i].device_gen, QAT_GEN4_STR);
        free(namelist[i]);
    }
    free(namelist);

    return number_of_pfs;
}
