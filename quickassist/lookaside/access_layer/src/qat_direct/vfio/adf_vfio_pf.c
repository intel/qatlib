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

#define DEVVFIO_DIR "/sys/bus/pci/drivers"
#define DEVICE_NAME_LENGTH 5

char device_names[] = { "4xxx,420xx" };

static int filter_pf_in_use(const struct dirent *entry)
{
    unsigned node, bus, dev, func;

    /* Deduce the entry is a PF if the name has 4 parts in format n:b:d.f */
    if (sscanf(entry->d_name, "%x:%x:%x.%x", &node, &bus, &dev, &func) != 4)
        return 0;

    return 1;
}

static int is_qat_dev_present(char *dev_name)
{
    int i;
    int status = CPA_STATUS_FAIL;
    struct dirent **namelist;
    int32_t number_of_dev;

    number_of_dev = scandir(DEVVFIO_DIR, &namelist, NULL, alphasort);

    if (number_of_dev < 0)
    {
        return status;
    }

    for (i = 0; i < number_of_dev; i++)
    {
        if (strncmp(namelist[i]->d_name, dev_name, DEVICE_NAME_LENGTH) == 0)
        {
            status = CPA_STATUS_SUCCESS;
            break;
        }
    }

    for (i = 0; i < number_of_dev; i++)
    {
        free(namelist[i]);
    }
    free(namelist);

    return status;
}

Cpa32S adf_vfio_init_pfs_info(icp_accel_pf_info_t *pf_info, size_t pf_info_len)
{
    unsigned domain, bus, dev, func;
    struct dirent **namelist;
    int32_t i, number_of_pfs = 0, total_no_pfs = 0;
    int status = CPA_STATUS_FAIL;
    char dev_path[QATMGR_MAX_STRLEN] = { '\0' };
    char *device_name = strtok(device_names, ",");

    ICP_CHECK_FOR_NULL_PARAM(pf_info);
    while (device_name != NULL)
    {
        status = is_qat_dev_present(device_name);
        if (status == CPA_STATUS_SUCCESS)
        {
            snprintf(
                dev_path, sizeof(dev_path), "%s/%s", DEVVFIO_DIR, device_name);
            number_of_pfs =
                scandir(dev_path, &namelist, &filter_pf_in_use, alphasort);
            /* This shows scandir dir failed. */
            if (number_of_pfs < 0)
            {
                ADF_ERROR("Failed to scan directory %s\n", DEVVFIO_DIR);
                return CPA_STATUS_FAIL;
            }
            total_no_pfs += number_of_pfs;
            if (pf_info_len < total_no_pfs)
            {
                ADF_ERROR("Given pf info array length is too small for %d "
                          "number of PFs\n",
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
                sscanf(namelist[i]->d_name,
                       "%x:%x:%x.%x",
                       &domain,
                       &bus,
                       &dev,
                       &func);
                pf_info[i].pkg_id = i;
                pf_info[i].domain = domain;
                pf_info[i].bdf =
                    ((0xFF & bus) << 8) + ((0x1F & dev) << 3) + (0x07 & func);
                strncpy(
                    pf_info[i].device_gen, device_name, ADF_DEVICE_TYPE_LENGTH);
                free(namelist[i]);
            }
            free(namelist);
        }
        device_name = strtok(NULL, ","); /* Get the next device name */
    }
    return total_no_pfs;
}
