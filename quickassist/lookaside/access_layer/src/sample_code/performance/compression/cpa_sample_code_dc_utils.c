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
 *****************************************************************************
 * @file cpa_sample_code_dc_utils.c
 *
 * @defgroup compressionThreads
 *
 * @ingroup compressionThreads
 *
 * @description
 * Contains function prototypes and #defines used throughout code
 * and macros
 *
 ***************************************************************************/

#include "cpa_sample_code_utils_common.h"
#include "cpa_sample_code_dc_perf.h"
#include "cpa_sample_code_crypto_utils.h"
#include "cpa_sample_code_framework.h"
#include "cpa_sample_code_dc_utils.h"
#include "qat_perf_latency.h"
#include "qat_perf_utils.h"
#include "qat_perf_cycles.h"
#include "icp_sal_poll.h"
#include "cpa.h"

#define MAX_SESSION_REMOVE_RETRIES (15)

static struct
{
    corpus_type_t corpusType;
    Cpa32U corpusFileIndex;
} extCorpusInfo = {0, 0};

typedef struct
{
    corpus_type_t corpusType;
    const char *const corpusName;
    corpus_data_t corpusData;
} corpusInfo;

static compute_test_result_func_t pfuncPassCriteria = NULL;
static Cpa32U setupCnVRequestFlag = CNV_FLAG_DEFAULT;

Cpa32U dcPollingInterval_g = OPERATIONS_POLLING_INTERVAL;
EXPORT_SYMBOL(dcPollingInterval_g);
CpaBoolean gUseStatefulLite = CPA_FALSE;
EXPORT_SYMBOL(gUseStatefulLite);
CpaDcChecksum gChecksum = CPA_DC_NONE;
EXPORT_SYMBOL(gChecksum);
CpaDcAutoSelectBest gAutoSelectBestMode = CPA_DC_ASB_DISABLED;
EXPORT_SYMBOL(gAutoSelectBestMode);
CpaBoolean testOverFlow_g = CPA_FALSE;
EXPORT_SYMBOL(testOverFlow_g);
CpaBoolean gRetainPartials = CPA_FALSE;
EXPORT_SYMBOL(gRetainPartials);
long dcPollingThreadsInterval_g = DEFAULT_POLL_INTERVAL_NSEC;
EXPORT_SYMBOL(dcPollingThreadsInterval_g);
CpaBoolean disableAdditionalCmpbufferSize_g = CPA_FALSE;
EXPORT_SYMBOL(disableAdditionalCmpbufferSize_g);

#if defined(USER_SPACE) && defined(SUPPORTED_FEAT_EPOLL) &&                    \
    defined(STV_TEST_CODE)
/**< Global mask to track which instances should use which response mode (up to
 * 64 instances) */
static Cpa64U dcInstanceResponseModeMask_g = 0;
/**< Response mode to apply when explicitly configured */
static CpaInstanceResponseMode dcConfiguredResponseMode_g =
    CPA_INST_RX_NOTIFY_NONE;
/**< Flag to track if response mode has been explicitly configured */
static CpaBoolean dcResponseModeConfigured_g = CPA_FALSE;
#endif /* USER_SPACE && SUPPORTED_FEAT_EPOLL && STV_TEST_CODE */

#if defined(USER_SPACE) && defined(SUPPORTED_FEAT_INT_COALESCING_TIMER) &&     \
    defined(STV_TEST_CODE)
/**< Global mask to track which DC instances should have the coalescing timer
 * applied (up to 64 instances) */
static Cpa64U dcInstanceCoalescingTimerMask_g = 0;
/**< Coalescing timer value (in nanoseconds) to apply when explicitly
 * configured */
static Cpa32U dcConfiguredCoalescingTimerNs_g = 0;
/**< Flag to track if the coalescing timer has been explicitly configured */
static CpaBoolean dcCoalescingTimerConfigured_g = CPA_FALSE;
#endif /* USER_SPACE && SUPPORTED_FEAT_INT_COALESCING_TIMER && STV_TEST_CODE   \
        */

#if DC_API_VERSION_AT_LEAST(3, 1)
CpaStatus setLZ4BlockIndependence(CpaBoolean val);
#endif

CpaStatus setTestOverFlow(CpaBoolean value);
CpaStatus setFuzzFile(const char *fileName);
CpaStatus printFuzzFile(void);

volatile CpaBoolean enableDcDpFlatsToSGLConv_g = CPA_FALSE;
EXPORT_SYMBOL(enableDcDpFlatsToSGLConv_g);
volatile Cpa32U dcDpNumFlatsPerSGL_g = 4;
EXPORT_SYMBOL(dcDpNumFlatsPerSGL_g);
#if DC_API_VERSION_AT_LEAST(3, 2)
volatile Cpa32U dcDpPartialReadBufferMask_g = 0;
EXPORT_SYMBOL(dcDpPartialReadBufferMask_g);
volatile CpaBoolean dcDpEnableZeroPad_g = CPA_FALSE;
EXPORT_SYMBOL(dcDpEnableZeroPad_g);
#endif /* #if DC_API_VERSION_AT_LEAST(3, 2) */
#if DC_API_VERSION_AT_LEAST(3, 1)
volatile CpaBoolean LZ4BlockIndependence_g = CPA_TRUE;
CpaStatus setLZ4BlockIndependence(CpaBoolean val)
{
    if (val != 0)
    {
        LZ4BlockIndependence_g = CPA_TRUE;
    }
    else
    {
        LZ4BlockIndependence_g = CPA_FALSE;
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(LZ4BlockIndependence_g);
EXPORT_SYMBOL(setLZ4BlockIndependence);
#endif
CpaStatus setChecksum(CpaDcChecksum checksum)
{
    gChecksum = checksum;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setChecksum);

CpaStatus setAutoSelectBestMode(CpaDcAutoSelectBest mode)
{
    gAutoSelectBestMode = mode;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setAutoSelectBestMode);

CpaStatus disableAdditionalCmpbufferSize(CpaBoolean value)
{
    disableAdditionalCmpbufferSize_g = value;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(disableAdditionalCmpbufferSize);

CpaStatus setTestOverFlow(CpaBoolean value)
{
    testOverFlow_g = value;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setTestOverFlow);

void setDcPollingThreadsInterval(long interval)
{
    dcPollingThreadsInterval_g = interval;
}
EXPORT_SYMBOL(setDcPollingThreadsInterval);

#if defined(USER_SPACE) && defined(SUPPORTED_FEAT_EPOLL) &&                    \
    defined(STV_TEST_CODE)
/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      mapUserResponseModeToEnum
 *
 * @description
 *      Maps user input values (0|1) to actual CpaInstanceResponseMode enum
 * values (1|2). This is needed because the enum values are
 * CPA_INST_RX_NOTIFY_NONE=1 and CPA_INST_RX_NOTIFY_BY_EVENT=2, but users
 * typically specify 0 for polling and 1 for event notification.
 *
 * @param[in]  userMode    User input mode (0 for polling, 1 for event)
 *
 * @retval CpaInstanceResponseMode  The corresponding enum value
 *
 *****************************************************************************/
static CpaInstanceResponseMode mapUserResponseModeToEnum(Cpa32U userMode)
{
    switch (userMode)
    {
        case 0:
            return CPA_INST_RX_NOTIFY_NONE; /* Maps 0 -> 1 (polling) */
        case 1:
            return CPA_INST_RX_NOTIFY_BY_EVENT; /* Maps 1 -> 2 (event) */
        default:
            PRINT_ERR("Invalid response mode %d, defaulting to polling mode\n",
                      userMode);
            return CPA_INST_RX_NOTIFY_NONE;
    }
}

CpaStatus setDcInstanceResponseMode(CpaInstanceResponseMode responseMode)
{
    dcConfiguredResponseMode_g = responseMode;
    dcResponseModeConfigured_g = CPA_TRUE;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setDcInstanceResponseMode);

CpaStatus setDcInstanceResponseModeWithMask(Cpa32U userMode, Cpa64U mask)
{
    CpaInstanceResponseMode enumMode = mapUserResponseModeToEnum(userMode);

    /* Set both the response mode and the mask */
    setDcInstanceResponseMode(enumMode);
    setDcInstanceResponseModeMask(mask);

    PRINT("Set DC response mode %d (enum %d) for instances with mask 0x%llx\n",
          userMode,
          enumMode,
          (unsigned long long)mask);
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setDcInstanceResponseModeWithMask);

CpaStatus setDcInstanceResponseModeForRange(Cpa32U userMode,
                                            Cpa16U startInst,
                                            Cpa16U endInst)
{
    Cpa64U mask = 0;
    Cpa16U i;

    /* Validate range */
    if (startInst > endInst || endInst >= 64)
    {
        PRINT_ERR("Invalid instance range %d-%d (must be 0-63)\n",
                  startInst,
                  endInst);
        return CPA_STATUS_FAIL;
    }

    /* Build mask for the range */
    for (i = startInst; i <= endInst; i++)
    {
        mask |= (1ULL << i);
    }

    /* Use the combined function */
    setDcInstanceResponseModeWithMask(userMode, mask);
    PRINT("Configured instances %d-%d with response mode %d\n",
          startInst,
          endInst,
          userMode);
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setDcInstanceResponseModeForRange);

CpaInstanceResponseMode getDcInstanceResponseMode(void)
{
    return dcConfiguredResponseMode_g;
}
EXPORT_SYMBOL(getDcInstanceResponseMode);

void setDcInstanceResponseModeMask(Cpa64U mask)
{
    dcInstanceResponseModeMask_g = mask;
}
EXPORT_SYMBOL(setDcInstanceResponseModeMask);

Cpa64U getDcInstanceResponseModeMask(void)
{
    return dcInstanceResponseModeMask_g;
}
EXPORT_SYMBOL(getDcInstanceResponseModeMask);

CpaStatus configureDcInstanceResponseModeForAll(
    CpaInstanceResponseMode responseMode)
{
    Cpa16U numInstances = 0;
    Cpa16U numDecompInst = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* Get the number of DC (compression) instances */
    status = cpaDcGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to get DC instances count for response mode "
                  "configuration\n");
        return CPA_STATUS_FAIL;
    }
    status =
        cpaGetNumInstances(CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION, &numDecompInst);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to get Decomp instances count for response mode "
                  "configuration\n");
        return CPA_STATUS_FAIL;
    }
    if (numInstances == 0 && numDecompInst == 0)
    {
        /* No DC instances in the active config (e.g. an SSL/CY-only
         * section). Nothing to configure; not a fatal condition. */
        PRINT("No DC and Decomp instances available - skipping DC and Decomp "
              "response mode configuration\n");
        return CPA_STATUS_SUCCESS;
    }
    {
        /* Set mask for all instances (up to 64 instances supported) */
        Cpa64U allInstancesMask;
        Cpa16U totalInstances = numInstances + numDecompInst;

        if (totalInstances >= 64)
        {
            allInstancesMask = 0xFFFFFFFFFFFFFFFFULL; /* All 64 bits set */
        }
        else
        {
            allInstancesMask = (1ULL << totalInstances) -
                               1; /* Set bits 0 to totalInstances-1 */
        }

        setDcInstanceResponseMode(responseMode);
        setDcInstanceResponseModeMask(allInstancesMask);

        PRINT("Explicitly configured response mode %d for %d instances "
              "(%d comp + %d decomp, mask: 0x%llx)\n",
              responseMode,
              totalInstances,
              numInstances,
              numDecompInst,
              (unsigned long long)allInstancesMask);
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(configureDcInstanceResponseModeForAll);

CpaStatus configureDcInstanceResponseModeForHalf(
    CpaInstanceResponseMode responseMode)
{
    Cpa16U numInstances = 0;
    Cpa16U numDecompInst = 0;
    Cpa16U half_numInstances = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* Get the number of DC instances */
    status = cpaDcGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to get DC instances count for response mode "
                  "configuration\n");
        return CPA_STATUS_FAIL;
    }
    status =
        cpaGetNumInstances(CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION, &numDecompInst);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to get Decomp instances count for response mode "
                  "configuration\n");
        return CPA_STATUS_FAIL;
    }
    if (numInstances == 0 && numDecompInst == 0)
    {
        /* No DC instances in the active config (e.g. an SSL/CY-only
         * section). Nothing to configure; not a fatal condition. */
        PRINT("No DC and Decomp instances available - skipping DC and Decomp "
              "response mode configuration\n");
        return CPA_STATUS_SUCCESS;
    }
    {
        Cpa16U totalInstances = numInstances + numDecompInst;
        Cpa16U halfComp = numInstances / 2;
        Cpa16U halfDecomp = numDecompInst / 2;
        Cpa64U halfInstancesMask = 0;
        Cpa16U b;

        half_numInstances = halfComp + halfDecomp;

        /* Lower half of comp bits (0..halfComp-1) */
        for (b = 0; b < halfComp && b < 64; b++)
        {
            halfInstancesMask |= (1ULL << b);
        }
        /* Lower half of decomp bits, placed after all comp bits */
        for (b = 0; b < halfDecomp && (numInstances + b) < 64; b++)
        {
            halfInstancesMask |= (1ULL << (numInstances + b));
        }

        setDcInstanceResponseMode(responseMode);
        setDcInstanceResponseModeMask(halfInstancesMask);

        PRINT("Explicitly configured response mode %d for HALF (%d of %d) "
              "instances (%d/%d comp + %d/%d decomp, mask: 0x%llx)\n",
              responseMode,
              half_numInstances,
              totalInstances,
              halfComp,
              numInstances,
              halfDecomp,
              numDecompInst,
              (unsigned long long)halfInstancesMask);
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(configureDcInstanceResponseModeForHalf);

CpaStatus setDcInstanceResponseModeByValue(Cpa32U userMode)
{
    CpaInstanceResponseMode enumMode = mapUserResponseModeToEnum(userMode);
    configureDcInstanceResponseModeForAll(enumMode);

    PRINT("Configured all DC instances: user input %d -> enum value %d\n",
          userMode,
          enumMode);
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setDcInstanceResponseModeByValue);

CpaBoolean isDcInstanceResponseModeConfigured(void)
{
    return dcResponseModeConfigured_g;
}
EXPORT_SYMBOL(isDcInstanceResponseModeConfigured);

CpaStatus clearDcInstanceResponseModeConfiguration(void)
{
    dcResponseModeConfigured_g = CPA_FALSE;
    /* Reset to a neutral value - actual library default will be queried
     * per-thread */
    dcConfiguredResponseMode_g = CPA_INST_RX_NOTIFY_NONE;
    dcInstanceResponseModeMask_g = 0;

    PRINT("Cleared DC instance response mode configuration\n");
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(clearDcInstanceResponseModeConfiguration);

CpaStatus applyDcInstanceResponseModeConfiguration(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa16U numInstances = 0;
    Cpa16U numDecompInstances = 0;
    CpaInstanceHandle *instances = NULL;
    Cpa64U instanceMask;
    Cpa16U i = 0;

    if (!isDcInstanceResponseModeConfigured())
    {
        /* No explicit configuration - nothing to apply */
        return CPA_STATUS_SUCCESS;
    }

    instanceMask = getDcInstanceResponseModeMask();
    if (instanceMask == 0)
    {
        /* Empty mask - nothing to apply */
        return CPA_STATUS_SUCCESS;
    }

    /* Get the number of DC (compression) instances */
    status = cpaDcGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to get DC instances count: %d\n", status);
        return status;
    }

    /* Also query pure decompression instances (cfg_services=decomp).
     * Mirrors applyDcInstanceCoalescingTimerConfiguration(). */
    {
        CpaStatus dstatus = cpaGetNumInstances(
            CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION, &numDecompInstances);
        if (CPA_STATUS_SUCCESS != dstatus)
        {
            numDecompInstances = 0;
        }
    }

    if (numInstances == 0 && numDecompInstances == 0)
    {
        PRINT_ERR("No DC or decompression instances available to apply "
                  "response mode\n");
        return CPA_STATUS_FAIL;
    }

    if (numInstances > 0)
    {
        /* Allocate memory for instance handles */
        instances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
        if (NULL == instances)
        {
            PRINT_ERR("Unable to allocate memory for DC instances\n");
            return CPA_STATUS_FAIL;
        }

        /* Get the instance handles */
        status = cpaDcGetInstances(numInstances, instances);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to get DC instances: %d\n", status);
            qaeMemFree((void **)&instances);
            return status;
        }
    }

    /* Apply response mode to compression instances specified in the mask */
    CpaInstanceResponseMode responseMode = getDcInstanceResponseMode();
    CpaInstanceResponseMode testMode = CPA_INST_RX_NOTIFY_NONE;

    for (i = 0; i < numInstances && i < 64; i++)
    {
        if (instanceMask & (1ULL << i))
        {
            status = cpaInstanceSetResponseMode(
                instances[i], CPA_ACC_SVC_TYPE_DATA_COMPRESSION, responseMode);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR(
                    "Failed to set response mode %d for DC instance %d: %d\n",
                    responseMode,
                    i,
                    status);
                /* Continue with other instances rather than failing completely
                 */
            }
            else
            {
                status = cpaInstanceGetResponseMode(
                    instances[i], CPA_ACC_SVC_TYPE_DATA_COMPRESSION, &testMode);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR(
                        "Failed to get response mode for DC instance %d: %d\n",
                        i,
                        status);
                    qaeMemFree((void **)&instances);
                    return status;
                }
                else if (testMode != responseMode)
                {
                    PRINT_ERR("Mismatch verifying response mode for DC "
                              "instance %d: set %d, got %d\n",
                              i,
                              responseMode,
                              testMode);
                    qaeMemFree((void **)&instances);
                    return CPA_STATUS_FAIL;
                }
                else
                {
                    PRINT("Verified response mode %d for DC instance %d\n",
                          testMode,
                          i);
                }
                // PRINT("Set response mode %d for DC instance %d\n",
                // responseMode, i);
            }
        }
    }

    if (instances != NULL)
    {
        qaeMemFree((void **)&instances);
        instances = NULL;
    }

    /* Now apply response mode to decompression instances (numDecompInstances
     * was queried earlier, mirroring
     * applyDcInstanceCoalescingTimerConfiguration()). */
    if (numDecompInstances > 0)
    {
        CpaInstanceHandle *decompInstances = NULL;

        decompInstances =
            qaeMemAlloc(sizeof(CpaInstanceHandle) * numDecompInstances);
        if (NULL == decompInstances)
        {
            PRINT_ERR("Unable to allocate memory for Decomp instances\n");
            return CPA_STATUS_FAIL;
        }
        status = cpaGetInstances(CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION,
                                 numDecompInstances,
                                 decompInstances);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to get Decomp instances: %d\n", status);
            qaeMemFree((void **)&decompInstances);
            return status;
        }

        for (i = 0; i < numDecompInstances && i < 64; i++)
        {
            if (instanceMask & (1ULL << i))
            {
                status = cpaInstanceSetResponseMode(
                    decompInstances[i],
                    CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION,
                    responseMode);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Failed to set response mode %d for Decomp "
                              "instance %d: %d\n",
                              responseMode,
                              i,
                              status);
                }
                else
                {
                    status = cpaInstanceGetResponseMode(
                        decompInstances[i],
                        CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION,
                        &testMode);
                    if (CPA_STATUS_SUCCESS != status)
                    {
                        PRINT_ERR("Failed to get response mode for Decomp "
                                  "instance %d: %d\n",
                                  i,
                                  status);
                        qaeMemFree((void **)&decompInstances);
                        return status;
                    }
                    else if (testMode != responseMode)
                    {
                        PRINT_ERR("Mismatch verifying response mode for "
                                  "Decomp instance %d: set %d, got %d\n",
                                  i,
                                  responseMode,
                                  testMode);
                        qaeMemFree((void **)&decompInstances);
                        return CPA_STATUS_FAIL;
                    }
                    else
                    {
                        PRINT("Verified response mode %d for Decomp "
                              "instance %d\n",
                              testMode,
                              i);
                    }
                }
            }
        }
        qaeMemFree((void **)&decompInstances);
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(applyDcInstanceResponseModeConfiguration);

#if defined(USER_SPACE) && defined(SUPPORTED_FEAT_INT_COALESCING_TIMER) &&     \
    defined(STV_TEST_CODE)
CpaStatus setDcInstanceCoalescingTimer(Cpa32U coalescingTimerInNs)
{
    dcConfiguredCoalescingTimerNs_g = coalescingTimerInNs;
    dcCoalescingTimerConfigured_g = CPA_TRUE;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setDcInstanceCoalescingTimer);

Cpa32U getDcInstanceCoalescingTimer(void)
{
    return dcConfiguredCoalescingTimerNs_g;
}
EXPORT_SYMBOL(getDcInstanceCoalescingTimer);

void setDcInstanceCoalescingTimerMask(Cpa64U mask)
{
    dcInstanceCoalescingTimerMask_g = mask;
}
EXPORT_SYMBOL(setDcInstanceCoalescingTimerMask);

Cpa64U getDcInstanceCoalescingTimerMask(void)
{
    return dcInstanceCoalescingTimerMask_g;
}
EXPORT_SYMBOL(getDcInstanceCoalescingTimerMask);

CpaBoolean isDcInstanceCoalescingTimerConfigured(void)
{
    return dcCoalescingTimerConfigured_g;
}
EXPORT_SYMBOL(isDcInstanceCoalescingTimerConfigured);

CpaStatus clearDcInstanceCoalescingTimerConfiguration(void)
{
    dcCoalescingTimerConfigured_g = CPA_FALSE;
    dcConfiguredCoalescingTimerNs_g = 0;
    dcInstanceCoalescingTimerMask_g = 0;

    PRINT("Cleared DC instance coalescing timer configuration\n");
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(clearDcInstanceCoalescingTimerConfiguration);

CpaStatus setDcInstanceCoalescingTimerWithMask(Cpa32U coalescingTimerInNs,
                                               Cpa64U mask)
{
    setDcInstanceCoalescingTimer(coalescingTimerInNs);
    setDcInstanceCoalescingTimerMask(mask);

    PRINT("Set DC coalescing timer %u ns for instances with mask 0x%llx\n",
          coalescingTimerInNs,
          (unsigned long long)mask);
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setDcInstanceCoalescingTimerWithMask);

CpaStatus setDcInstanceCoalescingTimerForRange(Cpa32U coalescingTimerInNs,
                                               Cpa16U startInst,
                                               Cpa16U endInst)
{
    Cpa64U mask = 0;
    Cpa16U i;

    if (startInst > endInst || endInst >= 64)
    {
        PRINT_ERR("Invalid instance range %d-%d (must be 0-63)\n",
                  startInst,
                  endInst);
        return CPA_STATUS_FAIL;
    }

    for (i = startInst; i <= endInst; i++)
    {
        mask |= (1ULL << i);
    }

    setDcInstanceCoalescingTimerWithMask(coalescingTimerInNs, mask);
    PRINT("Configured instances %d-%d with coalescing timer %u ns\n",
          startInst,
          endInst,
          coalescingTimerInNs);
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setDcInstanceCoalescingTimerForRange);

CpaStatus configureDcInstanceCoalescingTimerForAll(Cpa32U coalescingTimerInNs)
{
    Cpa16U numInstances = 0;
    Cpa16U numDecompInstances = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;

    status = cpaDcGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to get DC instances count for coalescing timer "
                  "configuration\n");
        return CPA_STATUS_FAIL;
    }
    status = cpaGetNumInstances(CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION,
                                &numDecompInstances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to get Decomp instances count for coalescing timer "
                  "configuration\n");
        return CPA_STATUS_FAIL;
    }
    if (numInstances == 0 && numDecompInstances == 0)
    {
        /* No DC instances in the active config (e.g. an SSL/CY-only
         * section). Nothing to configure; not a fatal condition. */
        PRINT("No DC and Decomp instances available - skipping DC and Decomp "
              "coalescing timer "
              "configuration\n");
        return CPA_STATUS_SUCCESS;
    }
    {
        Cpa64U allInstancesMask;
        Cpa16U totalInstances = numInstances + numDecompInstances;

        if (totalInstances >= 64)
        {
            allInstancesMask = 0xFFFFFFFFFFFFFFFFULL;
        }
        else
        {
            allInstancesMask = (1ULL << totalInstances) - 1;
        }

        setDcInstanceCoalescingTimer(coalescingTimerInNs);
        setDcInstanceCoalescingTimerMask(allInstancesMask);

        PRINT("Explicitly configured coalescing timer %u ns for %d "
              "instances (%d comp + %d decomp, mask: 0x%llx)\n",
              coalescingTimerInNs,
              totalInstances,
              numInstances,
              numDecompInstances,
              (unsigned long long)allInstancesMask);
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(configureDcInstanceCoalescingTimerForAll);

CpaStatus configureDcInstanceCoalescingTimerForHalf(Cpa32U coalescingTimerInNs)
{
    Cpa16U numInstances = 0;
    Cpa16U numDecompInstances = 0;
    Cpa16U half_numInstances = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;

    status = cpaDcGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to get DC instances count for coalescing timer "
                  "configuration\n");
        return CPA_STATUS_FAIL;
    }
    status = cpaGetNumInstances(CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION,
                                &numDecompInstances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to get Decomp instances count for coalescing timer "
                  "configuration\n");
        return CPA_STATUS_FAIL;
    }
    if (numInstances == 0 && numDecompInstances == 0)
    {
        PRINT("No DC and Decomp instances available - skipping DC and Decomp "
              "coalescing timer "
              "configuration\n");
        return CPA_STATUS_SUCCESS;
    }
    {
        Cpa16U totalInstances = numInstances + numDecompInstances;
        Cpa16U halfComp = numInstances / 2;
        Cpa16U halfDecomp = numDecompInstances / 2;
        Cpa64U halfInstancesMask = 0;
        Cpa16U b;

        half_numInstances = halfComp + halfDecomp;

        /* Lower half of comp bits (0..halfComp-1) */
        for (b = 0; b < halfComp && b < 64; b++)
        {
            halfInstancesMask |= (1ULL << b);
        }
        /* Lower half of decomp bits, placed after all comp bits */
        for (b = 0; b < halfDecomp && (numInstances + b) < 64; b++)
        {
            halfInstancesMask |= (1ULL << (numInstances + b));
        }

        setDcInstanceCoalescingTimer(coalescingTimerInNs);
        setDcInstanceCoalescingTimerMask(halfInstancesMask);

        PRINT("Explicitly configured coalescing timer %u ns for HALF (%d of "
              "%d) instances (%d/%d comp + %d/%d decomp, mask: 0x%llx)\n",
              coalescingTimerInNs,
              half_numInstances,
              totalInstances,
              halfComp,
              numInstances,
              halfDecomp,
              numDecompInstances,
              (unsigned long long)halfInstancesMask);
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(configureDcInstanceCoalescingTimerForHalf);

CpaStatus getDcInstanceRxInterruptMetaData(
    CpaInstanceHandle instanceHandle,
    CpaRxInterruptMetaData *pInterruptData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceInfo2 instanceInfo = { 0 };
    CpaAccelerationServiceType svcType = CPA_ACC_SVC_TYPE_DATA_COMPRESSION;

    if (NULL == pInterruptData)
    {
        PRINT_ERR("Invalid parameter: pInterruptData is NULL\n");
        return CPA_STATUS_FAIL;
    }

    status = cpaDcInstanceGetInfo2(instanceHandle, &instanceInfo);
    if (CPA_STATUS_SUCCESS == status)
    {
        if (CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION ==
            instanceInfo.accelerationServiceType)
        {
            svcType = CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION;
        }
    }

    return cpaInstanceGetRxInterruptMetaData(
        instanceHandle, svcType, pInterruptData);
}
EXPORT_SYMBOL(getDcInstanceRxInterruptMetaData);

CpaStatus applyDcInstanceCoalescingTimerConfiguration(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa16U numInstances = 0;
    Cpa16U numDecompInstances = 0;
    CpaInstanceHandle *instances = NULL;
    CpaInstanceHandle *decompInstances = NULL;
    Cpa64U instanceMask;
    Cpa32U coalescingTimerInNs;
    CpaRxInterruptMetaData interruptData = { 0 };
    Cpa16U i = 0;
    Cpa16U applied = 0;
    Cpa16U appliedDecomp = 0;

    if (!isDcInstanceCoalescingTimerConfigured())
    {
        /* No explicit configuration - nothing to apply */
        return CPA_STATUS_SUCCESS;
    }

    instanceMask = getDcInstanceCoalescingTimerMask();
    if (instanceMask == 0)
    {
        /* Empty mask - nothing to apply */
        return CPA_STATUS_SUCCESS;
    }

    coalescingTimerInNs = getDcInstanceCoalescingTimer();

    /* Get the number of DC (DATA_COMPRESSION) instances */
    status = cpaDcGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to get DC instances count: %d\n", status);
        return status;
    }

    /* Also query pure decompression instances (cfg_services=decomp). */
    {
        CpaStatus dstatus = cpaGetNumInstances(
            CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION, &numDecompInstances);
        if (CPA_STATUS_SUCCESS != dstatus)
        {
            numDecompInstances = 0;
        }
    }

    if (numInstances == 0 && numDecompInstances == 0)
    {
        PRINT_ERR("No DC or decompression instances available to apply "
                  "coalescing timer\n");
        return CPA_STATUS_FAIL;
    }

    if (numInstances > 0)
    {
        /* Allocate memory for instance handles */
        instances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
        if (NULL == instances)
        {
            PRINT_ERR("Unable to allocate memory for DC instances\n");
            return CPA_STATUS_FAIL;
        }

        /* Get the instance handles */
        status = cpaDcGetInstances(numInstances, instances);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to get DC instances: %d\n", status);
            qaeMemFree((void **)&instances);
            return status;
        }
    }

    /* Apply coalescing timer to instances specified in the mask */
    for (i = 0; i < numInstances && i < 64; i++)
    {
        if (instanceMask & (1ULL << i))
        {
            CpaInstanceInfo2 instanceInfo = { 0 };
            CpaAccelerationServiceType svcType =
                CPA_ACC_SVC_TYPE_DATA_COMPRESSION;

            /* Pick the correct acceleration service type for this instance.
             * A pure decompression instance is reported as
             * CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION. */
            status = cpaDcInstanceGetInfo2(instances[i], &instanceInfo);
            if (CPA_STATUS_SUCCESS == status &&
                CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION ==
                    instanceInfo.accelerationServiceType)
            {
                svcType = CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION;
            }

            status = cpaInstanceSetIntCoalescingTimer(
                instances[i], svcType, coalescingTimerInNs);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Failed to set coalescing timer %u ns for DC "
                          "instance %d (svcType %d): %d\n",
                          coalescingTimerInNs,
                          i,
                          svcType,
                          status);
                /* Continue with other instances rather than failing
                 * completely */
            }
            else
            {
                memset(&interruptData, 0, sizeof(interruptData));
                status = cpaInstanceGetRxInterruptMetaData(
                    instances[i], svcType, &interruptData);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Failed to get RX interrupt metadata for DC "
                              "instance %d: %d\n",
                              i,
                              status);
                    qaeMemFree((void **)&instances);
                    return status;
                }
                else if (interruptData.coalescingTimerInNs !=
                         coalescingTimerInNs)
                {
                    /* Hardware may round to nearest supported granularity.
                     * Treat large differences as a failure, otherwise warn. */
                    Cpa32U granularity =
                        interruptData.coalescingTimerGranularityInNs;
                    Cpa32U diff = (interruptData.coalescingTimerInNs >
                                   coalescingTimerInNs)
                                      ? (interruptData.coalescingTimerInNs -
                                         coalescingTimerInNs)
                                      : (coalescingTimerInNs -
                                         interruptData.coalescingTimerInNs);

                    if (granularity > 0 && diff <= granularity)
                    {
                        PRINT("Coalescing timer for DC instance %d rounded: "
                              "requested %u ns, actual %u ns (granularity "
                              "%u ns)\n",
                              i,
                              coalescingTimerInNs,
                              interruptData.coalescingTimerInNs,
                              granularity);
                        applied++;
                    }
                    else
                    {
                        PRINT_ERR("Mismatch verifying coalescing timer for DC "
                                  "instance %d: set %u ns, got %u ns "
                                  "(max %u ns, granularity %u ns)\n",
                                  i,
                                  coalescingTimerInNs,
                                  interruptData.coalescingTimerInNs,
                                  interruptData.coalescingTimerMaxInNs,
                                  granularity);
                        qaeMemFree((void **)&instances);
                        return CPA_STATUS_FAIL;
                    }
                }
                else
                {
                    PRINT("Verified coalescing timer %u ns for DC instance "
                          "%d (max %u ns, granularity %u ns)\n",
                          interruptData.coalescingTimerInNs,
                          i,
                          interruptData.coalescingTimerMaxInNs,
                          interruptData.coalescingTimerGranularityInNs);
                    applied++;
                }
            }
        }
    }

    if (instances != NULL)
    {
        qaeMemFree((void **)&instances);
        instances = NULL;
    }

    PRINT("Coalescing timer %u ns applied to %u DC instance(s)\n",
          coalescingTimerInNs,
          applied);

    if (numDecompInstances > 0)
    {
        Cpa16U j;

        decompInstances =
            qaeMemAlloc(sizeof(CpaInstanceHandle) * numDecompInstances);
        if (NULL == decompInstances)
        {
            PRINT_ERR("Unable to allocate memory for Decomp instances\n");
            return CPA_STATUS_FAIL;
        }

        status = cpaGetInstances(CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION,
                                 numDecompInstances,
                                 decompInstances);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to get Decomp instances: %d\n", status);
            qaeMemFree((void **)&decompInstances);
            return status;
        }

        for (j = 0; j < numDecompInstances; j++)
        {
            Cpa16U bit = numInstances + j;

            if (bit >= 64)
            {
                break;
            }
            if (!(instanceMask & (1ULL << bit)))
            {
                continue;
            }

            status = cpaInstanceSetIntCoalescingTimer(
                decompInstances[j],
                CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION,
                coalescingTimerInNs);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Failed to set coalescing timer %u ns for Decomp "
                          "instance %d: %d\n",
                          coalescingTimerInNs,
                          j,
                          status);
                continue;
            }

            memset(&interruptData, 0, sizeof(interruptData));
            status = cpaInstanceGetRxInterruptMetaData(
                decompInstances[j],
                CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION,
                &interruptData);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Failed to get RX interrupt metadata for Decomp "
                          "instance %d: %d\n",
                          j,
                          status);
                qaeMemFree((void **)&decompInstances);
                return status;
            }
            if (interruptData.coalescingTimerInNs != coalescingTimerInNs)
            {
                Cpa16U granularity =
                    interruptData.coalescingTimerGranularityInNs;
                Cpa32U diff =
                    (interruptData.coalescingTimerInNs > coalescingTimerInNs)
                        ? (interruptData.coalescingTimerInNs -
                           coalescingTimerInNs)
                        : (coalescingTimerInNs -
                           interruptData.coalescingTimerInNs);

                if (granularity > 0 && diff <= (Cpa32U)granularity)
                {
                    PRINT("Coalescing timer for Decomp instance %d rounded: "
                          "requested %u ns, actual %u ns (granularity "
                          "%u ns)\n",
                          j,
                          coalescingTimerInNs,
                          interruptData.coalescingTimerInNs,
                          granularity);
                    appliedDecomp++;
                }
                else
                {
                    PRINT_ERR("Mismatch verifying coalescing timer for "
                              "Decomp instance %d: set %u ns, got %u ns "
                              "(max %u ns, granularity %u ns)\n",
                              j,
                              coalescingTimerInNs,
                              interruptData.coalescingTimerInNs,
                              interruptData.coalescingTimerMaxInNs,
                              granularity);
                    qaeMemFree((void **)&decompInstances);
                    return CPA_STATUS_FAIL;
                }
            }
            else
            {
                PRINT("Verified coalescing timer %u ns for Decomp instance "
                      "%d (max %u ns, granularity %u ns)\n",
                      interruptData.coalescingTimerInNs,
                      j,
                      interruptData.coalescingTimerMaxInNs,
                      interruptData.coalescingTimerGranularityInNs);
                appliedDecomp++;
            }
        }
        qaeMemFree((void **)&decompInstances);

        PRINT("Coalescing timer %u ns applied to %u Decomp instance(s)\n",
              coalescingTimerInNs,
              appliedDecomp);
    }

    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(applyDcInstanceCoalescingTimerConfiguration);
#endif /* USER_SPACE && SUPPORTED_FEAT_INT_COALESCING_TIMER && STV_TEST_CODE   \
        */

CpaStatus setDcResponseModeIterationCount(Cpa32U count)
{
    dcResponseModeIterationCount_g = count;
    PRINT("Set DC response mode iteration count to %d\n", count);
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setDcResponseModeIterationCount);

CpaStatus getDcResponseModeIterationCount(Cpa32U *count)
{
    if (count == NULL)
    {
        PRINT_ERR("Invalid parameter: count pointer is NULL\n");
        return CPA_STATUS_FAIL;
    }

    *count = dcResponseModeIterationCount_g;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(getDcResponseModeIterationCount);

CpaInstanceResponseMode getDcResponseModeWithIteration(
    compression_test_params_t *testParams)
{
    CpaInstanceResponseMode currentMode;
    CpaInstanceResponseMode alternateMode;
    Cpa32U i;

    /* If iteration count is 1 or less, return currentResponseMode (default
     * behavior) */
    if (dcResponseModeIterationCount_g <= 1)
    {
        return (testParams != NULL) ? testParams->currentResponseMode
                                    : CPA_INST_RX_NOTIFY_NONE;
    }

    /* If testParams is NULL, cannot perform iteration */
    if (testParams == NULL)
    {
        PRINT_ERR(
            "Cannot perform response mode iteration without test parameters\n");
        return CPA_INST_RX_NOTIFY_NONE;
    }
    /* Use currentResponseMode from test parameters as the starting point */
    currentMode = testParams->currentResponseMode;

    /* Determine alternate mode - opposite of current mode */
    if (currentMode == CPA_INST_RX_NOTIFY_NONE)
    {
        alternateMode = CPA_INST_RX_NOTIFY_BY_EVENT;
    }
    else
    {
        alternateMode = CPA_INST_RX_NOTIFY_NONE;
    }

    /* Perform iterations with alternation starting from currentResponseMode */
    for (i = 0; i < dcResponseModeIterationCount_g; i++)
    {
        if (i % 2 == 0)
        {
            /* Even iterations (0, 2, 4...): use initial mode from test params
             */
            currentMode = testParams->currentResponseMode;
        }
        else
        {
            /* Odd iterations (1, 3, 5...): use alternate mode */
            currentMode = alternateMode;
        }
    }

    return currentMode;
}
EXPORT_SYMBOL(getDcResponseModeWithIteration);

CpaStatus enableDcResponseModeIteration(Cpa32U count)
{
    CpaStatus status;

    if (count < 1)
    {
        PRINT_ERR("Invalid iteration count %d, using default (1)\n", count);
        count = 1;
    }

    status = setDcResponseModeIterationCount(count);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to set DC response mode iteration count\n");
        return CPA_STATUS_FAIL;
    }
    PRINT("DC response mode iteration %s with count=%d "
          "(applies to both compression and decompression)\n",
          (count > 1) ? "ENABLED" : "DISABLED",
          count);
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(enableDcResponseModeIteration);

#endif /* USER_SPACE && SUPPORTED_FEAT_EPOLL && STV_TEST_CODE */

/*********** Call Back Function **************/
void dcPerformCallback(void *pCallbackTag, CpaStatus status)
{
    compression_test_params_t *test_struct =
        (compression_test_params_t *)pCallbackTag;
    perf_data_t *pPerfData = test_struct->performanceStats;

    /*check perf_data pointer is valid*/
    if (NULL == pPerfData)
    {
        PRINT_ERR("Invalid data in CallbackTag\n");
        return;
    }
    pPerfData->responses++;
    /*check status */
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR(
            "%s Failed, status = %d, responseCount %llu, submissions %u\n",
            __func__,
            status,
            (long long int)pPerfData->responses,
            pPerfData->submissions);
        pPerfData->threadReturnStatus = CPA_STATUS_FAIL;
    }
    if (latency_enable)
    {
        /* Did we setup the array pointer? */
        QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(
            pPerfData->response_times, pPerfData->threadReturnStatus);

        /*Have we sampled too many buffer operations?*/
        if (pPerfData->latencyCount >= MAX_LATENCY_COUNT)
        {
            PRINT_ERR("max latency count exceeded\n");
            pPerfData->threadReturnStatus = CPA_STATUS_FAIL;
        }
        /* Is this the buffer we calculate latency on?
         * And have we calculated too many for array? */
        if (pPerfData->threadReturnStatus == CPA_STATUS_SUCCESS &&
            pPerfData->responses == pPerfData->nextCount &&
            pPerfData->latencyCount < MAX_LATENCY_COUNT)
        {
            int i = pPerfData->latencyCount;
            /*Now get the end timestamp - before any print outs*/
            pPerfData->response_times[i] = sampleCodeTimestamp();
            pPerfData->nextCount += pPerfData->countIncrement;
            pPerfData->latencyCount++;
        }
    }

    if ((CPA_TRUE == gUseStatefulLite) ||
        (CPA_DC_STATEFUL == test_struct->setupData.sessState) ||
#if (DC_API_VERSION_AT_LEAST(3, 2))
        (reliability_g && ((CPA_TRUE == test_struct->useE2E) ||
                           (CPA_TRUE == test_struct->useE2EVerify))) ||
#else
        (CPA_TRUE == test_struct->useE2E) ||
        (CPA_TRUE == test_struct->useE2EVerify) ||
#endif
        (CPA_TRUE == test_struct->useStatefulLite))
    {
        sampleCodeSemaphorePost(&pPerfData->comp);
    }

    /* Release the semaphore if all the responses are gathered.
     * In case of failure, the number of responses will be for
     * submissions that had happened till the point of failure.
     */
    if ((pPerfData->responses >= pPerfData->numOperations) ||
        (pPerfData->threadReturnStatus != CPA_STATUS_SUCCESS &&
         pPerfData->responses >= pPerfData->submissions))
    {
        /* generate end of the cycle stamp for Corpus */
        pPerfData->endCyclesTimestamp = sampleCodeTimestamp();
        sampleCodeSemaphorePost(&pPerfData->comp);
    }
}

Cpa32U expansionFactor_g = 1;
EXPORT_SYMBOL(expansionFactor_g);
#ifdef ZERO_BYTE_LAST_REQUEST
CpaBoolean zeroByteLastRequest_g = CPA_FALSE;
#endif
extern int signOfLife;

/* Global array of polling threads */
sample_code_thread_t *dcPollingThread_g = NULL;

/* Number of Compression instances enabled for polling */
Cpa32U numDcPolledInstances_g = 0;

/* Global array of instance handles */
CpaInstanceHandle *dcInstances_g = NULL;

/* Number of Compression instances available */
Cpa16U numDcInstances_g = 0;

/* Flag to indicate if the DC services are started */
volatile CpaBoolean dc_service_started_g = CPA_FALSE;

/* Flag to indicate if the DC polling threads have been created */
volatile CpaBoolean dc_polling_started_g = CPA_FALSE;

static volatile CpaBoolean decomp_service_started_g = CPA_FALSE;
static CpaInstanceHandle *decompInstances_g = NULL;
static volatile CpaBoolean decomp_polling_started_g = CPA_FALSE;
static sample_code_thread_t *decompPollingThread_g = NULL;
static Cpa32U numDecompPolledInstances_g = 0;

/* flag to define weather to use zlib to compress data before decompression*/
CpaBoolean useZlib_g = CPA_FALSE;
EXPORT_SYMBOL(useZlib_g);

/* Dynamic Buffer List buffer list used to start DC Services */
CpaBufferList ***pInterBuffList_g = NULL;

#ifdef SC_ENABLE_DYNAMIC_COMPRESSION
CpaDcHuffType huffmanType_g = CPA_DC_HT_FULL_DYNAMIC;
#else
CpaDcHuffType huffmanType_g = CPA_DC_HT_STATIC;
#endif
EXPORT_SYMBOL(huffmanType_g);

#define SINGLE_INTER_BUFF_LIST (1)
#ifndef DO_CRYPTO
Cpa32U getThroughput(Cpa64U numPackets, Cpa32U packetSize, perf_cycles_t cycles)
{
    unsigned long long bytesSent = 0;
    unsigned long long time = cycles;
    unsigned long long rate = 0;
    /* declare frequency in kiloHertz*/
    Cpa32U freq = sampleCodeGetCpuFreq();
    bytesSent = packetSize;
    bytesSent = bytesSent * numPackets;

    /*get time in milli seconds by dividing numberOfClockCycles by frequency
     * in kilohertz ie: cycles/(cycles/millsec) = time (mSec) */
    do_div(time, freq);
    /*check that the sample time was not to small*/
    if (time == 0)
    {
        PRINT_ERR("Sample time is too small to calculate throughput\n");
        return 0;
    }
    /*set rate to be bytesSent, once we perform the do_div rate changes from
     * bytes to bytes/milli second or kiloBytes/second*/
    rate = bytesSent;
    /*rate in kBps*/
    do_div(rate, time);
    /*check that the rate is high enough to convert to Megabits per second*/
    if (rate == 0)
    {
        PRINT_ERR("no data was sent to calculate throughput\n");
        return 0;
    }
    /* convert Kilobytes/second to Kilobits/second*/
    rate = rate * NUM_BITS_IN_BYTE;
    /*then convert rate from Kilobits/second to Megabits/second*/
    do_div(rate, KILOBITS_IN_MEGABITS);
    return (Cpa32U)rate;
}
#endif /* not DO_CRYPTO */

static void freeDcBufferList(CpaBufferList **buffListArray,
                             Cpa32U numberOfBufferList)
{
    Cpa32U i = 0, j = 0;
    Cpa32U numberOfBuffers = 0;

    for (i = 0; i < numberOfBufferList; i++)
    {
        if (buffListArray[i] != NULL)
        {
            numberOfBuffers = buffListArray[i]->numBuffers;
            if (buffListArray[i]->pBuffers != NULL)
            {
                for (j = 0; j < numberOfBuffers; j++)
                {
                    if (buffListArray[i]->pBuffers[j].pData != NULL)
                    {
                        qaeMemFreeNUMA(
                            (void **)&buffListArray[i]->pBuffers[j].pData);
                        buffListArray[i]->pBuffers[j].pData = NULL;
                    }
                }

                qaeMemFreeNUMA((void **)&buffListArray[i]->pBuffers);
                buffListArray[i]->pBuffers = NULL;
            }

            if (buffListArray[i]->pPrivateMetaData != NULL)
            {

                qaeMemFreeNUMA((void **)&buffListArray[i]->pPrivateMetaData);
            }
        }
    }
}

static char *canterburyFileNames[] = {
    /* Single Canterbury corpus file is a concatenation of the following
     * files:
     "alice29.txt", "asyoulik.txt", "cp.html",
     "fields.c","grammar.lsp", "kennedy.xls", "lcet10.txt" ,
     "plrabn12.txt", "ptt5"
     */
    "canterbury"};

static char *calgaryFullFileNames[] = {
    /* Single Calgary corpus file is a concatenation of the following
     * files: */
    "bib",
    "book1",
    "book2",
    "geo",
    "news",
    "obj1",
    "obj2",
    "paper1",
    "paper2",
    "paper3",
    "paper4",
    "paper5",
    "paper6",
    "pic",
    "progc",
    "progl",
    "progp",
    "trans"};

static char *calgarySixFileNames[] =
    {"paper4", "paper5", "paper4", "paper5", "paper5", "paper4"};

static char *calgaryFileNames[] = {
    /* Single Calgary file is a concatenation of all files
     * in calgaryFullFileNames.
     */
    "calgary"};

static char *signOfLifeFile[] = {/* 1st 32k of calgary corpus file */
                                 "calgary32"};

static char *zeroLengthFilenames[] =
    {"zero1", "progp", "paper4", "zero2", "obj1", "zero3"};

static char *overflowFileNames[] =
    {"paper4", "bib", "book1", "book2", "geo", "news"};

static char *overflowAndZeroFileNames[] =
    {"zero1", "book1", "zero2", "book2", "news", "zero2"};

#define CORPUS_DATA_EMPTY                                                      \
    {                                                                          \
        NULL, NULL, 0, CPA_FALSE                                               \
    }
#define CORPUS_DATA_INIT(name)                                                 \
    {                                                                          \
        NULL, name, sizeof(name) / sizeof(name[0]), CPA_FALSE                  \
    }
#define CORPUS_TO_STR(corpus) #corpus
#define CORPUS_STR(corpus) CORPUS_TO_STR(corpus)
static corpusInfo corpus[] = {
    [CANTERBURY_CORPUS] = { CANTERBURY_CORPUS,
                            CORPUS_STR(CANTERBURY_CORPUS),
                            CORPUS_DATA_INIT(canterburyFileNames) },
    [CALGARY_CORPUS] = { CALGARY_CORPUS,
                         CORPUS_STR(CALGARY_CORPUS),
                         CORPUS_DATA_INIT(calgaryFileNames) },
    [RANDOM] = { RANDOM, CORPUS_STR(RANDOM), CORPUS_DATA_EMPTY },
    [SIGN_OF_LIFE_CORPUS] = { SIGN_OF_LIFE_CORPUS,
                              CORPUS_STR(SIGN_OF_LIFE_CORPUS),
                              CORPUS_DATA_INIT(signOfLifeFile) },
    [CALGARY_SIX_FILES] = { CALGARY_SIX_FILES,
                            CORPUS_STR(CALGARY_SIX_FILES),
                            CORPUS_DATA_INIT(calgarySixFileNames) },
    [CALGARY_FULL_SET] = { CALGARY_FULL_SET,
                           CORPUS_STR(CALGARY_FULL_SET),
                           CORPUS_DATA_INIT(calgaryFullFileNames) },
    [ZERO_LENGTH_FILE] = { ZERO_LENGTH_FILE,
                           CORPUS_STR(ZERO_LENGTH_FILE),
                           CORPUS_DATA_INIT(zeroLengthFilenames) },
    [OVERFLOW_FILE] = { OVERFLOW_FILE,
                        CORPUS_STR(OVERFLOW_FILE),
                        CORPUS_DATA_INIT(overflowFileNames) },
    [OVERFLOW_AND_ZERO_FILE] = { OVERFLOW_AND_ZERO_FILE,
                                 CORPUS_STR(OVERFLOW_AND_ZERO_FILE),
                                 CORPUS_DATA_INIT(overflowAndZeroFileNames) },
    [CORPUS_TYPE_EXTENDED] = { CORPUS_TYPE_EXTENDED,
                               CORPUS_STR(CORPUS_TYPE_EXTENDED),
                               CORPUS_DATA_EMPTY },

    /*All Corpus type should added above
     * CORPUS_TYPE_INVALID.
     */
    [CORPUS_TYPE_INVALID] = { CORPUS_TYPE_INVALID,
                              CORPUS_STR(CORPUS_TYPE_INVALID),
                              CORPUS_DATA_EMPTY }
};

#define CHECK_CORPUS_TYPE_AND_RETURN(type, status)                             \
    do                                                                         \
    {                                                                          \
        if ((type) < 0 || (type) >= MAX_NUM_CORPUS_TYPE)                       \
        {                                                                      \
            PRINT_ERR("Invalid corpus Type %d\n", corpusType);                 \
            return status;                                                     \
        }                                                                      \
    } while (0)

static CpaStatus populateCorpusInternal(corpus_type_t corpusType)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U numFiles = 0, i = 0;
    char **pCorpusFileNamesArray = NULL;
    corpus_file_t *pCorpusFile = NULL;

    CHECK_CORPUS_TYPE_AND_RETURN(corpusType, CPA_STATUS_FAIL);

    if (corpus[corpusType].corpusData.read == CPA_FALSE)
    {
        pCorpusFileNamesArray = corpus[corpusType].corpusData.fileNameArray;
        numFiles = corpus[corpusType].corpusData.numFilesInCorpus;
        if (numFiles == 0)
        {
            PRINT_ERR("No files in corpus %s. Failed to populate\n",
                      corpus[corpusType].corpusName);
            return CPA_STATUS_FAIL;
        }
        if (pCorpusFileNamesArray == NULL)
        {
            PRINT_ERR(
                "No File Names present for Corpus %s. Failed to populate\n",
                corpus[corpusType].corpusName);
            return CPA_STATUS_FAIL;
        }
        /* allocate the memory for the corpus file structure */
        pCorpusFile = qaeMemAlloc(numFiles * sizeof(corpus_file_t));
        if (NULL == pCorpusFile)
        {
            PRINT_ERR(" Unable to allocate Memory for "
                      "corpus structure\n");
            return CPA_STATUS_FAIL;
        }

        for (i = 0; i < numFiles; i++)
        {
            switch (corpusType)
            {
                default:
                    status = getCorpusFile(&pCorpusFile[i].corpusBinaryData,
                                           pCorpusFileNamesArray[i],
                                           &pCorpusFile[i].corpusBinaryDataLen);
            }
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Get \"%s\" Corpus File Failed\n",
                          pCorpusFileNamesArray[i]);
                qaeMemFree((void **)&pCorpusFile);
                return CPA_STATUS_FAIL;
            }
        }
        corpus[corpusType].corpusData.fileArray = pCorpusFile;
        corpus[corpusType].corpusData.read = CPA_TRUE;
    }

    return status;
}

CpaStatus populateCorpus(Cpa32U buffSize, corpus_type_t corpusType)
{
    return populateCorpusInternal(corpusType);
}
EXPORT_SYMBOL(populateCorpus);

inline Cpa32U getNumFilesInCorpus(corpus_type_t corpusType)
{
    CHECK_CORPUS_TYPE_AND_RETURN(corpusType, 0);
    return corpus[corpusType].corpusData.numFilesInCorpus;
}
EXPORT_SYMBOL(getNumFilesInCorpus);

inline char **getFileNamesInCorpus(corpus_type_t corpusType)
{
    CHECK_CORPUS_TYPE_AND_RETURN(corpusType, NULL);
    return corpus[corpusType].corpusData.fileNameArray;
}
EXPORT_SYMBOL(getFileNamesInCorpus);

inline const corpus_file_t *getFilesInCorpus(corpus_type_t corpusType)
{
    if (corpus[corpusType].corpusData.read == CPA_FALSE)
    {
        populateCorpusInternal(corpusType);
    }
    return corpus[corpusType].corpusData.fileArray;
}
EXPORT_SYMBOL(getFilesInCorpus);

inline const char *getCorpusName(corpus_type_t corpusType)
{
    static const char *unknownCorpus = "UNKNOWN CORPUS";
    CHECK_CORPUS_TYPE_AND_RETURN(corpusType, unknownCorpus);
    return corpus[corpusType].corpusName;
}

inline const char *getFileNameInCorpus(corpus_type_t corpusType,
                                       Cpa32U fileIndex)
{
    static const char *unknownCorpusFile = "UNKNOWN CORPUS FILE";
    CHECK_CORPUS_TYPE_AND_RETURN(corpusType, unknownCorpusFile);

    return corpus[corpusType].corpusData.fileNameArray[fileIndex];
}

inline corpus_type_t getCorpusTypeFromName(const char *name,
                                           const unsigned long name_max_size)
{
    corpus_type_t type = 0;
    for (; type < MAX_NUM_CORPUS_TYPE; type++)
    {
        if (strncmp(name, corpus[type].corpusName, name_max_size) == 0)
        {
            return type;
        }
    }
    return CORPUS_TYPE_INVALID;
}

void setCorpusType(corpus_type_t type)
{
    extCorpusInfo.corpusType = type;
}
EXPORT_SYMBOL(setCorpusType);

corpus_type_t getCorpusType(void)
{
    return extCorpusInfo.corpusType;
}

void setCorpusFileIndex(Cpa32U index)
{
    extCorpusInfo.corpusFileIndex = index;
}
EXPORT_SYMBOL(setCorpusFileIndex);

Cpa32U getCorpusFileIndex(void)
{
    return extCorpusInfo.corpusFileIndex;
}

compute_test_result_func_t getPassCriteria(void)
{
    return pfuncPassCriteria;
}

void setPassCriteria(compute_test_result_func_t pfunc)
{
    pfuncPassCriteria = pfunc;
}
EXPORT_SYMBOL(setPassCriteria);

Cpa32U getSetupCnVRequestFlag(void)
{
    return setupCnVRequestFlag;
}
EXPORT_SYMBOL(getSetupCnVRequestFlag);

void setSetupCnVRequestFlag(Cpa32U flag)
{
    setupCnVRequestFlag = flag;
}
EXPORT_SYMBOL(setSetupCnVRequestFlag);

void getDecompNumInstances(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    status = cpaGetNumInstances(CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION,
                                &numDecompInstances_g);
    if (CPA_STATUS_SUCCESS != status)
    {
        numDecompInstances_g = 0;
    }
}
EXPORT_SYMBOL(getDecompNumInstances);

CpaStatus dcGetInstances(CpaAccelerationServiceType accelSrvType,
                         CpaInstanceHandle **pInstHandle,
                         Cpa16U *numInstances)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (NULL == pInstHandle || NULL == numInstances)
    {
        PRINT_ERR("pInstHandle or numInstances is NULL\n");
        return CPA_STATUS_FAIL;
    }

    status = cpaGetNumInstances(accelSrvType, numInstances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR(" Unable to get number of DC instances\n");
        return CPA_STATUS_FAIL;
    }

    if (0 == *numInstances)
    {
        PRINT_ERR(" DC Instances are not present\n");
        return CPA_STATUS_FAIL;
    }
    *pInstHandle = qaeMemAlloc(sizeof(CpaInstanceHandle) * *numInstances);
    if (NULL == *pInstHandle)
    {
        PRINT_ERR("Unable to allocate Memory for Instances\n");
        return CPA_STATUS_FAIL;
    }
    status = cpaGetInstances(accelSrvType, *numInstances, *pInstHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR(" Unable to get DC instances\n");
        qaeMemFree((void **)pInstHandle);
        return CPA_STATUS_FAIL;
    }

    return status;
}
EXPORT_SYMBOL(dcGetInstances);

CpaStatus startDcServices(Cpa32U buffSize, Cpa32U numBuffs)

{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U size = 0;
    Cpa32U i = 0, k = 0;
    Cpa32U nodeId = 0;
    Cpa32U nProcessorsOnline = 0;
    Cpa16U numBuffers = 0;
    CpaBufferList **tempBufferList = NULL;

    /*if the service started flag is false*/
    if (dc_service_started_g == CPA_FALSE)
    {
        /* Get the number of DC Instances */
        status = cpaGetNumInstances(CPA_ACC_SVC_TYPE_DATA_COMPRESSION,
                                    &numDcInstances_g);
        /* Check the status */
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to Get Number of DC instances\n");
            return CPA_STATUS_FAIL;
        }
        /* Check if at least one DC instance are present */
        if (0 == numDcInstances_g)
        {
            PRINT_ERR(" DC Instances are not present\n");
            return CPA_STATUS_FAIL;
        }
        /* Allocate memory for all the instances */
        dcInstances_g =
            qaeMemAlloc(sizeof(CpaInstanceHandle) * numDcInstances_g);
        /* Check For NULL */
        if (NULL == dcInstances_g)
        {
            PRINT_ERR(" Unable to allocate memory for Instances \n");
            return CPA_STATUS_FAIL;
        }

        /* Get DC Instances */
        status = cpaGetInstances(
            CPA_ACC_SVC_TYPE_DATA_COMPRESSION, numDcInstances_g, dcInstances_g);
        /* Check Status */
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to Get DC instances\n");
            qaeMemFree((void **)&dcInstances_g);
            return CPA_STATUS_FAIL;
        }

        /* Allocate the buffer list pointers to the number of Instances
         * this buffer list list is used only in case of dynamic
         * compression
         */
        pInterBuffList_g = (CpaBufferList ***)qaeMemAlloc(
            numDcInstances_g * sizeof(CpaBufferList **));
        /* Check For NULL */
        if (NULL == pInterBuffList_g)
        {
            PRINT_ERR("Unable to allocate dynamic buffer List\n");
            qaeMemFree((void **)&dcInstances_g);
            return CPA_STATUS_FAIL;
        }

        /* Initialize memory for buffer lists */
        memset(
            pInterBuffList_g, 0, numDcInstances_g * sizeof(CpaBufferList **));

        /* Start the Loop to create Buffer List for each instance*/
        for (i = 0; i < numDcInstances_g; i++)
        {
            /* get the Node ID for each instance Handle */
            status = sampleCodeDcGetNode(dcInstances_g[i], &nodeId);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Unable to get NodeId\n");
                qaeMemFree((void **)&dcInstances_g);
                qaeMemFree((void **)&pInterBuffList_g);
                return CPA_STATUS_FAIL;
            }
            status =
                cpaDcGetNumIntermediateBuffers(dcInstances_g[i], &numBuffers);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Unable to allocate Memory for Dynamic Buffer\n");
                qaeMemFree((void **)&dcInstances_g);
                qaeMemFree((void **)&pInterBuffList_g);
                return CPA_STATUS_FAIL;
            }
            if (numBuffers > 0)
            {
                /* allocate the buffer list memory for the dynamic Buffers
                 * only applicable for CPM prior to gen4 as it is done in HW */
                pInterBuffList_g[i] =
                    qaeMemAllocNUMA(sizeof(CpaBufferList *) * numBuffers,
                                    nodeId,
                                    BYTE_ALIGNMENT_64);
                if (NULL == pInterBuffList_g[i])
                {
                    PRINT_ERR("Unable to allocate Memory for Dynamic Buffer\n");
                    qaeMemFree((void **)&dcInstances_g);
                    qaeMemFree((void **)&pInterBuffList_g);
                    return CPA_STATUS_FAIL;
                }

                /* get the size of the Private meta data
                 * needed to create Buffer List
                 */
                status = cpaDcBufferListGetMetaSize(
                    dcInstances_g[i], numBuffers, &size);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Get Meta Size Data Failed\n");
                    qaeMemFree((void **)&dcInstances_g);
                    qaeMemFree((void **)&pInterBuffList_g);
                    return CPA_STATUS_FAIL;
                }
            }
            tempBufferList = pInterBuffList_g[i];
            for (k = 0; k < numBuffers; k++)
            {
                tempBufferList[k] = (CpaBufferList *)qaeMemAllocNUMA(
                    sizeof(CpaBufferList), nodeId, BYTE_ALIGNMENT_64);
                if (NULL == tempBufferList[k])
                {
                    PRINT(" %s:: Unable to allocate memory for "
                          "tempBufferList\n",
                          __FUNCTION__);
                    qaeMemFree((void **)&dcInstances_g);
                    freeDcBufferList(tempBufferList, k + 1);
                    qaeMemFree((void **)&pInterBuffList_g);
                    return CPA_STATUS_FAIL;
                }
                tempBufferList[k]->pPrivateMetaData =
                    qaeMemAllocNUMA(size, nodeId, BYTE_ALIGNMENT_64);
                if (NULL == tempBufferList[k]->pPrivateMetaData)
                {
                    PRINT(" %s:: Unable to allocate memory for "
                          "pPrivateMetaData\n",
                          __FUNCTION__);
                    qaeMemFree((void **)&dcInstances_g);
                    freeDcBufferList(tempBufferList, k + 1);
                    qaeMemFree((void **)&pInterBuffList_g);
                    return CPA_STATUS_FAIL;
                }
                tempBufferList[k]->numBuffers = ONE_BUFFER_DC;
                /* allocate flat buffers */
                tempBufferList[k]->pBuffers = qaeMemAllocNUMA(
                    (sizeof(CpaFlatBuffer)), nodeId, BYTE_ALIGNMENT_64);
                if (NULL == tempBufferList[k]->pBuffers)
                {
                    PRINT_ERR("Unable to allocate memory for pBuffers\n");
                    qaeMemFree((void **)&dcInstances_g);
                    freeDcBufferList(tempBufferList, k + 1);
                    qaeMemFree((void **)&pInterBuffList_g);
                    return CPA_STATUS_FAIL;
                }

                tempBufferList[k]->pBuffers[0].pData = qaeMemAllocNUMA(
                    (size_t)expansionFactor_g * EXTRA_BUFFER * buffSize,
                    nodeId,
                    BYTE_ALIGNMENT_64);
                if (NULL == tempBufferList[k]->pBuffers[0].pData)
                {
                    PRINT_ERR("Unable to allocate Memory for pBuffers\n");
                    qaeMemFree((void **)&dcInstances_g);
                    freeDcBufferList(tempBufferList, k + 1);
                    qaeMemFree((void **)&pInterBuffList_g);
                    return CPA_STATUS_FAIL;
                }
                tempBufferList[k]->pBuffers[0].dataLenInBytes =
                    expansionFactor_g * EXTRA_BUFFER * buffSize;
            }

            /* When starting the DC Instance, the API expects that the
             * private meta data should be greater than the dataLength
             */
            /* Configure memory Configuration Function */
            status = cpaDcSetAddressTranslation(
                dcInstances_g[i], (CpaVirtualToPhysical)qaeVirtToPhysNUMA);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error setting memory config for instance\n");
                qaeMemFree((void **)&dcInstances_g);
                freeDcBufferList(pInterBuffList_g[i], numBuffers);
                qaeMemFreeNUMA((void **)&pInterBuffList_g[i]);
                qaeMemFree((void **)&pInterBuffList_g);
                return CPA_STATUS_FAIL;
            }
            /* Start DC Instance */
            status = cpaDcStartInstance(
                dcInstances_g[i], numBuffers, pInterBuffList_g[i]);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Unable to start DC Instance\n");
                qaeMemFree((void **)&dcInstances_g);
                freeDcBufferList(pInterBuffList_g[i], numBuffers);
                qaeMemFreeNUMA((void **)&pInterBuffList_g[i]);
                qaeMemFree((void **)&pInterBuffList_g);
                return CPA_STATUS_FAIL;
            }
        }
        /*set the started flag to true*/
        dc_service_started_g = CPA_TRUE;
    }

    /*determine number of cores on system and limit the number of cores to be
     * used to be the smaller of the numberOf Instances or the number of cores*/
    nProcessorsOnline = sampleCodeGetNumberOfCpus();
    if (nProcessorsOnline > numDcInstances_g)
    {
        setCoreLimit(numDcInstances_g);
    }
    return status;
}
EXPORT_SYMBOL(startDcServices);

CpaStatus startServices(const CpaAccelerationServiceType serviceType,
                        Cpa32U buffSize,
                        Cpa32U numBuffs)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U size = 0;
    Cpa32U i = 0, k = 0;
    Cpa32U nodeId = 0;
    Cpa32U nProcessorsOnline = 0;
    Cpa16U numBuffers = 0;
    CpaBufferList **tempBufferList = NULL;
#ifdef SC_DEV_INFO_ENABLED
    CpaBoolean intermediateBuffersRequired = CPA_TRUE;
#endif
    /*if the service started flag is false*/
    if (serviceType == CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION)
    {
        if (decomp_service_started_g == CPA_TRUE)
        {
            return CPA_STATUS_SUCCESS;
        }

        status = dcGetInstances(CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION,
                                &decompInstances_g,
                                &numDecompInstances_g);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to get DECOMP instances\n");
            return CPA_STATUS_FAIL;
        }

        for (i = 0; i < numDecompInstances_g; i++)
        {
            status = cpaDcSetAddressTranslation(
                decompInstances_g[i], (CpaVirtualToPhysical)qaeVirtToPhysNUMA);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error setting address translation for DECOMP "
                          "instance %d\n",
                          i);
                qaeMemFree((void **)&decompInstances_g);
                numDecompInstances_g = 0;
                return CPA_STATUS_FAIL;
            }

            status = cpaDcStartInstance(decompInstances_g[i], 0, NULL);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Unable to start DECOMP instance %d\n", i);
                qaeMemFree((void **)&decompInstances_g);
                numDecompInstances_g = 0;
                return CPA_STATUS_FAIL;
            }
        }

        decomp_service_started_g = CPA_TRUE;
        return CPA_STATUS_SUCCESS;
    }

    if (dc_service_started_g == CPA_FALSE)
    {
        if (serviceType == CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION)
        {
            status = dcGetInstances(CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION,
                                    &dcInstances_g,
                                    &numDcInstances_g);
        }
        else
        {
            status = dcGetInstances(CPA_ACC_SVC_TYPE_DATA_COMPRESSION,
                                    &dcInstances_g,
                                    &numDcInstances_g);
        }
        if (status != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("Unable to get instances\n");
            return CPA_STATUS_FAIL;
        }
        /* Allocate the buffer list pointers to the number of Instances
         * this buffer list list is used only in case of dynamic
         * compression
         */
        pInterBuffList_g = (CpaBufferList ***)qaeMemAlloc(
            numDcInstances_g * sizeof(CpaBufferList **));
        /* Check For NULL */
        if (NULL == pInterBuffList_g)
        {
            PRINT_ERR("Unable to allocate dynamic buffer List\n");
            qaeMemFree((void **)&dcInstances_g);
            return CPA_STATUS_FAIL;
        }

        /* Initialize memory for buffer lists */
        memset(
            pInterBuffList_g, 0, numDcInstances_g * sizeof(CpaBufferList **));

        /* Start the Loop to create Buffer List for each instance*/
        for (i = 0; i < numDcInstances_g; i++)
        {
            /* get the Node ID for each instance Handle */
            status = sampleCodeDcGetNode(dcInstances_g[i], &nodeId);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Unable to get NodeId\n");
                qaeMemFree((void **)&dcInstances_g);
                qaeMemFree((void **)&pInterBuffList_g);
                return CPA_STATUS_FAIL;
            }
            status =
                cpaDcGetNumIntermediateBuffers(dcInstances_g[i], &numBuffers);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Unable to allocate Memory for Dynamic Buffer\n");
                qaeMemFree((void **)&dcInstances_g);
                qaeMemFree((void **)&pInterBuffList_g);
                return CPA_STATUS_FAIL;
            }
#ifdef SC_DEV_INFO_ENABLED
            status = getIntermediateBuffersRequired(
                dcInstances_g[i], &intermediateBuffersRequired);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("getIntermediateBuffersRequired failed\n");
                qaeMemFree((void **)&dcInstances_g);
                qaeMemFree((void **)&pInterBuffList_g);
                return CPA_STATUS_FAIL;
            }

            if (intermediateBuffersRequired == CPA_FALSE && numBuffers != 0)
            {
                PRINT_ERR(
                    "cpaDcGetNumIntermediateBuffers returned an unexpected "
                    "non-zero(%d) value for this device generation\n",
                    numBuffers);
                qaeMemFree((void **)&dcInstances_g);
                qaeMemFree((void **)&pInterBuffList_g);
                return CPA_STATUS_FAIL;
            }
#endif
            if (numBuffers > 0)
            {
                /* allocate the buffer list memory for the dynamic Buffers
                 * only applicable for CPM prior to gen4 as it is done in HW */
                pInterBuffList_g[i] =
                    qaeMemAllocNUMA(sizeof(CpaBufferList *) * numBuffers,
                                    nodeId,
                                    BYTE_ALIGNMENT_64);
                if (NULL == pInterBuffList_g[i])
                {
                    PRINT_ERR("Unable to allocate Memory for Dynamic Buffer\n");
                    qaeMemFree((void **)&dcInstances_g);
                    qaeMemFree((void **)&pInterBuffList_g);
                    return CPA_STATUS_FAIL;
                }

                /* get the size of the Private meta data
                 * needed to create Buffer List
                 */
                status = cpaDcBufferListGetMetaSize(
                    dcInstances_g[i], numBuffers, &size);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Get Meta Size Data Failed\n");
                    qaeMemFree((void **)&dcInstances_g);
                    qaeMemFree((void **)&pInterBuffList_g);
                    return CPA_STATUS_FAIL;
                }
            }
            tempBufferList = pInterBuffList_g[i];
            for (k = 0; k < numBuffers; k++)
            {
                tempBufferList[k] = (CpaBufferList *)qaeMemAllocNUMA(
                    sizeof(CpaBufferList), nodeId, BYTE_ALIGNMENT_64);
                if (NULL == tempBufferList[k])
                {
                    PRINT(" %s:: Unable to allocate memory for "
                          "tempBufferList\n",
                          __FUNCTION__);
                    qaeMemFree((void **)&dcInstances_g);
                    freeDcBufferList(tempBufferList, k + 1);
                    qaeMemFree((void **)&pInterBuffList_g);
                    return CPA_STATUS_FAIL;
                }
                tempBufferList[k]->pPrivateMetaData =
                    qaeMemAllocNUMA(size, nodeId, BYTE_ALIGNMENT_64);
                if (NULL == tempBufferList[k]->pPrivateMetaData)
                {
                    PRINT(" %s:: Unable to allocate memory for "
                          "pPrivateMetaData\n",
                          __FUNCTION__);
                    qaeMemFree((void **)&dcInstances_g);
                    freeDcBufferList(tempBufferList, k + 1);
                    qaeMemFree((void **)&pInterBuffList_g);
                    return CPA_STATUS_FAIL;
                }
                tempBufferList[k]->numBuffers = ONE_BUFFER_DC;
                /* allocate flat buffers */
                tempBufferList[k]->pBuffers = qaeMemAllocNUMA(
                    (sizeof(CpaFlatBuffer)), nodeId, BYTE_ALIGNMENT_64);
                if (NULL == tempBufferList[k]->pBuffers)
                {
                    PRINT_ERR("Unable to allocate memory for pBuffers\n");
                    qaeMemFree((void **)&dcInstances_g);
                    freeDcBufferList(tempBufferList, k + 1);
                    qaeMemFree((void **)&pInterBuffList_g);
                    return CPA_STATUS_FAIL;
                }
                tempBufferList[k]->pBuffers[0].pData = qaeMemAllocNUMA(
                    (size_t)expansionFactor_g * EXTRA_BUFFER * buffSize,
                    nodeId,
                    BYTE_ALIGNMENT_64);
                if (NULL == tempBufferList[k]->pBuffers[0].pData)
                {
                    PRINT_ERR("Unable to allocate Memory for pBuffers\n");
                    qaeMemFree((void **)&dcInstances_g);
                    freeDcBufferList(tempBufferList, k + 1);
                    qaeMemFree((void **)&pInterBuffList_g);
                    return CPA_STATUS_FAIL;
                }
                tempBufferList[k]->pBuffers[0].dataLenInBytes =
                    expansionFactor_g * EXTRA_BUFFER * buffSize;
            }

            /* When starting the Instance, the API expects that the
             * private meta data should be greater than the dataLength
             */
            /* Configure memory Configuration Function */
            status = cpaDcSetAddressTranslation(
                dcInstances_g[i], (CpaVirtualToPhysical)qaeVirtToPhysNUMA);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error setting memory config for instance\n");
                qaeMemFree((void **)&dcInstances_g);
                freeDcBufferList(pInterBuffList_g[i], numBuffers);
                qaeMemFreeNUMA((void **)&pInterBuffList_g[i]);
                qaeMemFree((void **)&pInterBuffList_g);
                return CPA_STATUS_FAIL;
            }
            /* Start Instance */
            status = cpaDcStartInstance(
                dcInstances_g[i], numBuffers, pInterBuffList_g[i]);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Unable to start Instance\n");
                qaeMemFree((void **)&dcInstances_g);
                freeDcBufferList(pInterBuffList_g[i], numBuffers);
                qaeMemFreeNUMA((void **)&pInterBuffList_g[i]);
                qaeMemFree((void **)&pInterBuffList_g);
                return CPA_STATUS_FAIL;
            }
        }
        /*set the started flag to true*/
        dc_service_started_g = CPA_TRUE;
    }
    /*determine number of cores on system and limit the number of cores to be
     * used to be the smaller of the numberOf Instances or the number of cores*/
    nProcessorsOnline = sampleCodeGetNumberOfCpus();
    if (nProcessorsOnline > numDcInstances_g)
    {
        setCoreLimit(numDcInstances_g);
    }
    return status;
}
EXPORT_SYMBOL(startServices);

void freeCorpus(void)
{
    Cpa32U i = 0;
    corpus_type_t corpusType = 0;
    Cpa32U numFiles = 0;
    corpus_file_t *pCorpusFile = NULL;

    for (; corpusType < MAX_NUM_CORPUS_TYPE; corpusType++)
    {
        pCorpusFile = corpus[corpusType].corpusData.fileArray;
        numFiles = getNumFilesInCorpus(corpusType);
        if (numFiles == 0 || pCorpusFile == NULL)
        {
            continue;
        }
        for (i = 0; i < numFiles; i++)
        {
            if (NULL != pCorpusFile[i].corpusBinaryData)
            {
                qaeMemFree((void **)&pCorpusFile[i].corpusBinaryData);
                pCorpusFile[i].corpusBinaryData = NULL;
            }
        }
        /* Free corpus File Structure */
        qaeMemFree((void **)&pCorpusFile);
        corpus[corpusType].corpusData.fileArray = NULL;
        corpus[corpusType].corpusData.read = CPA_FALSE;
    }
    return;
}

/*stop all acceleration services*/
CpaStatus stopDcServices(void)
{
    Cpa32U i = 0, j = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaBufferList **tempBufferList = NULL;
    Cpa16U numBuffers = 0;

    setDecompServiceRequest(0);

    if (decomp_service_started_g == CPA_TRUE)
    {
        decomp_service_started_g = CPA_FALSE;
    }
    if (decomp_polling_started_g == CPA_TRUE)
    {
        decomp_polling_started_g = CPA_FALSE;
        for (i = 0; i < numDecompPolledInstances_g; i++)
        {
            sampleCodeThreadJoin(&decompPollingThread_g[i]);
        }
        if (numDecompPolledInstances_g > 0)
        {
            qaeMemFree((void **)&decompPollingThread_g);
            numDecompPolledInstances_g = 0;
        }
    }

    if (decompInstances_g != NULL)
    {
        for (i = 0; i < numDecompInstances_g; i++)
        {
            cpaDcStopInstance(decompInstances_g[i]);
        }
        qaeMemFree((void **)&decompInstances_g);
        decompInstances_g = NULL;
        numDecompInstances_g = 0;
    }

    /*stop only if the services is in a started state*/
    if (dc_service_started_g == CPA_TRUE)
    {
        for (i = 0; i < numDcInstances_g; i++)
        {
            /* Free the Dynamic Buffers allocated
             * while starting DC Services
             */
            tempBufferList = pInterBuffList_g[i];
            status =
                cpaDcGetNumIntermediateBuffers(dcInstances_g[i], &numBuffers);
            for (j = 0; j < numBuffers; j++)
            {

                qaeMemFreeNUMA((void **)&tempBufferList[j]->pBuffers->pData);
                qaeMemFreeNUMA((void **)&tempBufferList[j]->pPrivateMetaData);
                qaeMemFreeNUMA((void **)&tempBufferList[j]->pBuffers);
                qaeMemFreeNUMA((void **)&tempBufferList[j]);
            }
            if (NULL != pInterBuffList_g[i])
            {
                /* free the buffer List*/
                qaeMemFreeNUMA((void **)&pInterBuffList_g[i]);
            }

            /*stop all instances*/
            cpaDcStopInstance(dcInstances_g[i]);
        }
        qaeMemFree((void **)&pInterBuffList_g);
        /*set the service started flag to false*/
        dc_service_started_g = CPA_FALSE;
    }
    /* Free the corpus Data */
    freeCorpus();
    if (dc_polling_started_g == CPA_TRUE)
    {
        /* set polling flag to false */
        dc_polling_started_g = CPA_FALSE;
        /* Wait for all threads_g to complete */
        for (i = 0; i < numDcPolledInstances_g; i++)
        {
            sampleCodeThreadJoin(&dcPollingThread_g[i]);
        }
        if (numDcPolledInstances_g > 0)
        {
            qaeMemFree((void **)&dcPollingThread_g);
            numDcPolledInstances_g = 0;
        }
    }
    if (dcInstances_g != NULL)
    {
        qaeMemFree((void **)&dcInstances_g);
        dcInstances_g = NULL;
        numDcInstances_g = 0;
    }
    return status;
}

CpaStatus calculateRequireBuffers(compression_test_params_t *dcSetup)
{
    Cpa32U numberOfBuffers = 0, i = 0;
    Cpa32U numFiles = getNumFilesInCorpus(dcSetup->corpus);
    const corpus_file_t *const pCorpusFile = getFilesInCorpus(dcSetup->corpus);

    if (dcSetup->corpusFileIndex >= numFiles)
    {
        dcSetup->corpusFileIndex = 0;
    }

    dcSetup->numberOfBuffers = qaeMemAlloc(numFiles * sizeof(Cpa32U));
    if (NULL == dcSetup->numberOfBuffers)
    {
        PRINT("Could not allocate memory for dcSetup numberOfBuffers array");
        return CPA_STATUS_FAIL;
    }
    for (i = 0; i < numFiles; i++)
    {
        /*get number of full sized buffers, ignoring the last bit less than
         * the full buffer size*/
        if (pCorpusFile[i].corpusBinaryDataLen < dcSetup->bufferSize)
        {
            PRINT("Warning the input file size(%d) is less than the specified "
                  "buffer size(%d), results may be skewed\n",
                  pCorpusFile[i].corpusBinaryDataLen,
                  dcSetup->bufferSize);
            numberOfBuffers = 1;
        }
        else
        {
            numberOfBuffers =
                pCorpusFile[i].corpusBinaryDataLen / dcSetup->bufferSize;
        }
        dcSetup->numberOfBuffers[i] = numberOfBuffers;
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(calculateRequireBuffers);

#if defined(USER_SPACE) && !defined(SC_EPOLL_DISABLED)
#endif /* USER_SPACE && !SC_EPOLL_DISABLED */

CpaStatus dcCreatePollingThreadsIfPollingIsEnabled(void)
{
    CpaInstanceInfo2 *instanceInfo2 = NULL;
    Cpa16U i = 0, j = 0, numCreatedPollingThreads = 0;
    Cpa32U coreAffinity = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    performance_func_t *pollFnArr = NULL;
#ifdef SC_CORE_NUM_POLICY
    Cpa32U numCores = 0;
    numCores = sampleCodeGetNumberOfCpus();
    if (numCores <= 0)
    {
        PRINT_ERR("sampleCodeGetNumberOfCpus() failed\n");
        return CPA_STATUS_FAIL;
    }
#endif

    if (CPA_FALSE == dc_polling_started_g)
    {
        instanceInfo2 =
            qaeMemAlloc(numDcInstances_g * sizeof(CpaInstanceInfo2));
        if (NULL == instanceInfo2)
        {
            PRINT_ERR("Failed to allocate memory for pInstanceInfo2");
            return CPA_STATUS_FAIL;
        }
        pollFnArr = qaeMemAlloc(numDcInstances_g * sizeof(performance_func_t));
        if (NULL == pollFnArr)
        {
            PRINT_ERR("Failed to allocate memory for polling functions\n");
            qaeMemFree((void **)&instanceInfo2);
            return CPA_STATUS_FAIL;
        }
        for (i = 0; i < numDcInstances_g; i++)
        {
            status = cpaDcInstanceGetInfo2(dcInstances_g[i], &instanceInfo2[i]);
            if (CPA_STATUS_SUCCESS != status)
            {
                qaeMemFree((void **)&instanceInfo2);
                qaeMemFree((void **)&pollFnArr);
                return CPA_STATUS_FAIL;
            }
            pollFnArr[i] = NULL;
            if (CPA_TRUE == instanceInfo2[i].isPolled)
            {
                numDcPolledInstances_g++;
#if defined(USER_SPACE) && !defined(SC_EPOLL_DISABLED)
                {
                    status = trySetupDcLegacyEventPoll(dcInstances_g[i],
                                                       &pollFnArr[i]);
                    if (CPA_STATUS_FAIL == status)
                    {
                        PRINT_ERR(
                            "Error getting file descriptor for Event based "
                            "instance #%d\n",
                            i);
                        qaeMemFree((void **)&instanceInfo2);
                        qaeMemFree((void **)&pollFnArr);
                        return CPA_STATUS_FAIL;
                    }
                }
#endif /* USER_SPACE && !defined(SC_EPOLL_DISABLED) */
                if (NULL == pollFnArr[i])
                {
                    pollFnArr[i] = sampleCodeDcPoll;
                }
            }
        }
        if (0 == numDcPolledInstances_g)
        {
            qaeMemFree((void **)&instanceInfo2);
            qaeMemFree((void **)&pollFnArr);
            return CPA_STATUS_SUCCESS;
        }
        dcPollingThread_g =
            qaeMemAlloc(numDcPolledInstances_g * sizeof(sample_code_thread_t));
        if (NULL == dcPollingThread_g)
        {
            PRINT_ERR("Failed to allocate memory for polling threads\n");
            qaeMemFree((void **)&instanceInfo2);
            qaeMemFree((void **)&pollFnArr);
            return CPA_STATUS_FAIL;
        }
        for (i = 0; i < numDcInstances_g; i++)
        {
            if (NULL != pollFnArr[i])
            {
                status = sampleCodeThreadCreate(
                    &dcPollingThread_g[numCreatedPollingThreads],
                    NULL,
                    pollFnArr[i],
                    dcInstances_g[i]);
                if (status != CPA_STATUS_SUCCESS)
                {
                    PRINT_ERR("Error starting polling thread %d\n", status);
                    /*attempt to stop any started service, we don't check status
                     * as some instances may not have been started and
                     * this might return fail*/
                    qaeMemFree((void **)&instanceInfo2);
                    qaeMemFree((void **)&pollFnArr);
                    return CPA_STATUS_FAIL;
                }
                /*loop of the instanceInfo coreAffinity bitmask to find
                 * the core affinity*/
                for (j = 0; j < CPA_MAX_CORES; j++)
                {
                    if (CPA_BITMAP_BIT_TEST(instanceInfo2[i].coreAffinity, j))
                    {
#if defined(USER_SPACE)
                        coreAffinity = j;
#else
                        coreAffinity = j + 1;
#endif
                        break;
                    }
                }
#ifdef SC_CORE_NUM_POLICY
                if (numDcInstances_g % numCores == 0)
                {
                    /* To avoid recalculated and original core
                     * assignment equality */
                    coreAffinity =
                        (coreAffinity + numDcInstances_g + 1) % numCores;
                }
                else
                {
                    coreAffinity = (coreAffinity + numDcInstances_g) % numCores;
                }
#endif
                sampleCodeThreadBind(
                    &dcPollingThread_g[numCreatedPollingThreads], coreAffinity);
                sampleCodeThreadStart(
                    &dcPollingThread_g[numCreatedPollingThreads]);
                numCreatedPollingThreads++;
            }
        }
        qaeMemFree((void **)&instanceInfo2);
        qaeMemFree((void **)&pollFnArr);
        dc_polling_started_g = CPA_TRUE;
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(dcCreatePollingThreadsIfPollingIsEnabled);

inline CpaStatus dcDpPollNumOperations(perf_data_t *pPerfData,
                                       CpaInstanceHandle instanceHandle,
                                       Cpa64U numOperations)
{
    Cpa32U retries;
    return dcDpPollNumOperationsRetries(
        pPerfData, instanceHandle, numOperations, &retries);
}

CpaStatus dcDpPollNumOperationsRetries(perf_data_t *pPerfData,
                                       CpaInstanceHandle instanceHandle,
                                       Cpa64U numOperations,
                                       Cpa32U *retries)
{
    CpaStatus status = CPA_STATUS_FAIL;

    perf_cycles_t startCycles = 0, totalCycles = 0;
    Cpa32U freq = sampleCodeGetCpuFreq();
    CpaInstanceInfo2 info2 = { 0 };
    *retries = 0;
    startCycles = sampleCodeTimestamp();

    status = cpaDcInstanceGetInfo2(instanceHandle, &info2);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaDcInstanceGetInfo2 failed. (status = %d)\n", status);
        return status;
    }

    while (pPerfData->responses != numOperations)
    {
        if (CPA_TRUE == info2.isPolled)
        {
            coo_poll_dp_dc(pPerfData, instanceHandle, &status);
            /* in case when polling is used to process request's response
               which is not handled by coo measurement */
            if (CPA_STATUS_FAIL == status)
                 status = icp_sal_DcPollDpInstance(instanceHandle, 0);
        }
        if (CPA_STATUS_FAIL == status)
        {
            PRINT_ERR("Error polling instance\n");
            return CPA_STATUS_FAIL;
        }
        if (CPA_STATUS_RETRY == status)
        {
            (*retries)++;
            AVOID_SOFTLOCKUP;
        }
        totalCycles = (sampleCodeTimestamp() - startCycles);
        if (totalCycles > 0)
        {
            do_div(totalCycles, freq);
        }

        if (totalCycles > SAMPLE_CODE_WAIT_DEFAULT)
        {
            PRINT_ERR("Timeout on polling remaining Operations\n");
            PRINT("Expected %llu responses, revieved %llu\n",
                  (unsigned long long)numOperations,
                  (unsigned long long)pPerfData->responses);
            return CPA_STATUS_FAIL;
        }
    }
    return CPA_STATUS_SUCCESS;
}

/* If an error has occurred in-between the submissions loop,
 * wait for all in-flight requests has been processed.
 * Post this function, memory resources that are used by the
 * SAL library are de-allocated.
 */
CpaStatus waitForInflightRequestAfterError(perf_data_t *perfData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U tryLoops = 0;

    /* Give 3 tries to collect all the responses while waiting on the
     * semaphore. The ASYNC callback should release the semaphore
     * only when the responses are equal to expected number of operation.
     * If an error occurs in between, the subsequent submission of requests
     * is stopped and hence the response will always be less than expected
     * number of operation, meaning the semaphore is never released by the
     * callback function. Hence it should be timing out always here.
     */
    while ((perfData->responses < perfData->submissions) && tryLoops < 3)
    {
        status =
            sampleCodeSemaphoreWait(&perfData->comp, SAMPLE_CODE_WAIT_DEFAULT);
        tryLoops++;
    }

    if (perfData->responses < perfData->submissions)
    {
        PRINT_ERR("WARNING: Not all in-flight requests collected! "
                  "Submissions: %u, Responses: %llu\n",
                  perfData->submissions,
                  (unsigned long long)perfData->responses);
        if (status == CPA_STATUS_SUCCESS)
        {
            PRINT_ERR(" \tWait Semaphore released!\n");
        }
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

CpaStatus waitForSemaphore(perf_data_t *perfData)
{
    Cpa64S responsesReceived = INITIAL_RESPONSE_COUNT;
    CpaStatus status = CPA_STATUS_SUCCESS;

    /*wait for the callback to receive all responses and free the
     * semaphore, or if in sync mode, the semaphore should already be free*/

    while (sampleCodeSemaphoreWait(&perfData->comp, SAMPLE_CODE_WAIT_DEFAULT) !=
           CPA_STATUS_SUCCESS)
    {
        if (INITIAL_RESPONSE_COUNT != responsesReceived &&
            responsesReceived != (Cpa64S)perfData->numOperations &&
            responsesReceived == (Cpa64S)perfData->responses)
        {
            PRINT_ERR("System is not responding\n");
            PRINT("Responses expected/received: %llu/%llu\n",
                  (unsigned long long)perfData->numOperations,
                  (unsigned long long)perfData->responses);
            status = CPA_STATUS_FAIL;
            break;
        }
        else
        {
            responsesReceived = perfData->responses;
        }
    }
    return status;
}
EXPORT_SYMBOL(waitForSemaphore);

CpaStatus sampleCodeDcGetNode(CpaInstanceHandle instanceHandle, Cpa32U *node)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaInstanceInfo2 pInstanceInfo2;
    status = cpaDcInstanceGetInfo2(instanceHandle, &pInstanceInfo2);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to get Node affinity\n");
        return status;
    }
    *node = pInstanceInfo2.nodeAffinity;
    return status;
}
EXPORT_SYMBOL(sampleCodeDcGetNode);

/* Change to a compression callback tag with parameter for poll interval */
void sampleCodeDcPoll(CpaInstanceHandle instanceHandle_in)
{
    CpaStatus status = CPA_STATUS_FAIL;
#ifdef USER_SPACE
    struct timespec reqTime, remTime;
    reqTime.tv_sec = 0;
    reqTime.tv_nsec = dcPollingThreadsInterval_g;
#endif
    while (dc_service_started_g == CPA_TRUE)
    {
        /*poll for 0 means process all packets on the ET ring */
        status = icp_sal_DcPollInstance(instanceHandle_in, 0);
        if (CPA_STATUS_SUCCESS == status || CPA_STATUS_RETRY == status)
        {
            /* do nothing */
        }
        else
        {
            PRINT_ERR("ERROR icp_sal_DcPollInstance returned status %d\n",
                      status);
            error_flag_g = CPA_TRUE;
            break;
        }
#ifdef USER_SPACE
        nanosleep(&reqTime, &remTime);
#else
        sampleCodeSleepMilliSec(DEFAULT_POLL_INTERVAL_KERNEL);
#endif
    }
    sampleCodeThreadExit();
}

static void sampleCodeDecompPoll(CpaInstanceHandle instanceHandle_in)
{
    CpaStatus status = CPA_STATUS_FAIL;
#ifdef USER_SPACE
    struct timespec reqTime, remTime;
    reqTime.tv_sec = 0;
    reqTime.tv_nsec = dcPollingThreadsInterval_g;
#endif
    while (decomp_service_started_g == CPA_TRUE)
    {
        status = icp_sal_DcPollInstance(instanceHandle_in, 0);
        if (CPA_STATUS_SUCCESS == status || CPA_STATUS_RETRY == status)
        {
            /* do nothing */
        }
        else
        {
            PRINT_ERR("ERROR icp_sal_DcPollInstance returned status %d "
                      "for DECOMP instance\n",
                      status);
            error_flag_g = CPA_TRUE;
            break;
        }
#ifdef USER_SPACE
        nanosleep(&reqTime, &remTime);
#else
        sampleCodeSleepMilliSec(DEFAULT_POLL_INTERVAL_KERNEL);
#endif
    }
    sampleCodeThreadExit();
}

CpaStatus dcCreateDecompPollingThreads(void)
{
    CpaInstanceInfo2 instanceInfo2 = { 0 };
    Cpa16U i = 0, j = 0, numCreatedPollingThreads = 0;
    Cpa32U coreAffinity = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (CPA_TRUE == decomp_polling_started_g)
    {
        return CPA_STATUS_SUCCESS;
    }
    if (0 == numDecompInstances_g || NULL == decompInstances_g)
    {
        return CPA_STATUS_SUCCESS;
    }
    for (i = 0; i < numDecompInstances_g; i++)
    {
        status = cpaDcInstanceGetInfo2(decompInstances_g[i], &instanceInfo2);
        if (CPA_STATUS_SUCCESS != status)
        {
            return CPA_STATUS_FAIL;
        }
        if (CPA_TRUE == instanceInfo2.isPolled)
        {
            numDecompPolledInstances_g++;
        }
    }
    if (0 == numDecompPolledInstances_g)
    {
        return CPA_STATUS_SUCCESS;
    }

    decompPollingThread_g =
        qaeMemAlloc(numDecompPolledInstances_g * sizeof(sample_code_thread_t));
    if (NULL == decompPollingThread_g)
    {
        PRINT_ERR("Failed to allocate memory for DECOMP polling threads\n");
        return CPA_STATUS_FAIL;
    }

    for (i = 0; i < numDecompInstances_g; i++)
    {
        status = cpaDcInstanceGetInfo2(decompInstances_g[i], &instanceInfo2);
        if (CPA_STATUS_SUCCESS != status)
        {
            qaeMemFree((void **)&decompPollingThread_g);
            return CPA_STATUS_FAIL;
        }
        if (CPA_TRUE == instanceInfo2.isPolled)
        {
            status = sampleCodeThreadCreate(
                &decompPollingThread_g[numCreatedPollingThreads],
                NULL,
                (performance_func_t)sampleCodeDecompPoll,
                decompInstances_g[i]);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error starting DECOMP polling thread %d\n", status);
                qaeMemFree((void **)&decompPollingThread_g);
                return CPA_STATUS_FAIL;
            }
            for (j = 0; j < CPA_MAX_CORES; j++)
            {
                if (CPA_BITMAP_BIT_TEST(instanceInfo2.coreAffinity, j))
                {
#if defined(USER_SPACE)
                    coreAffinity = j;
#else
                    coreAffinity = j + 1;
#endif
                    break;
                }
            }
            sampleCodeThreadBind(
                &decompPollingThread_g[numCreatedPollingThreads], coreAffinity);
            sampleCodeThreadStart(
                &decompPollingThread_g[numCreatedPollingThreads]);
            numCreatedPollingThreads++;
        }
    }
    decomp_polling_started_g = CPA_TRUE;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(dcCreateDecompPollingThreads);

CpaStatus stopDcServicesFromPrintStats(thread_creation_data_t *dummy_ptr)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* stop DC Services */
    status = stopDcServices();
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to stop DC services\n");
    }
    return status;
}
EXPORT_SYMBOL(stopDcServicesFromPrintStats);

CpaStatus dcPrintStats(thread_creation_data_t *data)
{
    perf_cycles_t numOfCycles = {0};
    perf_data_t stats = {0};
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i = 0;
    Cpa32U throughput = 0;
    Cpa32U bytesConsumed = 0, bytesProduced = 0;
    Cpa32U averageNumLoops = 0;
    compression_test_params_t *dcSetup =
        (compression_test_params_t *)data->setupPtr;
    Cpa32U numberOfUnsupportedThreads = 0;
    Cpa32U totalThreadsRan = 0;

    /* stop DC Services */
    status = stopDcServices();
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to stop DC services\n");
        return status;
    }

    memset(&stats, 0, sizeof(perf_data_t));
    stats.averagePacketSizeInBytes = data->packetSize;

    /* get the longest start time and longest End time
     * from the performance stats structure
     */
    getLongestCycleCount(&stats, data->performanceStats, data->numberOfThreads);

    /* Get the total number of responses, bytes consumed and bytes produced
     * for all the threads */
    for (i = 0; i < data->numberOfThreads; i++)
    {
        if (CPA_STATUS_UNSUPPORTED ==
            data->performanceStats[i]->threadReturnStatus)
        {
            numberOfUnsupportedThreads++;
        }
        else if (CPA_STATUS_FAIL ==
                 data->performanceStats[i]->threadReturnStatus)
        {
            return CPA_STATUS_FAIL;
        }
        if (CPA_STATUS_SUCCESS == data->performanceStats[i]->threadReturnStatus)
        {
            if (!signOfLife)
            {

            if (latency_enable)
            {
                /* Accumulate over all tests. Before using later we divide
                 * by number of threads: data->numberOfThreads*/
                stats.minLatency += data->performanceStats[i]->minLatency;
                stats.aveLatency += data->performanceStats[i]->aveLatency;
                stats.maxLatency += data->performanceStats[i]->maxLatency;
            }
            if (latency_debug)
            {
                /* NOTE: These numbers are in CPU cycles here */
                PRINT(", minLatency: %llu, aveLatency: %llu, maxLatency: %llu",
                      data->performanceStats[i]->minLatency,
                      data->performanceStats[i]->aveLatency,
                      data->performanceStats[i]->maxLatency);
                PRINT("\n");
            }
        }
        if (iaCycleCount_g)
        {
            stats.offloadCycles += data->performanceStats[i]->offloadCycles;
        }
        averageNumLoops += data->performanceStats[i]->numLoops;
        stats.retries += data->performanceStats[i]->retries;
        stats.responses += data->performanceStats[i]->responses;
        bytesConsumed += data->performanceStats[i]->bytesConsumedPerLoop;
        bytesProduced += data->performanceStats[i]->bytesProducedPerLoop;
        dcSetup->numLoops = data->performanceStats[i]->numLoops;
        clearPerfStats(data->performanceStats[i]);
        }
    }
    totalThreadsRan = data->numberOfThreads - numberOfUnsupportedThreads;
    /* get the maximum number of cycles Required */
    numOfCycles = (stats.endCyclesTimestamp - stats.startCyclesTimestamp);

    /*don't assume that all threads submitted all loops
     * if the averageNumLoops does not equal the plan then that means
     * the thread exited early, so we need to use the average to calculate the
     * throughput*/
    if (totalThreadsRan != 0)
    {
        do_div(averageNumLoops, totalThreadsRan);
    }
    if (averageNumLoops != dcSetup->numLoops)
    {
        dcSetup->numLoops = averageNumLoops;
    }
    /* Print Statistics */
    dcPrintTestData(dcSetup);
    PRINT("Number of threads      %d\n", data->numberOfThreads);
    if (numberOfUnsupportedThreads)
    {
        PRINT("Unsupported Threads      %u\n", numberOfUnsupportedThreads);
    }
    PRINT("Total Threads ran      %u\n", totalThreadsRan);
    PRINT("Total Responses        %llu\n", (unsigned long long)stats.responses);
    PRINT("Total Retries          %llu\n", (unsigned long long)stats.retries);
    PRINT("Clock Cycles Start     %llu\n", stats.startCyclesTimestamp);
    PRINT("Clock Cycles End       %llu\n", stats.endCyclesTimestamp);
    if (!signOfLife)
    {
        PRINT("Total Cycles           %llu\n", numOfCycles);
        PRINT("CPU Frequency(kHz)     %u\n", sampleCodeGetCpuFreq());
        throughput =
            getDcThroughput(bytesConsumed, numOfCycles, dcSetup->numLoops);
        {
            PRINT("Throughput(Mbps)       %u\n", throughput);
        }

        dcCalculateAndPrintCompressionRatio(bytesConsumed, bytesProduced);
        if (iaCycleCount_g && (totalThreadsRan != 0))
        {
            do_div(stats.offloadCycles, totalThreadsRan);
            PRINT("Avg Offload Cycles        %llu\n", stats.offloadCycles);
        }
        if (latency_enable && (totalThreadsRan != 0))
        {
            perf_cycles_t statsLatency = 0;
            perf_cycles_t cpuFreqKHz = sampleCodeGetCpuFreq();

            /* Display how long it took on average to process a buffer in uSecs
             * Also include min/max to show variance */
            do_div(stats.minLatency, totalThreadsRan);
            statsLatency = 1000 * stats.minLatency;
            do_div(statsLatency, cpuFreqKHz);
            PRINT("Min. Latency (uSecs)      %llu\n", statsLatency);
            do_div(stats.aveLatency, totalThreadsRan);
            statsLatency = 1000 * stats.aveLatency;
            do_div(statsLatency, cpuFreqKHz);
            PRINT("Ave. Latency (uSecs)      %llu\n", statsLatency);
            do_div(stats.maxLatency, totalThreadsRan);
            statsLatency = 1000 * stats.maxLatency;
            do_div(statsLatency, cpuFreqKHz);
            PRINT("Max. Latency (uSecs)      %llu\n", statsLatency);
        }
    }
    return status;
}
EXPORT_SYMBOL(dcPrintStats);

#ifdef SC_CHAINING_ENABLED
CpaStatus dcChainPrintStats(thread_creation_data_t *data)
{
    perf_cycles_t numOfCycles = {0};
    perf_data_t stats = {0};
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i = 0;
    Cpa32U throughput = 0, currentThroughput = 0;
    Cpa32U bytesConsumed = 0, bytesProduced = 0;
    Cpa32U averageNumLoops = 0;
    compression_test_params_t *dcSetup =
        (compression_test_params_t *)data->setupPtr;

    /* stop DC Services */
    status = stopDcServices();
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to stop DC services\n");
        return status;
    }

    memset(&stats, 0, sizeof(perf_data_t));
    stats.averagePacketSizeInBytes = data->packetSize;

    /* get the longest start time and longest End time
     * from the performance stats structure
     */
    getLongestCycleCount(&stats, data->performanceStats, data->numberOfThreads);

    /* Get the total number of responses, bytes consumed and bytes produced
     * for all the threads */
    for (i = 0; i < data->numberOfThreads; i++)
    {
        if (CPA_STATUS_FAIL == data->performanceStats[i]->threadReturnStatus)
        {
            return CPA_STATUS_FAIL;
        }

        if (!signOfLife)
        {
            numOfCycles = data->performanceStats[i]->endCyclesTimestamp -
                          data->performanceStats[i]->startCyclesTimestamp;
            throughput =
                getDcThroughput(data->performanceStats[i]->bytesConsumedPerLoop,
                                numOfCycles,
                                data->performanceStats[i]->numLoops);
            PRINT(
                "Thread: %u, Retries: %llu, throughput: %u, consumedPerLoop %u,\
                    numLoops %u",
                i,
                (unsigned long long)data->performanceStats[i]->retries,
                throughput,
                data->performanceStats[i]->bytesConsumedPerLoop,
                data->performanceStats[i]->numLoops);
            if (latency_enable)
            {
                /* NOTE: These numbers are in CPU cycles here */
                PRINT(", minLatency: %llu, aveLatency: %llu, maxLatency: %llu",
                      data->performanceStats[i]->minLatency,
                      data->performanceStats[i]->aveLatency,
                      data->performanceStats[i]->maxLatency);

                /* Accumulate over all tests. Before using later we divide
                 * by number of threads: data->numberOfThreads*/
                stats.minLatency += data->performanceStats[i]->minLatency;
                stats.aveLatency += data->performanceStats[i]->aveLatency;
                stats.maxLatency += data->performanceStats[i]->maxLatency;
            }
            PRINT("\n");
        }

        averageNumLoops += data->performanceStats[i]->numLoops;
        stats.retries += data->performanceStats[i]->retries;
        stats.responses += data->performanceStats[i]->responses;
        bytesConsumed += data->performanceStats[i]->bytesConsumedPerLoop;
        bytesProduced += data->performanceStats[i]->bytesProducedPerLoop;
        dcSetup->numLoops = data->performanceStats[i]->numLoops;
        currentThroughput += data->performanceStats[i]->currentThroughput;
        clearPerfStats(data->performanceStats[i]);
    }
    /* get the maximum number of cycles Required */
    numOfCycles = (stats.endCyclesTimestamp - stats.startCyclesTimestamp);

    /*don't assume that all threads submitted all loops
     * if the averageNumLoops does not equal the plan then that means
     * the thread exited early, so we need to use the average to calculate the
     * throughput*/
    if (data->numberOfThreads != 0)
    {
        do_div(averageNumLoops, data->numberOfThreads);
    }
    if (averageNumLoops != dcSetup->numLoops)
    {
        dcSetup->numLoops = averageNumLoops;
    }
    /* Print Statistics */
    dcChainPrintTestData(dcSetup);
    PRINT("Number of threads      %d\n", data->numberOfThreads);
    PRINT("Total Responses        %llu\n", (unsigned long long)stats.responses);
    PRINT("Total Retries          %llu\n", (unsigned long long)stats.retries);
    PRINT("Clock Cycles Start     %llu\n", stats.startCyclesTimestamp);
    PRINT("Clock Cycles End       %llu\n", stats.endCyclesTimestamp);
    if (!signOfLife)
    {
        PRINT("Total Cycles           %llu\n", numOfCycles);
        PRINT("CPU Frequency(kHz)     %u\n", sampleCodeGetCpuFreq());
        throughput =
            getDcThroughput(bytesConsumed, numOfCycles, dcSetup->numLoops);
        if (sleepTime_enable)
        {
            PRINT("Throughput(Mbps)       %u\n", currentThroughput);
        }
        else
        {
            PRINT("Throughput(Mbps)       %u\n", throughput);
        }

        dcCalculateAndPrintCompressionRatio(bytesConsumed, bytesProduced);
        if (latency_enable && (data->numberOfThreads != 0))
        {
            perf_cycles_t statsLatency = 0;
            perf_cycles_t cpuFreqKHz = sampleCodeGetCpuFreq();

            /* Display how long it took on average to process a buffer in uSecs
             * Also include min/max to show variance */
            do_div(stats.minLatency, data->numberOfThreads);
            statsLatency = 1000 * stats.minLatency;
            do_div(statsLatency, cpuFreqKHz);
            PRINT("Min. Latency (uSecs)   %llu\n", statsLatency);
            do_div(stats.aveLatency, data->numberOfThreads);
            statsLatency = 1000 * stats.aveLatency;
            do_div(statsLatency, cpuFreqKHz);
            PRINT("Ave. Latency (uSecs)   %llu\n", statsLatency);
            do_div(stats.maxLatency, data->numberOfThreads);
            statsLatency = 1000 * stats.maxLatency;
            do_div(statsLatency, cpuFreqKHz);
            PRINT("Max. Latency (uSecs)   %llu\n", statsLatency);
        }
    }
    return status;
}
EXPORT_SYMBOL(dcChainPrintStats);
#endif

void dcPrintTestData(compression_test_params_t *dcSetup)
{
    PRINT("API                    ");
    if (dcSetup->isDpApi)
    {
        PRINT("Data_Plane\n");
    }
    else
    {
        PRINT("Traditional\n");
    }
    PRINT("Session State          ");
    switch (dcSetup->setupData.sessState)
    {
        case (CPA_DC_STATEFUL):
            PRINT("STATEFUL\n");
            break;
        case (CPA_DC_STATELESS):
            PRINT("STATELESS\n");
            break;
        default:
            PRINT("Unsupported        %d\n", dcSetup->setupData.sessState);
            break;
    }

    PRINT("Algorithm              ");
    switch (dcSetup->setupData.compType)
    {
        case (CPA_DC_DEFLATE):
            PRINT("DEFLATE\n");
            break;
#if DC_API_VERSION_AT_LEAST(3, 1)
        case (CPA_DC_LZ4):
            PRINT("CPA_DC_LZ4\n");
            break;
        case (CPA_DC_LZ4S):
            PRINT("CPA_DC_LZ4S\n");
            break;
#endif
        default:
            PRINT("Unsupported        %d\n", dcSetup->setupData.compType);
            break;
    }

#if DC_API_VERSION_AT_LEAST(3, 1)
    /*
     * Print MinMatch information for LZ4S algorithm.
     * The Min Match configuration (3_BYTE_MATCH or 4_BYTE_MATCH)
     * determines the minimum length of match
     * sequence for LZ4S compression.
     */
    if (dcSetup->setupData.compType == CPA_DC_LZ4S)
    {
        PRINT("Min Match              ");
        switch (dcSetup->setupData.minMatch)
        {
            case (CPA_DC_MIN_3_BYTE_MATCH):
                PRINT("3_BYTE_MATCH\n");
                break;
            case (CPA_DC_MIN_4_BYTE_MATCH):
                PRINT("4_BYTE_MATCH\n");
                break;
            default:
                PRINT("Unsupported        %d\n", dcSetup->setupData.minMatch);
                break;
        }
    }
#endif

    PRINT("Huffman Type           ");
    switch (dcSetup->setupData.huffType)
    {
        case (CPA_DC_HT_STATIC):
            PRINT("STATIC\n");
            break;
        case (CPA_DC_HT_FULL_DYNAMIC):
            PRINT("DYNAMIC\n");
            break;
        default:
            PRINT("Unsupported        %d\n", dcSetup->setupData.huffType);
            break;
    }

    PRINT("Mode                   ");
    switch (dcSetup->syncFlag)
    {
        case (SYNC):
            PRINT("SYNCHRONOUS\n");
            break;
        case (ASYNC):
            PRINT("ASYNCHRONOUS\n");
            break;
        default:
            PRINT("Unsupported %d\n", dcSetup->syncFlag);
            break;
    }

    if ((CPA_DC_STATELESS == dcSetup->setupData.sessState) &&
        (CPA_DC_DIR_COMPRESS == dcSetup->dcSessDir))
    {
        PRINT("CNV Enabled            ");
        switch (dcSetup->requestOps.compressAndVerify)
        {
            case (CPA_TRUE):
                PRINT("YES\n");
                break;
            case (CPA_FALSE):
                PRINT("NO\n");
                break;
            default:
                PRINT("Not known\n");
                break;
        }
    }

    PRINT("Direction              ");
    switch (dcSetup->dcSessDir)
    {
        case (CPA_DC_DIR_COMPRESS):
            PRINT("COMPRESS");
            break;
        case (CPA_DC_DIR_DECOMPRESS):
            PRINT("DECOMPRESS");
            break;
        case (CPA_DC_DIR_COMBINED):
            PRINT("COMBINED");
            break;
        default:
            PRINT("Unsupported        %d\n", dcSetup->setupData.sessDirection);
            break;
    }
    if (useZlib_g)
    {
        PRINT("(from SW lib compressed data)\n");
    }
    else
    {
        PRINT("\n");
    }

    if (dcSetup->isUseSGL)
    {
        PRINT("Packet Size            %d x %d\n",
              dcSetup->numFlatsPerSGL,
              dcSetup->bufferSize);
    }
    else
    {
        PRINT("Packet Size            %d\n", dcSetup->bufferSize);
    }

    PRINT("Compression Level      %d\n", dcSetup->setupData.compLevel);

    PRINT("Corpus                 ");
    PRINT("%s\n", getCorpusName(dcSetup->corpus));
    PRINT("Corpus Filename        ");
    PRINT("%s\n",
          getFileNameInCorpus(dcSetup->corpus, dcSetup->corpusFileIndex));
#if DC_API_VERSION_AT_LEAST(2, 2)
    PRINT("CNV Recovery Enabled   ");
    switch (CNV_RECOVERY(&dcSetup->requestOps))
    {
        case (CPA_TRUE):
            PRINT("YES\n");
            break;
        case (CPA_FALSE):
            PRINT("NO\n");
            break;
        default:
            PRINT("Not known\n");
            break;
    }
#endif
}
EXPORT_SYMBOL(dcPrintTestData);

void dcChainPrintTestData(compression_test_params_t *chainSetup)
{
    PRINT("API                    ");
    if (chainSetup->isDpApi)
    {
        PRINT("Data_Plane\n");
    }
    else
    {
        PRINT("Traditional\n");
    }

    PRINT("Algorithm Chaining     ");
    switch (chainSetup->chainOperation)
    {
        case (CPA_DC_CHAIN_HASH_THEN_COMPRESS):
            if (chainSetup->symSetupData.hashSetupData.hashAlgorithm ==
                    CPA_CY_SYM_HASH_SHA1 &&
                chainSetup->setupData.sessState == CPA_DC_STATELESS &&
                chainSetup->setupData.huffType == CPA_DC_HT_STATIC)
            {
                PRINT("SHA1 Stateless Static Compression Chaining\n");
            }
            else if (chainSetup->symSetupData.hashSetupData.hashAlgorithm ==
                         CPA_CY_SYM_HASH_SHA224 &&
                     chainSetup->setupData.sessState == CPA_DC_STATELESS &&
                     chainSetup->setupData.huffType == CPA_DC_HT_STATIC)
            {
                PRINT("SHA2-224 Stateless Static Compression Chaining\n");
            }
            else if (chainSetup->symSetupData.hashSetupData.hashAlgorithm ==
                         CPA_CY_SYM_HASH_SHA256 &&
                     chainSetup->setupData.sessState == CPA_DC_STATELESS &&
                     chainSetup->setupData.huffType == CPA_DC_HT_STATIC)
            {
                PRINT("SHA2-256 Stateless Static Compression Chaining\n");
            }
            else if (chainSetup->symSetupData.hashSetupData.hashAlgorithm ==
                         CPA_CY_SYM_HASH_SHA1 &&
                     chainSetup->setupData.sessState == CPA_DC_STATELESS &&
                     chainSetup->setupData.huffType == CPA_DC_HT_FULL_DYNAMIC)
            {
                PRINT("SHA1 Stateless Dynamic Compression Chaining\n");
            }
            else if (chainSetup->symSetupData.hashSetupData.hashAlgorithm ==
                         CPA_CY_SYM_HASH_SHA224 &&
                     chainSetup->setupData.sessState == CPA_DC_STATELESS &&
                     chainSetup->setupData.huffType == CPA_DC_HT_FULL_DYNAMIC)
            {
                PRINT("SHA2-224 Stateless Dynamic Compression Chaining\n");
            }
            else if (chainSetup->symSetupData.hashSetupData.hashAlgorithm ==
                         CPA_CY_SYM_HASH_SHA256 &&
                     chainSetup->setupData.sessState == CPA_DC_STATELESS &&
                     chainSetup->setupData.huffType == CPA_DC_HT_FULL_DYNAMIC)
            {
                PRINT("SHA2-256 Stateless Dynamic Compression Chaining\n");
            }
            else
            {
                PRINT("Unsupported Algorithm Chaining\n");
            }
            break;
        case (CPA_DC_CHAIN_COMPRESS_THEN_ENCRYPT):
            if (chainSetup->symSetupData.cipherSetupData.cipherAlgorithm ==
                    CPA_CY_SYM_CIPHER_AES_CBC &&
                chainSetup->setupData.sessState == CPA_DC_STATELESS &&
                chainSetup->setupData.huffType == CPA_DC_HT_STATIC)
            {
                PRINT("Static Stateless Compress AES_CBC Encrypt Chaining\n");
            }
            break;
        case (CPA_DC_CHAIN_COMPRESS_THEN_AEAD):
            if (chainSetup->symSetupData.cipherSetupData.cipherAlgorithm ==
                    CPA_CY_SYM_CIPHER_AES_GCM &&
                chainSetup->setupData.sessState == CPA_DC_STATELESS &&
                chainSetup->setupData.huffType == CPA_DC_HT_FULL_DYNAMIC)
            {
                PRINT("Dynamic Stateless Compress AES_GCM Encrypt Chaining\n");
            }
            break;
        case (CPA_DC_CHAIN_AEAD_THEN_DECOMPRESS):
            if (chainSetup->symSetupData.cipherSetupData.cipherAlgorithm ==
                    CPA_CY_SYM_CIPHER_AES_GCM &&
                chainSetup->setupData.sessState == CPA_DC_STATELESS &&
                chainSetup->setupData.huffType == CPA_DC_HT_FULL_DYNAMIC)
            {
                PRINT("Dynamic Stateless AES_GCM Decrypt Decompression "
                      "Chaining\n");
            }
            break;
        default:
            PRINT("Unsupported        %d\n", chainSetup->chainOperation);
            break;
    }

    PRINT("Mode                   ");
    switch (chainSetup->syncFlag)
    {
        case (SYNC):
            PRINT("SYNCHRONOUS\n");
            break;
        case (ASYNC):
            PRINT("ASYNCHRONOUS\n");
            break;
        default:
            PRINT("Unsupported %d\n", chainSetup->syncFlag);
            break;
    }

    if ((CPA_DC_STATELESS == chainSetup->setupData.sessState) &&
        (CPA_DC_DIR_COMPRESS == chainSetup->dcSessDir))
    {
        PRINT("CNV Enabled            ");
        switch (chainSetup->requestOps.compressAndVerify)
        {
            case (CPA_TRUE):
                PRINT("YES\n");
                break;
            case (CPA_FALSE):
                PRINT("NO\n");
                break;
            default:
                PRINT("Not known\n");
                break;
        }
    }

    PRINT("Direction              ");
    switch (chainSetup->dcSessDir)
    {
        case (CPA_DC_DIR_COMPRESS):
            PRINT("COMPRESS");
            break;
        case (CPA_DC_DIR_DECOMPRESS):
            PRINT("DECOMPRESS");
            break;
        case (CPA_DC_DIR_COMBINED):
            PRINT("COMBINED");
            break;
        default:
            PRINT("Unsupported        %d\n",
                  chainSetup->setupData.sessDirection);
            break;
    }
    if (useZlib_g)
    {
        PRINT("(from SW lib compressed data)\n");
    }
    else
    {
        PRINT("\n");
    }

    PRINT("Packet Size            %d\n", chainSetup->bufferSize);

    PRINT("Compression Level      %d\n", chainSetup->setupData.compLevel);

    PRINT("Corpus                 ");
    PRINT("%s\n", getCorpusName(chainSetup->corpus));
    PRINT("Corpus Filename        ");
    PRINT("%s\n",
          getFileNameInCorpus(chainSetup->corpus, chainSetup->corpusFileIndex));
#if DC_API_VERSION_AT_LEAST(2, 2)
    PRINT("CNV Recovery Enabled   ");
    switch (CNV_RECOVERY(&chainSetup->requestOps))
    {
        case (CPA_TRUE):
            PRINT("YES\n");
            break;
        case (CPA_FALSE):
            PRINT("NO\n");
            break;
        default:
            PRINT("Not known\n");
            break;
    }
#endif
}
EXPORT_SYMBOL(dcChainPrintTestData);

void dcDpSetBytesProducedAndConsumed(CpaDcDpOpData ***opdata,
                                     perf_data_t *perfData,
                                     compression_test_params_t *setup)
{
    Cpa32U i = 0, j = 0, numSamples;
    Cpa32U numFiles = getNumFilesInCorpus(setup->corpus);

    for (i = 0; i < numFiles; i++)
    {
        if (setup->isUseSGL)
            numSamples = setup->numberOfSGLs[i];
        else
            numSamples = setup->numberOfBuffers[i];
        for (j = 0; j < numSamples; j++)
        {
            perfData->bytesConsumedPerLoop += opdata[i][j]->results.consumed;
            perfData->bytesProducedPerLoop += opdata[i][j]->results.produced;
        }
    }
}

void dcSetBytesProducedAndConsumed(CpaDcRqResults ***cmpResult,
                                   perf_data_t *perfData,
                                   compression_test_params_t *setup)
{

    Cpa32U i = 0, j = 0;
    Cpa32U numFiles = getNumFilesInCorpus(setup->corpus);

    for (i = 0; i < numFiles; i++)
    {
        for (j = 0; j < setup->numberOfBuffers[i]; j++)
        {

            perfData->bytesConsumedPerLoop += cmpResult[i][j]->consumed;
            perfData->bytesProducedPerLoop += cmpResult[i][j]->produced;
        }
    }
}
EXPORT_SYMBOL(dcSetBytesProducedAndConsumed);

CpaStatus dcCalculateAndPrintCompressionRatio(Cpa32U bytesConsumed,
                                              Cpa32U bytesProduced)
{

    if (0 == bytesConsumed)
    {
        PRINT("Divide by zero error on calculating compression ratio\n");
        return CPA_STATUS_FAIL;
    }
#ifdef USER_SPACE
    PRINT("Compression Ratio      %.04f\n",
          ((float)bytesProduced / bytesConsumed));
    return CPA_STATUS_SUCCESS;
#else
    ratio = bytesProduced * SCALING_FACTOR_1000;
    do_div(ratio, bytesConsumed);
    remainder = ratio % BASE_10;
    ratio = bytesProduced * SCALING_FACTOR_100;
    do_div(ratio, bytesConsumed);
    PRINT("Compression Ratio      0.%d%d\n", ratio, remainder);
    return CPA_STATUS_SUCCESS;
#endif
}

Cpa32U getDcThroughput(Cpa32U totalBytes,
                       perf_cycles_t cycles,
                       Cpa32U numOfLoops)
{
    unsigned long long bytesSent = 0;
    unsigned long long time = cycles;
    unsigned long long rate = 0;
    /* declare frequency in kiloHertz*/
    Cpa32U freq = sampleCodeGetCpuFreq();
    bytesSent = totalBytes;

    /*get time in milli seconds by dividing numberOfClockCycles by frequency
     * in kilohertz ie: cycles/(cycles/millsec) = time (mSec) */
    do_div(time, freq);
    /*check that the sample time was not to small*/
    if (time == 0)
    {
        PRINT_ERR("Sample time is too small to calculate throughput\n");
        return 0;
    }
    /*set rate to be bytesSent, once we perform the do_div rate changes from
     * bytes to bytes/milli second or kiloBytes/second*/
    rate = bytesSent * numOfLoops;
    /*rate in kBps*/
    do_div(rate, time);
    /*check that the rate is high enough to convert to Megabits per second*/
    if (rate == 0)
    {
        PRINT_ERR("no data was sent to calculate throughput\n");
        return 0;
    }
    /* convert Kilobytes/second to Kilobits/second*/
    rate = rate * NUM_BITS_IN_BYTE;
    /*then convert rate from Kilobits/second to Megabits/second*/
    do_div(rate, KILOBITS_IN_MEGABITS);
    return (Cpa32U)rate;
}

/*This function tells the compression sample code to use zLib software to
 * compress the data prior to calling the decompression*/
CpaStatus useZlib(void)
{
#ifdef USE_ZLIB
    useZlib_g = CPA_TRUE;
#else
#endif
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(useZlib);

/*This function tells the compression sample code to use zLib software to
 * compress the data prior to calling the decompression*/
CpaStatus useAccelCompression(void)
{
    useZlib_g = CPA_FALSE;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(useAccelCompression);

#ifdef ZERO_BYTE_LAST_REQUEST
CpaStatus enableZeroByteRequest(void)
{
    zeroByteLastRequest_g = CPA_TRUE;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(enableZeroByteRequest);

CpaStatus disableZeroByteRequest(void)
{
    zeroByteLastRequest_g = CPA_FALSE;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(disableZeroByteRequest);
#endif
/*****************************************************************************
 * * @description
 * Poll the number of dc operations
 * ***************************************************************************/
CpaStatus dcPollNumOperations(perf_data_t *pPerfData,
                              CpaInstanceHandle instanceHandle,
                              Cpa64U numOperations)
{
    CpaStatus status = CPA_STATUS_FAIL;

    perf_cycles_t startCycles = 0, totalCycles = 0;
    Cpa32U freq = sampleCodeGetCpuFreq();
    startCycles = sampleCodeTimestamp();

    while (pPerfData->responses != numOperations)
    {
        coo_poll_trad_dc(pPerfData, instanceHandle, &status);
        if (CPA_STATUS_FAIL == status)
        {
            PRINT_ERR("Error polling instance\n");
            return CPA_STATUS_FAIL;
        }
        if (CPA_STATUS_RETRY == status)
        {
            AVOID_SOFTLOCKUP;
        }
        totalCycles = (sampleCodeTimestamp() - startCycles);
        if (totalCycles > 0)
        {
            do_div(totalCycles, freq);
        }

        if (totalCycles > SAMPLE_CODE_WAIT_DEFAULT)
        {
            PRINT_ERR("Timeout on polling remaining Operations\n");
            return CPA_STATUS_FAIL;
        }
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(dcPollNumOperations);
CpaStatus dynamicHuffmanEnabled(CpaAccelerationServiceType accelSrvType,
                                CpaInstanceHandle *dcInstanceHandle,
                                CpaBoolean *isEnabled)
{
    CpaDcInstanceCapabilities capabilities = {0};
    CpaStatus status = CPA_STATUS_FAIL;
    CpaInstanceHandle pLocalDcInstanceHandle = NULL;
    Cpa16U numInstances = 0;

    /* Initialize to CPA_FALSE */
    *isEnabled = CPA_FALSE;

    if (NULL == dcInstanceHandle)
    {
        status = cpaGetNumInstances(accelSrvType, &numInstances);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to check if dynamic Huffman is enabled, "
                      "cpaGetNumInstances failed with status: %d\n",
                      status);
            return CPA_STATUS_FAIL;
        }
        if (0 == numInstances)
        {
            PRINT_ERR("Unable to check if dynamic Huffman is enabled, "
                      "No DC instances available");
            return CPA_STATUS_FAIL;
        }
        status = cpaGetInstances(accelSrvType, 1, &pLocalDcInstanceHandle);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to check if dynamic Huffman is enabled, "
                      "cpaGetInstances failed with status: %d"
                      "\n",
                      status);
            return CPA_STATUS_FAIL;
        }
    }
    else
    {
        pLocalDcInstanceHandle = *dcInstanceHandle;
    }
    status = cpaDcQueryCapabilities(pLocalDcInstanceHandle, &capabilities);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to check if dynamic Huffman is enabled, "
                  "cpaDcQueryCapabilities failed with status: %d"
                  "\n",
                  status);
        return CPA_STATUS_FAIL;
    }
    if (CPA_TRUE == capabilities.dynamicHuffman)
    {
        *isEnabled = CPA_TRUE;
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(dynamicHuffmanEnabled);

CpaStatus staticHuffmanEnabled(CpaAccelerationServiceType accelSrvType,
                               CpaInstanceHandle *dcInstanceHandle,
                               CpaBoolean *isEnabled)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaInstanceHandle pLocalDcInstanceHandle = NULL;
    CpaDcCapabilityReq capabilityReq = { 0 };
    capabilityReq.capId = CPA_DC_CAP_BOOL_STATIC_HUFFMAN;
    capabilityReq.algo = CPA_DC_DEFLATE;
    capabilityReq.dir = (accelSrvType == CPA_ACC_SVC_TYPE_DATA_COMPRESSION)
                            ? CPA_DC_DIR_COMPRESS
                            : CPA_DC_DIR_DECOMPRESS;
    CpaDcCapabilityResp capabilityResp = { 0 };
    Cpa16U numInstances = 0;

    if (NULL == isEnabled)
    {
        PRINT_ERR("isEnabled is NULL\n");
        return CPA_STATUS_FAIL;
    }

    /* Initialize to CPA_FALSE */
    *isEnabled = CPA_FALSE;

    if (NULL == dcInstanceHandle)
    {
        status = cpaGetNumInstances(accelSrvType, &numInstances);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to check if static Huffman is enabled, "
                      "cpaGetNumInstances failed with status: %d\n",
                      status);
            return CPA_STATUS_FAIL;
        }
        if (0 == numInstances)
        {
            PRINT_ERR("Unable to check if static Huffman is enabled, "
                      "No DC instances available");
            return CPA_STATUS_FAIL;
        }
        status = cpaGetInstances(accelSrvType, 1, &pLocalDcInstanceHandle);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to check if static Huffman is enabled, "
                      "cpaGetInstances failed with status: %d"
                      "\n",
                      status);
            return CPA_STATUS_FAIL;
        }
    }
    else
    {
        pLocalDcInstanceHandle = *dcInstanceHandle;
    }

    status = cpaDcQueryCapabilityByType(
        pLocalDcInstanceHandle, capabilityReq, &capabilityResp);

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to check if static Huffman is enabled, "
                  "cpaDcQueryCapabilityByType failed with status: %d"
                  "\n",
                  status);
        return CPA_STATUS_FAIL;
    }

    *isEnabled = capabilityResp.boolStatus;

    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(staticHuffmanEnabled);

CpaStatus dcSampleCreateStatefulContextBuffer(Cpa32U buffSize,
                                              Cpa32U metaSize,
                                              CpaBufferList **pBuffListArray,
                                              Cpa32U nodeId)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    *pBuffListArray =
        qaeMemAllocNUMA((sizeof(CpaBufferList)), nodeId, BYTE_ALIGNMENT_64);
    if (NULL == (*pBuffListArray))
    {
        PRINT_ERR(" Unable to allocate Buffers List Array\n");
        return CPA_STATUS_FAIL;
    }
    (*pBuffListArray)->numBuffers = ONE_BUFFER_DC;
    (*pBuffListArray)->pBuffers =
        qaeMemAllocNUMA((sizeof(CpaFlatBuffer)), nodeId, BYTE_ALIGNMENT_64);
    if (NULL == (*pBuffListArray)->pBuffers)
    {
        PRINT_ERR(" Unable to allocate Flat Buffers\n");
        qaeMemFreeNUMA((void **)pBuffListArray);
        return CPA_STATUS_FAIL;
    }
    if (metaSize)
    {
        (*pBuffListArray)->pPrivateMetaData =
            (Cpa8U *)qaeMemAllocNUMA(metaSize, nodeId, BYTE_ALIGNMENT_64);
        if (NULL == (*pBuffListArray)->pPrivateMetaData)
        {
            PRINT_ERR(" Unable to allocate pPrivateMetaData Buffers\n");
            qaeMemFreeNUMA((void **)&(*pBuffListArray)->pBuffers);
            qaeMemFreeNUMA((void **)pBuffListArray);
            return CPA_STATUS_FAIL;
        }
    }
    else
    {
        (*pBuffListArray)->pPrivateMetaData = NULL;
    }

    /* Allocate Flat buffer for each buffer List */
    (*pBuffListArray)->pBuffers->dataLenInBytes = buffSize;
    if (0 == buffSize)
    {
        (*pBuffListArray)->pBuffers->pData = NULL;
    }
    else
    {
        (*pBuffListArray)->pBuffers->pData =
            qaeMemAllocNUMA(buffSize, nodeId, BYTE_ALIGNMENT_64);
        if (NULL == (*pBuffListArray)->pBuffers->pData)
        {
            PRINT(" Unable to allocate Flat buffer\n");
            qaeMemFreeNUMA((void **)&(*pBuffListArray)->pPrivateMetaData);
            qaeMemFreeNUMA((void **)&(*pBuffListArray)->pBuffers);
            qaeMemFreeNUMA((void **)pBuffListArray);
            return CPA_STATUS_FAIL;
        }
        memset((*pBuffListArray)->pBuffers->pData, 0, buffSize);
    }

    return status;
}
EXPORT_SYMBOL(dcSampleCreateStatefulContextBuffer);

CpaStatus dcSampleFreeStatefulContextBuffer3(CpaBufferList *pBuffListArray)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (NULL == pBuffListArray)
    {
        PRINT_ERR(" Buffers List Array is NULL\n");
        /* Return Silent */
        return CPA_STATUS_FAIL;
    }

    if (NULL != pBuffListArray->pPrivateMetaData)
    {
        qaeMemFreeNUMA((void **)&pBuffListArray->pPrivateMetaData);
    }
    if (NULL != pBuffListArray->pBuffers)
    {
        if (NULL != pBuffListArray->pBuffers->pData)
        {
            qaeMemFreeNUMA((void **)&pBuffListArray->pBuffers->pData);
        }
        qaeMemFreeNUMA((void **)&pBuffListArray->pBuffers);
    }
    if (NULL != pBuffListArray)
    {
        qaeMemFreeNUMA((void **)&pBuffListArray);
    }

    return status;
}
void freeBuffers(CpaBufferList ***pBuffListArray,
                 Cpa32U numberOfFiles,
                 compression_test_params_t *setup)
{
    Cpa32U i = 0, j = 0;

    if (NULL == pBuffListArray)
    {
        /* Return Silent */
        return;
    }
    if (0 != numberOfFiles)
    {
        for (i = 0; i < numberOfFiles; i++)
        {
            for (j = 0; j < setup->numberOfBuffers[i]; j++)
            {
                if (NULL != pBuffListArray[i][j]->pBuffers->pData)
                {
                    qaeMemFreeNUMA(
                        (void **)&pBuffListArray[i][j]->pBuffers->pData);
                    if (NULL != pBuffListArray[i][j]->pBuffers->pData)
                    {
                        PRINT(
                            "Could not free bufferList[%d][%d]->pData\n", i, j);
                    }
                }
                if (NULL != pBuffListArray[i][j]->pPrivateMetaData)
                {
                    qaeMemFreeNUMA(
                        (void **)&pBuffListArray[i][j]->pPrivateMetaData);
                    if (NULL != pBuffListArray[i][j]->pPrivateMetaData)
                    {
                        PRINT("Could not free "
                              "bufferList[%d][%d]->pPrivateMetaData\n",
                              i,
                              j);
                    }
                }
                if (NULL != pBuffListArray[i][j]->pBuffers)
                {
                    qaeMemFree((void **)&pBuffListArray[i][j]->pBuffers);
                    if (NULL != pBuffListArray[i][j]->pBuffers)
                    {
                        PRINT("Could not free bufferList[%d][%d]->pBuffers\n",
                              i,
                              j);
                    }
                }
                if (NULL != pBuffListArray[i][j])
                {
                    qaeMemFree((void **)&pBuffListArray[i][j]);
                    if (NULL != pBuffListArray[i][j])
                    {
                        PRINT("Could not free bufferList[%d][%d]\n", i, j);
                    }
                }
            }
            if (NULL != pBuffListArray[i])
            {
                qaeMemFree((void **)&pBuffListArray[i]);
                if (NULL != pBuffListArray[i])
                {
                    PRINT("Could not free bufferList[%d]\n", i);
                }
            }
        }
    }
    qaeMemFree((void **)&pBuffListArray);
    if (NULL != pBuffListArray)
    {
        PRINT("Could not free bufferList\n");
    }
    return;
}

CpaStatus createBuffers(Cpa32U buffSize,
                        Cpa32U numBuffs,
                        CpaBufferList **pBuffListArray,
                        Cpa32U nodeId)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i = 0;

    for (i = 0; i < numBuffs; i++)
    {
        pBuffListArray[i] = qaeMemAlloc(sizeof(CpaBufferList));
        if (NULL == pBuffListArray[i])
        {
            PRINT_ERR("Unable to allocate pBuffListArray[%d]\n", i);
            return CPA_STATUS_FAIL;
        }
        pBuffListArray[i]->pBuffers = qaeMemAlloc(sizeof(CpaFlatBuffer));
        if (NULL == pBuffListArray[i]->pBuffers)
        {
            PRINT_ERR("Unable to allocate pBuffListArray[%d]->pBuffers\n", i);
            return CPA_STATUS_FAIL;
        }
        /* Allocate Flat buffer for each buffer List */
        pBuffListArray[i]->pBuffers->dataLenInBytes = buffSize;
        pBuffListArray[i]->pBuffers->pData =
            qaeMemAllocNUMA(buffSize, nodeId, BYTE_ALIGNMENT_64);

        if (NULL == pBuffListArray[i]->pBuffers->pData)
        {
            PRINT_ERR("Unable to allocate pBuffListArray[%d]->pBuffers.pData\n",
                      i);
            return CPA_STATUS_FAIL;
        }
        memset(pBuffListArray[i]->pBuffers->pData, 0, buffSize);
        pBuffListArray[i]->numBuffers = ONE_BUFFER_DC;
    }

    return status;
}
void freeResults(CpaDcRqResults ***ppDcResult,
                 Cpa32U numFiles,
                 compression_test_params_t *setup)
{
    Cpa32U i = 0, j = 0;

    if (NULL == ppDcResult)
    {
        /* Return Silent */
        return;
    }
    if (0 != numFiles)
    {
        for (i = 0; i < numFiles; i++)
        {
            for (j = 0; j < setup->numberOfBuffers[i]; j++)
            {
                if (NULL != ppDcResult[i][j])
                {
                    qaeMemFree((void **)&ppDcResult[i][j]);
                }
            }
            if (NULL != ppDcResult[i])
            {
                qaeMemFree((void **)&ppDcResult[i]);
            }
        }
    }
    qaeMemFree((void **)&ppDcResult);
}

void freeCbTags(dc_callbacktag_t ***callbackTag,
                Cpa32U numFiles,
                compression_test_params_t *setup)
{
    Cpa32U i = 0, j = 0;

    if (NULL == callbackTag)
    {
        /* Return Silent */
        return;
    }
    if (0 != numFiles)
    {
        for (i = 0; i < numFiles; i++)
        {

            for (j = 0; j < setup->numberOfBuffers[i]; j++)
            {
                if (NULL != callbackTag[i][j])
                {
                    qaeMemFreeNUMA((void **)&callbackTag[i][j]);
                }
            }
            if (NULL != callbackTag[i])
            {
                qaeMemFreeNUMA((void **)&callbackTag[i]);
            }
        }
    }
    qaeMemFreeNUMA((void **)&callbackTag);
}

CpaStatus sampleRemoveDcDpSession(CpaInstanceHandle dcInstance,
                                  CpaDcSessionHandle pSessionHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa16U retries = 0;
    Cpa32U delay = REMOVE_SESSION_WAIT;

    /*
     * We do a incremental sleep starting from 50 micro secs and
     * by incrementing the sleep time by twice the previous value
     * for each retry. Total sleep time would be 1.6 secs
     * for 15 number of retries which would be enough for all
     * in-flight requests to get processed.
     */
    do
    {
        status = cpaDcDpRemoveSession(dcInstance, pSessionHandle);
        delay *= 2;
        sleepNano(delay * 1000);
    } while ((CPA_STATUS_RETRY == status) &&
             (MAX_SESSION_REMOVE_RETRIES >= ++retries));

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Remove session failed with status %d\n", status);
        status = CPA_STATUS_FAIL;
    }

    return status;
}
EXPORT_SYMBOL(sampleRemoveDcDpSession);

CpaStatus getDcCapabilityStatusForAlg(CpaInstanceHandle dcInstance,
                                      Cpa32U capId,
                                      CpaDcCompType algorithm,
                                      CpaDcSessionDir direction,
                                      CpaBoolean *pCapStatus)

{
    CpaDcCapabilityReq capabilityReq = { 0 };
    CpaDcCapabilityResp capabilityResp = { 0 };
    CpaStatus status = CPA_STATUS_FAIL;

    capabilityReq.capId = capId;
    capabilityReq.algo = algorithm;
    capabilityReq.dir = direction;

    status =
        cpaDcQueryCapabilityByType(dcInstance, capabilityReq, &capabilityResp);

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to get dc capability status\n");
        return CPA_STATUS_FAIL;
    }

    if (NULL == pCapStatus)
    {
        PRINT_ERR("pCapStatus is NULL\n");
        status = CPA_STATUS_FAIL;
    }
    else
    {
        *pCapStatus = capabilityResp.boolStatus;
    }

    return status;
}
EXPORT_SYMBOL(getDcCapabilityStatusForAlg);

