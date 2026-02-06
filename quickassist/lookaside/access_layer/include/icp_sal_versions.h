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
 ***************************************************************************
 * @file icp_sal_versions.h
 *
 * @defgroup SalVersions
 *
 * @ingroup SalVersions
 *
 * API and structures definition for obtaining software and hardware versions
 *
 ***************************************************************************/

#ifndef _ICP_SAL_VERSIONS_H_
#define _ICP_SAL_VERSIONS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <qat_library_version.h>

/**
 *****************************************************************************
 * ICP API version history
 *  v1.0: Base version
 *  v1.1: addition of icp_sal_get_num_pfs() and icp_sal_get_num_pfs()
 *****************************************************************************/

/**
 *****************************************************************************
 * @ingroup SalVersions
 *      ICP Major Version Number
 * 
 * @description
 *      The ICP API major version number. This number will be incremented
 *      when significant changes to the API have occurred. The combination of the
 *      major and minor number definitions represents the complete version number
 *      for this interface.
 *
 *****************************************************************************/
#define ICP_API_VERSION_NUM_MAJOR (1)

/**
 *****************************************************************************
 * @ingroup SalVersions
 *       ICP Minor Version Number
 * 
 * @description
 *      The ICP API minor version number. This number will be incremented
 *      when minor changes to the API have occurred. The combination of the major
 *      and minor number definitions represents the complete version number for
 *      this interface.
 *
 *****************************************************************************/
#define ICP_API_VERSION_NUM_MINOR (1)

/**< Check for ICP API version (at least) */
#define ICP_API_VERSION_AT_LEAST(major, minor)                                 \
    (ICP_API_VERSION_NUM_MAJOR > major ||                                      \
     (ICP_API_VERSION_NUM_MAJOR == major &&                                    \
      ICP_API_VERSION_NUM_MINOR >= minor))

/**< Check for ICP API version (less than) */
#define ICP_API_VERSION_LESS_THAN(major, minor)                                \
    (ICP_API_VERSION_NUM_MAJOR < major ||                                      \
     (ICP_API_VERSION_NUM_MAJOR == major &&                                    \
      ICP_API_VERSION_NUM_MINOR < minor))

/**
*******************************************************************************
* SAL software, firmware and hardware versions
*****************************************************************************/

#define ICP_SAL_VERSIONS_FW_VERSION_SIZE 16
/**< Max length of firmware version string */
#define ICP_SAL_VERSIONS_SW_VERSION_SIZE 16
/**< Max length of software version string */
#define ICP_SAL_VERSIONS_MMP_VERSION_SIZE 16
/**< Max length of MMP binary version string */
#define ICP_SAL_VERSIONS_HW_VERSION_SIZE 4
/**< Max length of hardware version string */

#define VERSION_STRING(ver) #ver

#define VERSION_CONCAT(ver, ...) VERSION_STRING(ver) #__VA_ARGS__

#define QAT_SW_VERSION(s1, s2, s3, s4) s1 s2 s3 s4

static const char *__attribute__((used)) qat_sw_version =
    QAT_SW_VERSION(VERSION_CONCAT(QAT_SOFTWARE_VERSION, =),
                   VERSION_CONCAT(QAT_LIBRARY_VERSION_MAJOR, .),
                   VERSION_CONCAT(QAT_LIBRARY_VERSION_MINOR, .),
                   VERSION_CONCAT(QAT_LIBRARY_VERSION_PATCH));

/**
*******************************************************************************
* @ingroup SalVersions
*      Structure holding versions information
*
* @description
*      This structure stores information about versions of software
*      and hardware being run on a particular device.
*****************************************************************************/
typedef struct icp_sal_dev_version_info_s
{
    Cpa32U devId;
    /**< Number of acceleration device for which this structure holds version
     * information */
    Cpa8U firmwareVersion[ICP_SAL_VERSIONS_FW_VERSION_SIZE];
    /**< String identifying the version of the firmware associated with
     * the device. */
    Cpa8U mmpVersion[ICP_SAL_VERSIONS_MMP_VERSION_SIZE];
    /**< String identifying the version of the MMP binary associated with
     * the device. */
    Cpa8U softwareVersion[ICP_SAL_VERSIONS_SW_VERSION_SIZE];
    /**< String identifying the version of the software associated with
     * the device. */
    Cpa8U hardwareVersion[ICP_SAL_VERSIONS_HW_VERSION_SIZE];
    /**< String identifying the version of the hardware (stepping and
     * revision ID) associated with the device. */
} icp_sal_dev_version_info_t;

/**
*******************************************************************************
* @ingroup SalVersions
*      Obtains the version information for a given device
* @description
*      This function obtains hardware and software version information
*      associated with a given device.
*
* @param[in]   accelId     ID of the acceleration device for which version
*                          information is to be obtained.
* @param[out]  pVerInfo    Pointer to a structure that will hold version
*                          information
*
* @context
*      This function might sleep. It cannot be executed in a context that
*      does not permit sleeping.
* @assumptions
*      The system has been started
* @sideEffects
*      None
* @blocking
*      No
* @reentrant
*      No
* @threadSafe
*      Yes
*
* @return CPA_STATUS_SUCCESS       Operation finished successfully
* @return CPA_STATUS_INVALID_PARAM Invalid parameter passed to the function
* @return CPA_STATUS_RESOURCE      System resources problem
* @return CPA_STATUS_FAIL          Operation failed
*
*****************************************************************************/
CpaStatus icp_sal_getDevVersionInfo(Cpa32U accelId,
                                    icp_sal_dev_version_info_t *pVerInfo);

#ifdef __cplusplus
} /* close the extern "C" { */
#endif

#endif
