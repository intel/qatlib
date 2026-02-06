/****************************************************************************
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
 * @file dc_ns_datapath.h
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Definition of the Data Compression datapath parameters.
 *
 ****************************************************************************/
#ifndef DC_NS_DATAPATH_H
#define DC_NS_DATAPATH_H

/* No-Session [NS] operations can come into the lib on the following APIs:
 * - Traditional API [Trad] : cpaDcNsXxx APIs
 * - Data-plane API [DP]    : cpaDcDpEnqueueXxx with
 *  	                      CpaDcDpOpData->pSetupData populated and
 *  	                      pSessionHandle = NULL 
 * The response from the firmware needs to be handled differently
 * depending on whether the request came in the DP or Trad path.
 *
 * As the pSessionHandle field in the internal cookie is superfluous for
 * NS operations, that field is overloaded to convey DP/Trad information.
 * This field is set when the request is set up and examined during the
 * response handling.
 */
#define DCNS 1
#define DCDPNS 0

void dcNsCompression_ProcessCallback(void *pRespMsg);

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Construct compression base request
 *
 * @description
 *      This function will construct a compression base request, i.e. a request
 *      that serves as the base for a Traditional API request or a Data Plane
 *      API request. The function is the NS API equivalent of dcInitSession.
 *
 * @param[out]      pMsg             Pointer to empty message
 * @param[in]       pService         Pointer to compression service
 * @param[in]       pSetupData       Pointer to (de)compression parameters
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_UNSUPPORTED    Unsupported algorithm/feature
 *****************************************************************************/

CpaStatus dcNsCreateBaseRequest(icp_qat_fw_comp_req_t *pMsg,
                                sal_compression_service_t *pService,
                                CpaDcNsSetupData *pSetupData);

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Set the cnvErrorInjection flag in sal compression service request
 *
 * @description
 *      This function enables/disable the CnVError injection for the No-Session
 *      case. All Compression requests sent are injected with CnV errors.
 *
 * @param[in]       dcInstance       Instance Handle
 * @param[in]       enableCnvErrInj  TRUE/FALSE to Enable/Disable CnV Error
 *                                   Injection
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 * @retval CPA_STATUS_UNSUPPORTED    Unsupported feature
 *****************************************************************************/
CpaStatus dcNsSetCnvErrorInj(CpaInstanceHandle dcInstance,
                             CpaBoolean enableCnvErrInj);

#endif /* DC_NS_DATAPATH_H */
