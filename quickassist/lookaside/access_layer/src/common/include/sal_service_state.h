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
 * @file sal_service_state.h
 *
 * @defgroup SalServiceState
 *
 * @ingroup SalCtrl
 *
 * Checks state for generic service instance
 *
 ***************************************************************************/

#ifndef SAL_SERVICE_STATE_H_
#define SAL_SERVICE_STATE_H_

/**
*******************************************************************************
* @ingroup SalServiceState
*      Check to see if the instance is in the running state
*
* @description
*      This function checks the state of an instance to see if it is in the
*      running state
*
* @param[in]  instance   Instance handle (assumes this is valid, i.e. checked
*                        before this function is called)
* @retval CPA_TRUE       Instance in the RUNNING state
* @retval CPA_FALSE      Instance not in RUNNING state
*
*****************************************************************************/
CpaBoolean Sal_ServiceIsRunning(CpaInstanceHandle instanceHandle);

/**
*******************************************************************************
* @ingroup SalServiceState
*      Check to see if the instance is beign restarted
*
* @description
*      This function checks the state of an instance to see if the device it
*      uses is being restarted because of hardware error.
*
* @param[in]  instance   Instance handle (assumes this is valid, i.e. checked
*                        before this function is called)
* @retval CPA_TRUE       Device the instance is using is restarting.
* @retval CPA_FALSE      Device the instance is running.
*
*****************************************************************************/
CpaBoolean Sal_ServiceIsRestarting(CpaInstanceHandle instanceHandle);

/**
*******************************************************************************
* @ingroup SalServiceState
*      Check to see if the instance is in error state
*
* @description
*      This function checks the state of an instance to see if the device it
*      uses is in an error state due to a hardware error
*
* @param[in]  instance   Instance handle (assumes this is valid, i.e. checked
*                        before this function is called)
* @retval CPA_TRUE       Device the instance is using is in error state.
* @retval CPA_FALSE      Device the instance is not in error state.
*
*****************************************************************************/
CpaBoolean Sal_ServiceIsInError(CpaInstanceHandle instanceHandle);

/**
 *******************************************************************************
 * @ingroup SalServiceState
 *      This macro checks if an instance is running. An error message is logged
 *      if it is not in a running state.
 *
 * @return CPA_STATUS_FAIL Instance not in RUNNING state.
 * @return void            Instance is in RUNNING state.
 ******************************************************************************/
#define SAL_RUNNING_CHECK(instanceHandle)                                      \
    do                                                                         \
    {                                                                          \
        if (unlikely(CPA_TRUE != Sal_ServiceIsRunning(instanceHandle)))        \
        {                                                                      \
            if (CPA_TRUE == Sal_ServiceIsRestarting(instanceHandle))           \
            {                                                                  \
                return CPA_STATUS_RESTARTING;                                  \
            }                                                                  \
            LAC_LOG_ERROR("Instance not in a Running state");                  \
            return CPA_STATUS_FAIL;                                            \
        }                                                                      \
    } while (0)

/**
 *******************************************************************************
 * @ingroup SalServiceState
 *      This macro checks if an instance is in a state to get init event.
 *
 * @return CPA_STATUS_FAIL Instance not in good state.
 * @return void            Instance is in good state.
 ******************************************************************************/
#define SAL_SERVICE_GOOD_FOR_INIT(instanceHandle)                              \
    do                                                                         \
    {                                                                          \
        sal_service_t *pService = (sal_service_t *)instanceHandle;             \
        if ((SAL_SERVICE_STATE_UNINITIALIZED != pService->state) &&            \
            (SAL_SERVICE_STATE_RESTARTING != pService->state))                 \
        {                                                                      \
            LAC_LOG_ERROR("Not in the correct state to call init\n");          \
            return CPA_STATUS_FAIL;                                            \
        }                                                                      \
    } while (0)

/**
 *******************************************************************************
 * @ingroup SalServiceState
 *      This macro checks if an instance is in a state to get restarted event.
 *
 * @return CPA_STATUS_FAIL Instance not in good state.
 * @return void            Instance is in good state.
 ******************************************************************************/
#define SAL_SERVICE_GOOD_FOR_RESTARTED(instanceHandle)                         \
    do                                                                         \
    {                                                                          \
        sal_service_t *pService = (sal_service_t *)instanceHandle;             \
        if ((SAL_SERVICE_STATE_UNINITIALIZED != pService->state) &&            \
            (SAL_SERVICE_STATE_RESTARTING != pService->state))                 \
        {                                                                      \
            LAC_LOG_ERROR("Not in the correct state to call restarted\n");     \
            return CPA_STATUS_FAIL;                                            \
        }                                                                      \
    } while (0)

#endif /* SAL_SERVICE_STATE_H_ */
