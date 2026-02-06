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
 * @file qat_library_version.h
 *
 * @defgroup QatLibVersion
 *
 * @ingroup QatLibVersion
 *
 * Definition of the software library version. This header file should not be
 * included directly in an application, instead the icp_sal_getDevVersionInfo
 * API should be used to query the version.
 *
 ***************************************************************************/

#ifndef _QAT_LIBRARY_VERSION_H_
#define _QAT_LIBRARY_VERSION_H_

#ifdef __cplusplus
extern "C" {
#endif

#define QAT_LIBRARY_VERSION_MAJOR 26
#define QAT_LIBRARY_VERSION_MINOR 2
#define QAT_LIBRARY_VERSION_PATCH 0

#ifdef __cplusplus
} /* close the extern "C" { */
#endif

#endif /* _QAT_LIBRARY_VERSION_H_ */
