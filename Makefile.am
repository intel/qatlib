################################################################
#   BSD LICENSE
# 
#   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
#   All rights reserved.
# 
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
# 
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Intel Corporation nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
# 
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
################################################################

ACLOCAL_AMFLAGS = -Im4

noinst_LTLIBRARIES = libosal.la
libosal_la_SOURCES = \
	quickassist/utilities/osal/src/linux/user_space/OsalSemaphore.c \
	quickassist/utilities/osal/src/linux/user_space/OsalThread.c \
	quickassist/utilities/osal/src/linux/user_space/OsalMutex.c \
	quickassist/utilities/osal/src/linux/user_space/OsalSpinLock.c \
	quickassist/utilities/osal/src/linux/user_space/OsalAtomic.c \
	quickassist/utilities/osal/src/linux/user_space/OsalServices.c \
	quickassist/utilities/osal/src/linux/user_space/OsalUsrKrnProxy.c \
	quickassist/utilities/osal/src/linux/user_space/OsalCryptoInterface.c

libosal_la_CFLAGS = -I$(srcdir)/quickassist/utilities/osal/src/linux/user_space \
		    -I$(srcdir)/quickassist/utilities/osal/src/linux/user_space/include \
		    -I$(srcdir)/quickassist/utilities/osal/include \
		    -DOSAL_ENSURE_ON -DUSE_OPENSSL \
		    -Wno-deprecated-declarations \
		    $(COMMON_FLAGS)

noinst_LTLIBRARIES += libadf.la
libadf_la_SOURCES = \
	quickassist/lookaside/access_layer/src/qat_direct/common/adf_process_proxy.c \
	quickassist/lookaside/access_layer/src/qat_direct/common/adf_user_cfg.c \
	quickassist/lookaside/access_layer/src/qat_direct/common/adf_user_device.c \
	quickassist/lookaside/access_layer/src/qat_direct/common/adf_user_dyn.c \
	quickassist/lookaside/access_layer/src/qat_direct/common/adf_user_ETring_mgr_dp.c \
	quickassist/lookaside/access_layer/src/qat_direct/common/adf_user_init.c \
	quickassist/lookaside/access_layer/src/qat_direct/common/adf_user_ring.c \
	quickassist/lookaside/access_layer/src/qat_direct/common/adf_user_transport_ctrl.c \
	quickassist/lookaside/access_layer/src/qat_direct/vfio/adf_vfio_cfg.c \
	quickassist/lookaside/access_layer/src/qat_direct/vfio/adf_vfio_ring.c \
	quickassist/lookaside/access_layer/src/qat_direct/vfio/adf_vfio_user_bundles.c \
	quickassist/lookaside/access_layer/src/qat_direct/vfio/adf_vfio_user_proxy.c \
	quickassist/lookaside/access_layer/src/qat_direct/vfio/qat_mgr_client.c \
	quickassist/lookaside/access_layer/src/qat_direct/vfio/qat_mgr_lib.c \
	quickassist/lookaside/access_layer/src/qat_direct/vfio/qat_log.c \
	quickassist/lookaside/access_layer/src/qat_direct/vfio/vfio_lib.c \
	quickassist/lookaside/access_layer/src/qat_direct/vfio/adf_pfvf_proto.c \
	quickassist/lookaside/access_layer/src/qat_direct/vfio/adf_pfvf_vf_msg.c
libadf_la_CFLAGS = -I$(srcdir)/quickassist/utilities/libusdm_drv \
		   -I$(srcdir)/quickassist/utilities/osal/include \
		   -I$(srcdir)/quickassist/utilities/osal/src/linux/user_space/include \
		   -I$(srcdir)/quickassist/include \
		   -I$(srcdir)/quickassist/include/lac \
		   -I$(srcdir)/quickassist/qat/drivers/crypto/qat/qat_common \
		   -I$(srcdir)/quickassist/lookaside/access_layer/src/common/include \
		   -I$(srcdir)/quickassist/lookaside/access_layer/include \
		   -I$(srcdir)/quickassist/lookaside/access_layer/src/qat_direct/include \
		   -I$(srcdir)/quickassist/lookaside/access_layer/src/qat_direct/common/include \
		   -I$(srcdir)/quickassist/lookaside/access_layer/src/qat_direct/vfio \
		   -D USER_SPACE \
		   $(COMMON_FLAGS)

sbin_PROGRAMS = qatmgr
qatmgr_SOURCES = \
	quickassist/utilities/qat_mgr/qat_mgr.c \
	quickassist/lookaside/access_layer/src/qat_direct/vfio/qat_mgr_lib.c \
	quickassist/lookaside/access_layer/src/qat_direct/vfio/qat_log.c \
	quickassist/lookaside/access_layer/src/qat_direct/vfio/adf_pfvf_proto.c \
	quickassist/lookaside/access_layer/src/qat_direct/vfio/adf_pfvf_vf_msg.c \
	quickassist/lookaside/access_layer/src/qat_direct/vfio/vfio_lib.c
qatmgr_CFLAGS = -I$(srcdir)/quickassist/lookaside/access_layer/src/qat_direct/vfio \
	        -I$(srcdir)/quickassist/lookaside/access_layer/include \
	        -I$(srcdir)/quickassist/include \
	        -I$(srcdir)/quickassist/utilities/osal/include \
	        -I$(srcdir)/quickassist/utilities/osal/src/linux/user_space/include \
	        -I$(srcdir)/quickassist/qat/drivers/crypto/qat/qat_common \
	        -I$(srcdir)/quickassist/lookaside/access_layer/src/qat_direct/include \
	        -I$(srcdir)/quickassist/lookaside/access_layer/src/qat_direct/common/include \
	        -D USER_SPACE \
	        $(COMMON_FLAGS)

qatmgr_LDADD = -lpthread

lib_LTLIBRARIES = lib@LIBUSDMNAME@.la
lib@LIBUSDMNAME@_la_SOURCES = \
	quickassist/utilities/libusdm_drv/user_space/vfio/qae_mem_utils_vfio.c \
	quickassist/utilities/libusdm_drv/user_space/qae_mem_utils_common.c \
	quickassist/utilities/libusdm_drv/user_space/vfio/qae_mem_hugepage_utils_vfio.c
lib@LIBUSDMNAME@_la_CFLAGS = -I$(srcdir)/quickassist/utilities/libusdm_drv \
			     -I$(srcdir)/quickassist/utilities/libusdm_drv/include \
			     -I$(srcdir)/quickassist/utilities/libusdm_drv/user_space \
			     $(COMMON_FLAGS)
lib@LIBUSDMNAME@_la_LDFLAGS = -version-info $(LIBUSDM_VERSION) \
			      $(COMMON_LDFLAGS) \
			      -export-symbols-regex '^(qae)'

if !USE_CCODE_CRC
# Creating CRC libs from asm files using nasm with automake-like output
libcrc_SOURCES_DIR = quickassist/lookaside/access_layer/src/common/compression/
%.lo:
	@echo "  CCAS     $(libcrc_SOURCES_DIR)$@"
	@$(LIBTOOL) --mode=compile --quiet \
	nasm -f elf64 -D LINUX -X gnu $(libcrc_SOURCES_DIR)$(@:.lo=.S) -I$(libcrc_SOURCES_DIR) -o $@ -prefer-non-pic
endif

lib_LTLIBRARIES += lib@LIBQATNAME@.la
lib@LIBQATNAME@_la_SOURCES = \
	quickassist/lookaside/access_layer/src/common/compression/dc_buffers.c \
	quickassist/lookaside/access_layer/src/common/compression/dc_chain.c \
	quickassist/lookaside/access_layer/src/common/compression/dc_datapath.c \
	quickassist/lookaside/access_layer/src/common/compression/dc_dp.c \
	quickassist/lookaside/access_layer/src/common/compression/dc_header_footer.c \
	quickassist/lookaside/access_layer/src/common/compression/dc_header_footer_lz4.c \
	quickassist/lookaside/access_layer/src/common/compression/dc_session.c \
	quickassist/lookaside/access_layer/src/common/compression/dc_stats.c \
	quickassist/lookaside/access_layer/src/common/compression/dc_err_sim.c \
	quickassist/lookaside/access_layer/src/common/compression/dc_ns_datapath.c \
	quickassist/lookaside/access_layer/src/common/compression/dc_ns_header_footer.c \
	quickassist/lookaside/access_layer/src/common/compression/dc_crc32.c \
	quickassist/lookaside/access_layer/src/common/compression/dc_crc64.c \
	quickassist/lookaside/access_layer/src/common/compression/dc_xxhash32.c \
	quickassist/lookaside/access_layer/src/common/compression/icp_sal_dc_err_sim.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/diffie_hellman/lac_dh_control_path.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/diffie_hellman/lac_dh_data_path.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/diffie_hellman/lac_dh_interface_check.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/diffie_hellman/lac_dh_stats.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/dsa/lac_dsa.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/dsa/lac_dsa_interface_check.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/ecc/lac_ec.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/ecc/lac_ec_common.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/ecc/lac_ec_montedwds.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/ecc/lac_ec_nist_curves.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/ecc/lac_ecdh.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/ecc/lac_ecdsa.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/ecc/lac_kpt_ecdsa.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/large_number/lac_ln.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/large_number/lac_ln_interface_check.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/pke_common/lac_pke_mmp.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/pke_common/lac_pke_qat_comms.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/pke_common/lac_pke_utils.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/prime/lac_prime.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/prime/lac_prime_interface_check.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/rsa/lac_rsa.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/rsa/lac_rsa_control_path.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/rsa/lac_rsa_decrypt.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/rsa/lac_rsa_encrypt.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/rsa/lac_rsa_interface_check.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/rsa/lac_rsa_keygen.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/rsa/lac_rsa_stats.c \
	quickassist/lookaside/access_layer/src/common/crypto/asym/rsa/lac_kpt_rsa_decrypt.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/drbg/lac_sym_drbg_api.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/key/lac_sym_key.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/lac_sym_alg_chain.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/lac_sym_api.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/lac_sym_auth_enc.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/lac_sym_cb.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/lac_sym_cipher.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/lac_sym_compile_check.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/lac_sym_dp.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/lac_sym_hash.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/lac_sym_partial.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/lac_sym_queue.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/lac_sym_stats.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/nrbg/lac_sym_nrbg_api.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/qat/lac_sym_qat.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/qat/lac_sym_qat_cipher.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/qat/lac_sym_qat_constants_table.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/qat/lac_sym_qat_hash.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/qat/lac_sym_qat_hash_defs_lookup.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/qat/lac_sym_qat_key.c \
	quickassist/lookaside/access_layer/src/common/crypto/sym/lac_sym_hash_sw_precomputes.c \
	quickassist/lookaside/access_layer/src/common/crypto/kpt/provision/lac_kpt_provision.c \
	quickassist/lookaside/access_layer/src/common/ctrl/sal_compression.c \
	quickassist/lookaside/access_layer/src/common/ctrl/sal_create_services.c \
	quickassist/lookaside/access_layer/src/common/ctrl/sal_ctrl_services.c \
	quickassist/lookaside/access_layer/src/common/ctrl/sal_list.c \
	quickassist/lookaside/access_layer/src/common/ctrl/sal_crypto.c \
	quickassist/lookaside/access_layer/src/common/ctrl/sal_dc_chain.c \
	quickassist/lookaside/access_layer/src/common/ctrl/sal_instances.c \
	quickassist/lookaside/access_layer/src/common/qat_comms/sal_qat_cmn_msg.c \
	quickassist/lookaside/access_layer/src/common/utils/lac_buffer_desc.c \
	quickassist/lookaside/access_layer/src/common/utils/lac_log_message.c \
	quickassist/lookaside/access_layer/src/common/utils/lac_mem.c \
	quickassist/lookaside/access_layer/src/common/utils/lac_mem_pools.c \
	quickassist/lookaside/access_layer/src/common/utils/lac_sw_responses.c \
	quickassist/lookaside/access_layer/src/common/utils/lac_sync.c \
	quickassist/lookaside/access_layer/src/common/utils/sal_service_state.c \
	quickassist/lookaside/access_layer/src/common/utils/sal_statistics.c \
	quickassist/lookaside/access_layer/src/common/utils/sal_misc_error_stats.c \
	quickassist/lookaside/access_layer/src/common/utils/sal_string_parse.c \
	quickassist/lookaside/access_layer/src/common/utils/sal_user_process.c \
	quickassist/lookaside/access_layer/src/common/utils/sal_versions.c \
	quickassist/lookaside/access_layer/src/common/device/sal_dev_info.c \
	quickassist/lookaside/access_layer/src/user/sal_user.c \
	quickassist/lookaside/access_layer/src/user/sal_user_dyn_instance.c
if USE_CCODE_CRC
lib@LIBQATNAME@_la_SOURCES += \
	quickassist/lookaside/access_layer/src/common/compression/dc_crc_base.c
endif
lib@LIBQATNAME@_la_CFLAGS = -I$(srcdir)/quickassist/utilities/libusdm_drv \
			    -I$(srcdir)/quickassist/utilities/osal/include \
			    -I$(srcdir)/quickassist/utilities/osal/src/linux/user_space/include \
			    -I$(srcdir)/quickassist/include \
			    -I$(srcdir)/quickassist/include/lac \
			    -I$(srcdir)/quickassist/include/dc \
			    -I$(srcdir)/quickassist/qat/drivers/crypto/qat/qat_common \
			    -I$(srcdir)/quickassist/lookaside/access_layer/src/common/compression/include \
			    -I$(srcdir)/quickassist/lookaside/access_layer/src/common/crypto/sym/include \
			    -I$(srcdir)/quickassist/lookaside/access_layer/src/common/crypto/asym/include \
			    -I$(srcdir)/quickassist/lookaside/firmware/include \
			    -I$(srcdir)/quickassist/lookaside/access_layer/src/common/include \
			    -I$(srcdir)/quickassist/lookaside/access_layer/include \
			    -I$(srcdir)/quickassist/lookaside/access_layer/src/qat_direct/include \
			    -I$(srcdir)/quickassist/lookaside/access_layer/src/qat_direct/common/include \
			    -I$(srcdir)/quickassist/lookaside/access_layer/src/qat_direct/vfio \
			    -D USER_SPACE \
			    -D LAC_BYTE_ORDER=__LITTLE_ENDIAN \
			    $(COMMON_FLAGS)
lib@LIBQATNAME@_la_LIBADD = libosal.la libadf.la lib@LIBUSDMNAME@.la -lcrypto
if !USE_CCODE_CRC
lib@LIBQATNAME@_la_LIBADD += crc32_gzip_refl_by8.lo crc64_ecma_norm_by8.lo
endif
lib@LIBQATNAME@_la_LDFLAGS = -version-info $(LIBQAT_VERSION) \
			     $(COMMON_LDFLAGS) \
			     -export-symbols-regex '^(cpa|icp_sal)'

pkgincludedir = $(includedir)/qat
pkginclude_HEADERS = \
	quickassist/include/cpa.h \
	quickassist/include/cpa_dev.h \
	quickassist/include/cpa_types.h \
	quickassist/include/lac/cpa_cy_common.h \
	quickassist/include/lac/cpa_cy_dh.h \
	quickassist/include/lac/cpa_cy_drbg.h \
	quickassist/include/lac/cpa_cy_dsa.h \
	quickassist/include/lac/cpa_cy_ecdh.h \
	quickassist/include/lac/cpa_cy_ecdsa.h \
	quickassist/include/lac/cpa_cy_ec.h \
	quickassist/include/lac/cpa_cy_im.h \
	quickassist/include/lac/cpa_cy_key.h \
	quickassist/include/lac/cpa_cy_kpt.h \
	quickassist/include/lac/cpa_cy_ln.h \
	quickassist/include/lac/cpa_cy_nrbg.h \
	quickassist/include/lac/cpa_cy_prime.h \
	quickassist/include/lac/cpa_cy_rsa.h \
	quickassist/include/lac/cpa_cy_sym_dp.h \
	quickassist/include/lac/cpa_cy_sym.h \
	quickassist/include/dc/cpa_dc.h \
	quickassist/include/dc/cpa_dc_dp.h \
	quickassist/include/dc/cpa_dc_chain.h \
	quickassist/lookaside/access_layer/include/icp_sal_congestion_mgmt.h \
	quickassist/lookaside/access_layer/include/icp_sal_poll.h \
	quickassist/lookaside/access_layer/include/icp_sal_user.h \
	quickassist/lookaside/access_layer/include/icp_sal.h \
	quickassist/lookaside/access_layer/include/icp_sal_versions.h \
	quickassist/utilities/libusdm_drv/qae_mem.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = qatlib.pc libqat.pc libusdm.pc

if HAVE_SYSTEMD
systemdsystemunit_DATA = quickassist/utilities/service/qat.service
endif

systemd_scriptsdir = $(prefix)/sbin
dist_systemd_scripts_SCRIPTS = quickassist/utilities/service/qat_init.sh

install-data-hook:
if SERVICE_AC
	@if [ "$(shell id -u)" == 0 ]; then \
		/usr/sbin/groupadd qat 2> /dev/null || :; \
		systemctl daemon-reload; \
		systemctl start qat; \
		systemctl enable qat; \
	fi
endif

uninstall-hook:
if SERVICE_AC
	@if [ "$(shell id -u)" == 0 ]; then \
		systemctl daemon-reload; \
		pidof qatmgr > /dev/null && kill `pidof qatmgr`; \
		rm -rf /run/qat; \
		systemctl disable qat; \
	fi
endif

dist_man_MANS = qat_init.sh.8 qatmgr.8

EXTRA_DIST = LICENSE \
	autogen.sh \
	quickassist/lookaside/firmware/include \
	quickassist/include \
	quickassist/lookaside/access_layer/src/common \
	quickassist/lookaside/access_layer/include \
	quickassist/lookaside/access_layer/src/qat_direct \
	quickassist/utilities/osal \
	quickassist/utilities/libusdm_drv/include \
	quickassist/utilities/libusdm_drv/user_space \
	quickassist/lookaside/access_layer/src/sample_code

DISTCHECK_CONFIGURE_FLAGS = \
        --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

######################
#  Build parameters  #
######################

COMMON_LDFLAGS = -pie -z relro -z now -z noexecstack
AM_LDFLAGS = $(COMMON_LDFLAGS)

COMMON_FLAGS = -Wformat \
	       -Wformat-security \
	       -Werror=format-security \
	       -D_FORTIFY_SOURCE=2 \
	       -fstack-protector-strong \
	       -fPIE \
	       -fPIC \
	       -fno-strict-overflow \
	       -fno-delete-null-pointer-checks \
	       -fwrapv \
	       -D MAX_MR_ROUND=$(MAX_MR) \
	       -D _FILE_OFFSET_BITS=64 \
	       $(NO_UNUSED_CMDLINE_ARG_CFLAGS) \
	       $(MCX16_CFLAGS)

if ICP_DEBUG_AC
ICP_DEBUG = 1
COMMON_FLAGS += -DICP_DEBUG
endif

if ICP_PARAM_CHECK_AC
ICP_PARAM_CHECK = y
COMMON_FLAGS += -DICP_PARAM_CHECK
endif

if DISABLE_STATS_AC
DISABLE_STATS = 1
COMMON_FLAGS += -DDISABLE_STATS
endif

if ICP_LOG_SYSLOG_AC
ICP_LOG_SYSLOG = 1
COMMON_FLAGS += -DICP_LOG_SYSLOG
endif

if ICP_TRACE_AC
ICP_TRACE = 1
COMMON_FLAGS += -DICP_TRACE
endif

if ICP_DC_ERROR_SIMULATION_AC
ICP_DC_ERROR_SIMULATION = 1
COMMON_FLAGS += -DICP_DC_ERROR_SIMULATION
endif


if USE_CCODE_CRC
COMMON_FLAGS += -DUSE_CCODE_CRC
endif

if QAT_LEGACY_ALGORITHMS_AC
QAT_LEGACY_ALGORITHMS = y
COMMON_FLAGS += -DQAT_LEGACY_ALGORITHMS
else
QAT_LEGACY_ALGORITHMS = n
endif

include Samples.am

########################
# RPM package building #
########################

rpm: clean dist qatlib.spec
	@mkdir -p rpmbuild/BUILD rpmbuild/RPMS rpmbuild/SOURCES rpmbuild/SPECS rpmbuild/SRPMS
	@cp $(PACKAGE)-$(VERSION).tar.gz rpmbuild/SOURCES/
	@cp qatlib.spec rpmbuild/SPECS/
	@rpmbuild --define "_topdir $(abs_srcdir)/rpmbuild" -ba rpmbuild/SPECS/qatlib.spec

rpmclean:
	@rm -fr rpmbuild

.PHONY: rpm rpmclean
