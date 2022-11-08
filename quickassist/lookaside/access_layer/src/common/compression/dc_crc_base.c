/**********************************************************************
  Copyright(c) 2011-2022 Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

/**
 *****************************************************************************
 * @file dc_crc_base.c
 *
 * @defgroup Dc_DataCompression DC Data Compression
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Implementation of the CRC-32 and CRC-64 operations in C.
 *      Implementation derived from ISA-L 
 *      ISA-L : Intel(R) Intelligent Storage Acceleration Library
 *
 *****************************************************************************/

#include <stdint.h>

static const uint32_t crc32_table_gzip_refl[256] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
	0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
	0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
	0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
	0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
	0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
	0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
	0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
	0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
	0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
	0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
	0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
	0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
	0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
	0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
	0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
	0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
	0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
	0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
	0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
	0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
	0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
	0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
	0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
	0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
	0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
	0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
	0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
	0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
	0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
	0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
	0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
	0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
	0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
	0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
	0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
	0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
	0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

static const uint64_t crc64_ecma_norm_table[256] = {
	0x0000000000000000ULL, 0x42f0e1eba9ea3693ULL,
	0x85e1c3d753d46d26ULL, 0xc711223cfa3e5bb5ULL,
	0x493366450e42ecdfULL, 0x0bc387aea7a8da4cULL,
	0xccd2a5925d9681f9ULL, 0x8e224479f47cb76aULL,
	0x9266cc8a1c85d9beULL, 0xd0962d61b56fef2dULL,
	0x17870f5d4f51b498ULL, 0x5577eeb6e6bb820bULL,
	0xdb55aacf12c73561ULL, 0x99a54b24bb2d03f2ULL,
	0x5eb4691841135847ULL, 0x1c4488f3e8f96ed4ULL,
	0x663d78ff90e185efULL, 0x24cd9914390bb37cULL,
	0xe3dcbb28c335e8c9ULL, 0xa12c5ac36adfde5aULL,
	0x2f0e1eba9ea36930ULL, 0x6dfeff5137495fa3ULL,
	0xaaefdd6dcd770416ULL, 0xe81f3c86649d3285ULL,
	0xf45bb4758c645c51ULL, 0xb6ab559e258e6ac2ULL,
	0x71ba77a2dfb03177ULL, 0x334a9649765a07e4ULL,
	0xbd68d2308226b08eULL, 0xff9833db2bcc861dULL,
	0x388911e7d1f2dda8ULL, 0x7a79f00c7818eb3bULL,
	0xcc7af1ff21c30bdeULL, 0x8e8a101488293d4dULL,
	0x499b3228721766f8ULL, 0x0b6bd3c3dbfd506bULL,
	0x854997ba2f81e701ULL, 0xc7b97651866bd192ULL,
	0x00a8546d7c558a27ULL, 0x4258b586d5bfbcb4ULL,
	0x5e1c3d753d46d260ULL, 0x1cecdc9e94ace4f3ULL,
	0xdbfdfea26e92bf46ULL, 0x990d1f49c77889d5ULL,
	0x172f5b3033043ebfULL, 0x55dfbadb9aee082cULL,
	0x92ce98e760d05399ULL, 0xd03e790cc93a650aULL,
	0xaa478900b1228e31ULL, 0xe8b768eb18c8b8a2ULL,
	0x2fa64ad7e2f6e317ULL, 0x6d56ab3c4b1cd584ULL,
	0xe374ef45bf6062eeULL, 0xa1840eae168a547dULL,
	0x66952c92ecb40fc8ULL, 0x2465cd79455e395bULL,
	0x3821458aada7578fULL, 0x7ad1a461044d611cULL,
	0xbdc0865dfe733aa9ULL, 0xff3067b657990c3aULL,
	0x711223cfa3e5bb50ULL, 0x33e2c2240a0f8dc3ULL,
	0xf4f3e018f031d676ULL, 0xb60301f359dbe0e5ULL,
	0xda050215ea6c212fULL, 0x98f5e3fe438617bcULL,
	0x5fe4c1c2b9b84c09ULL, 0x1d14202910527a9aULL,
	0x93366450e42ecdf0ULL, 0xd1c685bb4dc4fb63ULL,
	0x16d7a787b7faa0d6ULL, 0x5427466c1e109645ULL,
	0x4863ce9ff6e9f891ULL, 0x0a932f745f03ce02ULL,
	0xcd820d48a53d95b7ULL, 0x8f72eca30cd7a324ULL,
	0x0150a8daf8ab144eULL, 0x43a04931514122ddULL,
	0x84b16b0dab7f7968ULL, 0xc6418ae602954ffbULL,
	0xbc387aea7a8da4c0ULL, 0xfec89b01d3679253ULL,
	0x39d9b93d2959c9e6ULL, 0x7b2958d680b3ff75ULL,
	0xf50b1caf74cf481fULL, 0xb7fbfd44dd257e8cULL,
	0x70eadf78271b2539ULL, 0x321a3e938ef113aaULL,
	0x2e5eb66066087d7eULL, 0x6cae578bcfe24bedULL,
	0xabbf75b735dc1058ULL, 0xe94f945c9c3626cbULL,
	0x676dd025684a91a1ULL, 0x259d31cec1a0a732ULL,
	0xe28c13f23b9efc87ULL, 0xa07cf2199274ca14ULL,
	0x167ff3eacbaf2af1ULL, 0x548f120162451c62ULL,
	0x939e303d987b47d7ULL, 0xd16ed1d631917144ULL,
	0x5f4c95afc5edc62eULL, 0x1dbc74446c07f0bdULL,
	0xdaad56789639ab08ULL, 0x985db7933fd39d9bULL,
	0x84193f60d72af34fULL, 0xc6e9de8b7ec0c5dcULL,
	0x01f8fcb784fe9e69ULL, 0x43081d5c2d14a8faULL,
	0xcd2a5925d9681f90ULL, 0x8fdab8ce70822903ULL,
	0x48cb9af28abc72b6ULL, 0x0a3b7b1923564425ULL,
	0x70428b155b4eaf1eULL, 0x32b26afef2a4998dULL,
	0xf5a348c2089ac238ULL, 0xb753a929a170f4abULL,
	0x3971ed50550c43c1ULL, 0x7b810cbbfce67552ULL,
	0xbc902e8706d82ee7ULL, 0xfe60cf6caf321874ULL,
	0xe224479f47cb76a0ULL, 0xa0d4a674ee214033ULL,
	0x67c58448141f1b86ULL, 0x253565a3bdf52d15ULL,
	0xab1721da49899a7fULL, 0xe9e7c031e063acecULL,
	0x2ef6e20d1a5df759ULL, 0x6c0603e6b3b7c1caULL,
	0xf6fae5c07d3274cdULL, 0xb40a042bd4d8425eULL,
	0x731b26172ee619ebULL, 0x31ebc7fc870c2f78ULL,
	0xbfc9838573709812ULL, 0xfd39626eda9aae81ULL,
	0x3a28405220a4f534ULL, 0x78d8a1b9894ec3a7ULL,
	0x649c294a61b7ad73ULL, 0x266cc8a1c85d9be0ULL,
	0xe17dea9d3263c055ULL, 0xa38d0b769b89f6c6ULL,
	0x2daf4f0f6ff541acULL, 0x6f5faee4c61f773fULL,
	0xa84e8cd83c212c8aULL, 0xeabe6d3395cb1a19ULL,
	0x90c79d3fedd3f122ULL, 0xd2377cd44439c7b1ULL,
	0x15265ee8be079c04ULL, 0x57d6bf0317edaa97ULL,
	0xd9f4fb7ae3911dfdULL, 0x9b041a914a7b2b6eULL,
	0x5c1538adb04570dbULL, 0x1ee5d94619af4648ULL,
	0x02a151b5f156289cULL, 0x4051b05e58bc1e0fULL,
	0x87409262a28245baULL, 0xc5b073890b687329ULL,
	0x4b9237f0ff14c443ULL, 0x0962d61b56fef2d0ULL,
	0xce73f427acc0a965ULL, 0x8c8315cc052a9ff6ULL,
	0x3a80143f5cf17f13ULL, 0x7870f5d4f51b4980ULL,
	0xbf61d7e80f251235ULL, 0xfd913603a6cf24a6ULL,
	0x73b3727a52b393ccULL, 0x31439391fb59a55fULL,
	0xf652b1ad0167feeaULL, 0xb4a25046a88dc879ULL,
	0xa8e6d8b54074a6adULL, 0xea16395ee99e903eULL,
	0x2d071b6213a0cb8bULL, 0x6ff7fa89ba4afd18ULL,
	0xe1d5bef04e364a72ULL, 0xa3255f1be7dc7ce1ULL,
	0x64347d271de22754ULL, 0x26c49cccb40811c7ULL,
	0x5cbd6cc0cc10fafcULL, 0x1e4d8d2b65facc6fULL,
	0xd95caf179fc497daULL, 0x9bac4efc362ea149ULL,
	0x158e0a85c2521623ULL, 0x577eeb6e6bb820b0ULL,
	0x906fc95291867b05ULL, 0xd29f28b9386c4d96ULL,
	0xcedba04ad0952342ULL, 0x8c2b41a1797f15d1ULL,
	0x4b3a639d83414e64ULL, 0x09ca82762aab78f7ULL,
	0x87e8c60fded7cf9dULL, 0xc51827e4773df90eULL,
	0x020905d88d03a2bbULL, 0x40f9e43324e99428ULL,
	0x2cffe7d5975e55e2ULL, 0x6e0f063e3eb46371ULL,
	0xa91e2402c48a38c4ULL, 0xebeec5e96d600e57ULL,
	0x65cc8190991cb93dULL, 0x273c607b30f68faeULL,
	0xe02d4247cac8d41bULL, 0xa2dda3ac6322e288ULL,
	0xbe992b5f8bdb8c5cULL, 0xfc69cab42231bacfULL,
	0x3b78e888d80fe17aULL, 0x7988096371e5d7e9ULL,
	0xf7aa4d1a85996083ULL, 0xb55aacf12c735610ULL,
	0x724b8ecdd64d0da5ULL, 0x30bb6f267fa73b36ULL,
	0x4ac29f2a07bfd00dULL, 0x08327ec1ae55e69eULL,
	0xcf235cfd546bbd2bULL, 0x8dd3bd16fd818bb8ULL,
	0x03f1f96f09fd3cd2ULL, 0x41011884a0170a41ULL,
	0x86103ab85a2951f4ULL, 0xc4e0db53f3c36767ULL,
	0xd8a453a01b3a09b3ULL, 0x9a54b24bb2d03f20ULL,
	0x5d45907748ee6495ULL, 0x1fb5719ce1045206ULL,
	0x919735e51578e56cULL, 0xd367d40ebc92d3ffULL,
	0x1476f63246ac884aULL, 0x568617d9ef46bed9ULL,
	0xe085162ab69d5e3cULL, 0xa275f7c11f7768afULL,
	0x6564d5fde549331aULL, 0x279434164ca30589ULL,
	0xa9b6706fb8dfb2e3ULL, 0xeb46918411358470ULL,
	0x2c57b3b8eb0bdfc5ULL, 0x6ea7525342e1e956ULL,
	0x72e3daa0aa188782ULL, 0x30133b4b03f2b111ULL,
	0xf7021977f9cceaa4ULL, 0xb5f2f89c5026dc37ULL,
	0x3bd0bce5a45a6b5dULL, 0x79205d0e0db05dceULL,
	0xbe317f32f78e067bULL, 0xfcc19ed95e6430e8ULL,
	0x86b86ed5267cdbd3ULL, 0xc4488f3e8f96ed40ULL,
	0x0359ad0275a8b6f5ULL, 0x41a94ce9dc428066ULL,
	0xcf8b0890283e370cULL, 0x8d7be97b81d4019fULL,
	0x4a6acb477bea5a2aULL, 0x089a2aacd2006cb9ULL,
	0x14dea25f3af9026dULL, 0x562e43b4931334feULL,
	0x913f6188692d6f4bULL, 0xd3cf8063c0c759d8ULL,
	0x5dedc41a34bbeeb2ULL, 0x1f1d25f19d51d821ULL,
	0xd80c07cd676f8394ULL, 0x9afce626ce85b507ULL
};

uint32_t crc32_gzip_refl_base(uint32_t seed, uint8_t * buf, uint64_t len)
{
	unsigned int crc;
	unsigned char *p_buf;
	unsigned char *p_end = buf + len;

	p_buf = (unsigned char *)buf;
	crc = ~seed;

	while (p_buf < p_end) {
		crc = (crc >> 8) ^ crc32_table_gzip_refl[(crc & 0x000000FF) ^ *p_buf++];
	}

	return ~crc;
}

uint64_t crc64_ecma_norm_base(uint64_t seed, const uint8_t * buf, uint64_t len)
{
	uint64_t i;
	/* Original ISA-L has crc = ~seed; Changed for CPM gen4 HW compatibility */
	uint64_t crc = seed;

	for (i = 0; i < len; i++) {
		uint8_t byte = buf[i];
		crc = crc64_ecma_norm_table[((crc >> 56) ^ byte) & 0xff] ^ (crc << 8);
	}

	/* Original ISA-L has return ~crc; Changed for CPM gen4 HW compatibility */
	return crc;
}
