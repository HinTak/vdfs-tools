/**
 * VDFS4 -- Vertically Deliberate improved performance File System
 *
 * Copyright 2012 by Samsung Electronics, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>

#include "vdfs_tools.h"
/**
 * @brief Crc32 values table crc32table_le
 */
static const unsigned int tab[4][256] = {{
0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL,
0x076dc419L, 0x706af48fL, 0xe963a535L, 0x9e6495a3L,
0x0edb8832L, 0x79dcb8a4L, 0xe0d5e91eL, 0x97d2d988L,
0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L, 0x90bf1d91L,
0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L,
0x136c9856L, 0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL,
0x14015c4fL, 0x63066cd9L, 0xfa0f3d63L, 0x8d080df5L,
0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L, 0xa2677172L,
0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L,
0x32d86ce3L, 0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L,
0x26d930acL, 0x51de003aL, 0xc8d75180L, 0xbfd06116L,
0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L, 0xb8bda50fL,
0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL,
0x76dc4190L, 0x01db7106L, 0x98d220bcL, 0xefd5102aL,
0x71b18589L, 0x06b6b51fL, 0x9fbfe4a5L, 0xe8b8d433L,
0x7807c9a2L, 0x0f00f934L, 0x9609a88eL, 0xe10e9818L,
0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL,
0x6c0695edL, 0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L,
0x65b0d9c6L, 0x12b7e950L, 0x8bbeb8eaL, 0xfcb9887cL,
0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L, 0xfbd44c65L,
0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL,
0x4369e96aL, 0x346ed9fcL, 0xad678846L, 0xda60b8d0L,
0x44042d73L, 0x33031de5L, 0xaa0a4c5fL, 0xdd0d7cc9L,
0x5005713cL, 0x270241aaL, 0xbe0b1010L, 0xc90c2086L,
0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L,
0x59b33d17L, 0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL,
0xedb88320L, 0x9abfb3b6L, 0x03b6e20cL, 0x74b1d29aL,
0xead54739L, 0x9dd277afL, 0x04db2615L, 0x73dc1683L,
0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L,
0xf00f9344L, 0x8708a3d2L, 0x1e01f268L, 0x6906c2feL,
0xf762575dL, 0x806567cbL, 0x196c3671L, 0x6e6b06e7L,
0xfed41b76L, 0x89d32be0L, 0x10da7a5aL, 0x67dd4accL,
0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L,
0xd1bb67f1L, 0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL,
0xd80d2bdaL, 0xaf0a1b4cL, 0x36034af6L, 0x41047a60L,
0xdf60efc3L, 0xa867df55L, 0x316e8eefL, 0x4669be79L,
0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL,
0xc5ba3bbeL, 0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L,
0xc2d7ffa7L, 0xb5d0cf31L, 0x2cd99e8bL, 0x5bdeae1dL,
0x9b64c2b0L, 0xec63f226L, 0x756aa39cL, 0x026d930aL,
0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L,
0x92d28e9bL, 0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L,
0x86d3d2d4L, 0xf1d4e242L, 0x68ddb3f8L, 0x1fda836eL,
0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L, 0x18b74777L,
0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L,
0xa00ae278L, 0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L,
0xa7672661L, 0xd06016f7L, 0x4969474dL, 0x3e6e77dbL,
0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L, 0x37d83bf0L,
0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L,
0xbad03605L, 0xcdd70693L, 0x54de5729L, 0x23d967bfL,
0xb3667a2eL, 0xc4614ab8L, 0x5d681b02L, 0x2a6f2b94L,
0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL, 0x2d02ef8dL},
{
0x00000000L, 0x191b3141L, 0x32366282L, 0x2b2d53c3L,
0x646cc504L, 0x7d77f445L, 0x565aa786L, 0x4f4196c7L,
0xc8d98a08L, 0xd1c2bb49L, 0xfaefe88aL, 0xe3f4d9cbL,
0xacb54f0cL, 0xb5ae7e4dL, 0x9e832d8eL, 0x87981ccfL,
0x4ac21251L, 0x53d92310L, 0x78f470d3L, 0x61ef4192L,
0x2eaed755L, 0x37b5e614L, 0x1c98b5d7L, 0x05838496L,
0x821b9859L, 0x9b00a918L, 0xb02dfadbL, 0xa936cb9aL,
0xe6775d5dL, 0xff6c6c1cL, 0xd4413fdfL, 0xcd5a0e9eL,
0x958424a2L, 0x8c9f15e3L, 0xa7b24620L, 0xbea97761L,
0xf1e8e1a6L, 0xe8f3d0e7L, 0xc3de8324L, 0xdac5b265L,
0x5d5daeaaL, 0x44469febL, 0x6f6bcc28L, 0x7670fd69L,
0x39316baeL, 0x202a5aefL, 0x0b07092cL, 0x121c386dL,
0xdf4636f3L, 0xc65d07b2L, 0xed705471L, 0xf46b6530L,
0xbb2af3f7L, 0xa231c2b6L, 0x891c9175L, 0x9007a034L,
0x179fbcfbL, 0x0e848dbaL, 0x25a9de79L, 0x3cb2ef38L,
0x73f379ffL, 0x6ae848beL, 0x41c51b7dL, 0x58de2a3cL,
0xf0794f05L, 0xe9627e44L, 0xc24f2d87L, 0xdb541cc6L,
0x94158a01L, 0x8d0ebb40L, 0xa623e883L, 0xbf38d9c2L,
0x38a0c50dL, 0x21bbf44cL, 0x0a96a78fL, 0x138d96ceL,
0x5ccc0009L, 0x45d73148L, 0x6efa628bL, 0x77e153caL,
0xbabb5d54L, 0xa3a06c15L, 0x888d3fd6L, 0x91960e97L,
0xded79850L, 0xc7cca911L, 0xece1fad2L, 0xf5facb93L,
0x7262d75cL, 0x6b79e61dL, 0x4054b5deL, 0x594f849fL,
0x160e1258L, 0x0f152319L, 0x243870daL, 0x3d23419bL,
0x65fd6ba7L, 0x7ce65ae6L, 0x57cb0925L, 0x4ed03864L,
0x0191aea3L, 0x188a9fe2L, 0x33a7cc21L, 0x2abcfd60L,
0xad24e1afL, 0xb43fd0eeL, 0x9f12832dL, 0x8609b26cL,
0xc94824abL, 0xd05315eaL, 0xfb7e4629L, 0xe2657768L,
0x2f3f79f6L, 0x362448b7L, 0x1d091b74L, 0x04122a35L,
0x4b53bcf2L, 0x52488db3L, 0x7965de70L, 0x607eef31L,
0xe7e6f3feL, 0xfefdc2bfL, 0xd5d0917cL, 0xcccba03dL,
0x838a36faL, 0x9a9107bbL, 0xb1bc5478L, 0xa8a76539L,
0x3b83984bL, 0x2298a90aL, 0x09b5fac9L, 0x10aecb88L,
0x5fef5d4fL, 0x46f46c0eL, 0x6dd93fcdL, 0x74c20e8cL,
0xf35a1243L, 0xea412302L, 0xc16c70c1L, 0xd8774180L,
0x9736d747L, 0x8e2de606L, 0xa500b5c5L, 0xbc1b8484L,
0x71418a1aL, 0x685abb5bL, 0x4377e898L, 0x5a6cd9d9L,
0x152d4f1eL, 0x0c367e5fL, 0x271b2d9cL, 0x3e001cddL,
0xb9980012L, 0xa0833153L, 0x8bae6290L, 0x92b553d1L,
0xddf4c516L, 0xc4eff457L, 0xefc2a794L, 0xf6d996d5L,
0xae07bce9L, 0xb71c8da8L, 0x9c31de6bL, 0x852aef2aL,
0xca6b79edL, 0xd37048acL, 0xf85d1b6fL, 0xe1462a2eL,
0x66de36e1L, 0x7fc507a0L, 0x54e85463L, 0x4df36522L,
0x02b2f3e5L, 0x1ba9c2a4L, 0x30849167L, 0x299fa026L,
0xe4c5aeb8L, 0xfdde9ff9L, 0xd6f3cc3aL, 0xcfe8fd7bL,
0x80a96bbcL, 0x99b25afdL, 0xb29f093eL, 0xab84387fL,
0x2c1c24b0L, 0x350715f1L, 0x1e2a4632L, 0x07317773L,
0x4870e1b4L, 0x516bd0f5L, 0x7a468336L, 0x635db277L,
0xcbfad74eL, 0xd2e1e60fL, 0xf9ccb5ccL, 0xe0d7848dL,
0xaf96124aL, 0xb68d230bL, 0x9da070c8L, 0x84bb4189L,
0x03235d46L, 0x1a386c07L, 0x31153fc4L, 0x280e0e85L,
0x674f9842L, 0x7e54a903L, 0x5579fac0L, 0x4c62cb81L,
0x8138c51fL, 0x9823f45eL, 0xb30ea79dL, 0xaa1596dcL,
0xe554001bL, 0xfc4f315aL, 0xd7626299L, 0xce7953d8L,
0x49e14f17L, 0x50fa7e56L, 0x7bd72d95L, 0x62cc1cd4L,
0x2d8d8a13L, 0x3496bb52L, 0x1fbbe891L, 0x06a0d9d0L,
0x5e7ef3ecL, 0x4765c2adL, 0x6c48916eL, 0x7553a02fL,
0x3a1236e8L, 0x230907a9L, 0x0824546aL, 0x113f652bL,
0x96a779e4L, 0x8fbc48a5L, 0xa4911b66L, 0xbd8a2a27L,
0xf2cbbce0L, 0xebd08da1L, 0xc0fdde62L, 0xd9e6ef23L,
0x14bce1bdL, 0x0da7d0fcL, 0x268a833fL, 0x3f91b27eL,
0x70d024b9L, 0x69cb15f8L, 0x42e6463bL, 0x5bfd777aL,
0xdc656bb5L, 0xc57e5af4L, 0xee530937L, 0xf7483876L,
0xb809aeb1L, 0xa1129ff0L, 0x8a3fcc33L, 0x9324fd72L},
{
0x00000000L, 0x01c26a37L, 0x0384d46eL, 0x0246be59L,
0x0709a8dcL, 0x06cbc2ebL, 0x048d7cb2L, 0x054f1685L,
0x0e1351b8L, 0x0fd13b8fL, 0x0d9785d6L, 0x0c55efe1L,
0x091af964L, 0x08d89353L, 0x0a9e2d0aL, 0x0b5c473dL,
0x1c26a370L, 0x1de4c947L, 0x1fa2771eL, 0x1e601d29L,
0x1b2f0bacL, 0x1aed619bL, 0x18abdfc2L, 0x1969b5f5L,
0x1235f2c8L, 0x13f798ffL, 0x11b126a6L, 0x10734c91L,
0x153c5a14L, 0x14fe3023L, 0x16b88e7aL, 0x177ae44dL,
0x384d46e0L, 0x398f2cd7L, 0x3bc9928eL, 0x3a0bf8b9L,
0x3f44ee3cL, 0x3e86840bL, 0x3cc03a52L, 0x3d025065L,
0x365e1758L, 0x379c7d6fL, 0x35dac336L, 0x3418a901L,
0x3157bf84L, 0x3095d5b3L, 0x32d36beaL, 0x331101ddL,
0x246be590L, 0x25a98fa7L, 0x27ef31feL, 0x262d5bc9L,
0x23624d4cL, 0x22a0277bL, 0x20e69922L, 0x2124f315L,
0x2a78b428L, 0x2bbade1fL, 0x29fc6046L, 0x283e0a71L,
0x2d711cf4L, 0x2cb376c3L, 0x2ef5c89aL, 0x2f37a2adL,
0x709a8dc0L, 0x7158e7f7L, 0x731e59aeL, 0x72dc3399L,
0x7793251cL, 0x76514f2bL, 0x7417f172L, 0x75d59b45L,
0x7e89dc78L, 0x7f4bb64fL, 0x7d0d0816L, 0x7ccf6221L,
0x798074a4L, 0x78421e93L, 0x7a04a0caL, 0x7bc6cafdL,
0x6cbc2eb0L, 0x6d7e4487L, 0x6f38fadeL, 0x6efa90e9L,
0x6bb5866cL, 0x6a77ec5bL, 0x68315202L, 0x69f33835L,
0x62af7f08L, 0x636d153fL, 0x612bab66L, 0x60e9c151L,
0x65a6d7d4L, 0x6464bde3L, 0x662203baL, 0x67e0698dL,
0x48d7cb20L, 0x4915a117L, 0x4b531f4eL, 0x4a917579L,
0x4fde63fcL, 0x4e1c09cbL, 0x4c5ab792L, 0x4d98dda5L,
0x46c49a98L, 0x4706f0afL, 0x45404ef6L, 0x448224c1L,
0x41cd3244L, 0x400f5873L, 0x4249e62aL, 0x438b8c1dL,
0x54f16850L, 0x55330267L, 0x5775bc3eL, 0x56b7d609L,
0x53f8c08cL, 0x523aaabbL, 0x507c14e2L, 0x51be7ed5L,
0x5ae239e8L, 0x5b2053dfL, 0x5966ed86L, 0x58a487b1L,
0x5deb9134L, 0x5c29fb03L, 0x5e6f455aL, 0x5fad2f6dL,
0xe1351b80L, 0xe0f771b7L, 0xe2b1cfeeL, 0xe373a5d9L,
0xe63cb35cL, 0xe7fed96bL, 0xe5b86732L, 0xe47a0d05L,
0xef264a38L, 0xeee4200fL, 0xeca29e56L, 0xed60f461L,
0xe82fe2e4L, 0xe9ed88d3L, 0xebab368aL, 0xea695cbdL,
0xfd13b8f0L, 0xfcd1d2c7L, 0xfe976c9eL, 0xff5506a9L,
0xfa1a102cL, 0xfbd87a1bL, 0xf99ec442L, 0xf85cae75L,
0xf300e948L, 0xf2c2837fL, 0xf0843d26L, 0xf1465711L,
0xf4094194L, 0xf5cb2ba3L, 0xf78d95faL, 0xf64fffcdL,
0xd9785d60L, 0xd8ba3757L, 0xdafc890eL, 0xdb3ee339L,
0xde71f5bcL, 0xdfb39f8bL, 0xddf521d2L, 0xdc374be5L,
0xd76b0cd8L, 0xd6a966efL, 0xd4efd8b6L, 0xd52db281L,
0xd062a404L, 0xd1a0ce33L, 0xd3e6706aL, 0xd2241a5dL,
0xc55efe10L, 0xc49c9427L, 0xc6da2a7eL, 0xc7184049L,
0xc25756ccL, 0xc3953cfbL, 0xc1d382a2L, 0xc011e895L,
0xcb4dafa8L, 0xca8fc59fL, 0xc8c97bc6L, 0xc90b11f1L,
0xcc440774L, 0xcd866d43L, 0xcfc0d31aL, 0xce02b92dL,
0x91af9640L, 0x906dfc77L, 0x922b422eL, 0x93e92819L,
0x96a63e9cL, 0x976454abL, 0x9522eaf2L, 0x94e080c5L,
0x9fbcc7f8L, 0x9e7eadcfL, 0x9c381396L, 0x9dfa79a1L,
0x98b56f24L, 0x99770513L, 0x9b31bb4aL, 0x9af3d17dL,
0x8d893530L, 0x8c4b5f07L, 0x8e0de15eL, 0x8fcf8b69L,
0x8a809decL, 0x8b42f7dbL, 0x89044982L, 0x88c623b5L,
0x839a6488L, 0x82580ebfL, 0x801eb0e6L, 0x81dcdad1L,
0x8493cc54L, 0x8551a663L, 0x8717183aL, 0x86d5720dL,
0xa9e2d0a0L, 0xa820ba97L, 0xaa6604ceL, 0xaba46ef9L,
0xaeeb787cL, 0xaf29124bL, 0xad6fac12L, 0xacadc625L,
0xa7f18118L, 0xa633eb2fL, 0xa4755576L, 0xa5b73f41L,
0xa0f829c4L, 0xa13a43f3L, 0xa37cfdaaL, 0xa2be979dL,
0xb5c473d0L, 0xb40619e7L, 0xb640a7beL, 0xb782cd89L,
0xb2cddb0cL, 0xb30fb13bL, 0xb1490f62L, 0xb08b6555L,
0xbbd72268L, 0xba15485fL, 0xb853f606L, 0xb9919c31L,
0xbcde8ab4L, 0xbd1ce083L, 0xbf5a5edaL, 0xbe9834edL},
{
0x00000000L, 0xb8bc6765L, 0xaa09c88bL, 0x12b5afeeL,
0x8f629757L, 0x37def032L, 0x256b5fdcL, 0x9dd738b9L,
0xc5b428efL, 0x7d084f8aL, 0x6fbde064L, 0xd7018701L,
0x4ad6bfb8L, 0xf26ad8ddL, 0xe0df7733L, 0x58631056L,
0x5019579fL, 0xe8a530faL, 0xfa109f14L, 0x42acf871L,
0xdf7bc0c8L, 0x67c7a7adL, 0x75720843L, 0xcdce6f26L,
0x95ad7f70L, 0x2d111815L, 0x3fa4b7fbL, 0x8718d09eL,
0x1acfe827L, 0xa2738f42L, 0xb0c620acL, 0x087a47c9L,
0xa032af3eL, 0x188ec85bL, 0x0a3b67b5L, 0xb28700d0L,
0x2f503869L, 0x97ec5f0cL, 0x8559f0e2L, 0x3de59787L,
0x658687d1L, 0xdd3ae0b4L, 0xcf8f4f5aL, 0x7733283fL,
0xeae41086L, 0x525877e3L, 0x40edd80dL, 0xf851bf68L,
0xf02bf8a1L, 0x48979fc4L, 0x5a22302aL, 0xe29e574fL,
0x7f496ff6L, 0xc7f50893L, 0xd540a77dL, 0x6dfcc018L,
0x359fd04eL, 0x8d23b72bL, 0x9f9618c5L, 0x272a7fa0L,
0xbafd4719L, 0x0241207cL, 0x10f48f92L, 0xa848e8f7L,
0x9b14583dL, 0x23a83f58L, 0x311d90b6L, 0x89a1f7d3L,
0x1476cf6aL, 0xaccaa80fL, 0xbe7f07e1L, 0x06c36084L,
0x5ea070d2L, 0xe61c17b7L, 0xf4a9b859L, 0x4c15df3cL,
0xd1c2e785L, 0x697e80e0L, 0x7bcb2f0eL, 0xc377486bL,
0xcb0d0fa2L, 0x73b168c7L, 0x6104c729L, 0xd9b8a04cL,
0x446f98f5L, 0xfcd3ff90L, 0xee66507eL, 0x56da371bL,
0x0eb9274dL, 0xb6054028L, 0xa4b0efc6L, 0x1c0c88a3L,
0x81dbb01aL, 0x3967d77fL, 0x2bd27891L, 0x936e1ff4L,
0x3b26f703L, 0x839a9066L, 0x912f3f88L, 0x299358edL,
0xb4446054L, 0x0cf80731L, 0x1e4da8dfL, 0xa6f1cfbaL,
0xfe92dfecL, 0x462eb889L, 0x549b1767L, 0xec277002L,
0x71f048bbL, 0xc94c2fdeL, 0xdbf98030L, 0x6345e755L,
0x6b3fa09cL, 0xd383c7f9L, 0xc1366817L, 0x798a0f72L,
0xe45d37cbL, 0x5ce150aeL, 0x4e54ff40L, 0xf6e89825L,
0xae8b8873L, 0x1637ef16L, 0x048240f8L, 0xbc3e279dL,
0x21e91f24L, 0x99557841L, 0x8be0d7afL, 0x335cb0caL,
0xed59b63bL, 0x55e5d15eL, 0x47507eb0L, 0xffec19d5L,
0x623b216cL, 0xda874609L, 0xc832e9e7L, 0x708e8e82L,
0x28ed9ed4L, 0x9051f9b1L, 0x82e4565fL, 0x3a58313aL,
0xa78f0983L, 0x1f336ee6L, 0x0d86c108L, 0xb53aa66dL,
0xbd40e1a4L, 0x05fc86c1L, 0x1749292fL, 0xaff54e4aL,
0x322276f3L, 0x8a9e1196L, 0x982bbe78L, 0x2097d91dL,
0x78f4c94bL, 0xc048ae2eL, 0xd2fd01c0L, 0x6a4166a5L,
0xf7965e1cL, 0x4f2a3979L, 0x5d9f9697L, 0xe523f1f2L,
0x4d6b1905L, 0xf5d77e60L, 0xe762d18eL, 0x5fdeb6ebL,
0xc2098e52L, 0x7ab5e937L, 0x680046d9L, 0xd0bc21bcL,
0x88df31eaL, 0x3063568fL, 0x22d6f961L, 0x9a6a9e04L,
0x07bda6bdL, 0xbf01c1d8L, 0xadb46e36L, 0x15080953L,
0x1d724e9aL, 0xa5ce29ffL, 0xb77b8611L, 0x0fc7e174L,
0x9210d9cdL, 0x2aacbea8L, 0x38191146L, 0x80a57623L,
0xd8c66675L, 0x607a0110L, 0x72cfaefeL, 0xca73c99bL,
0x57a4f122L, 0xef189647L, 0xfdad39a9L, 0x45115eccL,
0x764dee06L, 0xcef18963L, 0xdc44268dL, 0x64f841e8L,
0xf92f7951L, 0x41931e34L, 0x5326b1daL, 0xeb9ad6bfL,
0xb3f9c6e9L, 0x0b45a18cL, 0x19f00e62L, 0xa14c6907L,
0x3c9b51beL, 0x842736dbL, 0x96929935L, 0x2e2efe50L,
0x2654b999L, 0x9ee8defcL, 0x8c5d7112L, 0x34e11677L,
0xa9362eceL, 0x118a49abL, 0x033fe645L, 0xbb838120L,
0xe3e09176L, 0x5b5cf613L, 0x49e959fdL, 0xf1553e98L,
0x6c820621L, 0xd43e6144L, 0xc68bceaaL, 0x7e37a9cfL,
0xd67f4138L, 0x6ec3265dL, 0x7c7689b3L, 0xc4caeed6L,
0x591dd66fL, 0xe1a1b10aL, 0xf3141ee4L, 0x4ba87981L,
0x13cb69d7L, 0xab770eb2L, 0xb9c2a15cL, 0x017ec639L,
0x9ca9fe80L, 0x241599e5L, 0x36a0360bL, 0x8e1c516eL,
0x866616a7L, 0x3eda71c2L, 0x2c6fde2cL, 0x94d3b949L,
0x090481f0L, 0xb1b8e695L, 0xa30d497bL, 0x1bb12e1eL,
0x43d23e48L, 0xfb6e592dL, 0xe9dbf6c3L, 0x516791a6L,
0xccb0a91fL, 0x740cce7aL, 0x66b96194L, 0xde0506f1L}
};

/******************************************************************************/
/* PRIVATE FUNCTIONS                                                          */
/******************************************************************************/
/**
 * @brief Crc32 calculation body.
 * @param crc Initial Crc32 value.
 * @param buf Pointer to buffer where Crc32 must be calculated.
 * @param len Length of buffer buf.
 * @return Value of Crc32
 */
unsigned int crc32_body(unsigned int crc,
	unsigned char const *buf,
	u_int32_t len)
{
#  define DO_CRC(x) (crc = tab[0][(crc ^ (x)) & 255] ^ (crc >> 8))
#  define DO_CRC4 crc = tab[3][(crc) & 255] ^ \
		tab[2][(crc >> 8) & 255] ^ \
		tab[1][(crc >> 16) & 255] ^ \
		tab[0][(crc >> 24) & 255]
	const unsigned int *b;
	u_int32_t    rem_len;

	/* Align it */
	if ((long)buf & 3 && len) {
		do {
			DO_CRC(*buf++);
		} while ((--len) && ((long)buf)&3);
	}
	rem_len = len & 3;
	/* load data 32 bits wide, xor data 32 bits wide. */
	len = len >> 2;
	b = (const unsigned int *)buf;
	for (--b; len; --len) {
		crc ^= *++b; /* use pre increment for speed */
		DO_CRC4;
	}
	len = rem_len;
	/* And the last few bytes */
	if (len) {
		unsigned char *p = (unsigned char *)(b + 1) - 1;
		do {
			DO_CRC(*++p); /* use pre increment for speed */
		} while (--len);
	}
	return crc;
#undef DO_CRC
#undef DO_CRC4
}
/******************************************************************************/
/* PUBLIC FUNCTIONS                                                           */
/******************************************************************************/
unsigned int vdfs4_crc32(const void *buff, u_int32_t len)
{
	return crc32_body(0, (const unsigned char *)buff, len);
}

unsigned int calculate_file_crc(int file_id, int calc_last_block, int *error)
{
	unsigned int crc = 0;
	unsigned char buf[BLOCK_SIZE_DEFAULT];
	ssize_t sz, calc_size;
	struct stat stat;

	*error = 0;
	lseek(file_id, 0, SEEK_SET);
	if (fstat(file_id, &stat)) {
		*error = errno;
		return 0;
	}
	calc_size = stat.st_size;
	if (!calc_last_block)
		calc_size -= BLOCK_SIZE_DEFAULT;

	while (calc_size > 0 && (sz = read(file_id, buf, BLOCK_SIZE_DEFAULT))) {
		if (sz == -1) {
			*error = errno;
			return 0;
		}

		crc = crc32_body(crc, buf, sz);
		calc_size -= sz;
	}
	return crc;
}

