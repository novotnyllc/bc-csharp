using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class OaepTest
        : SimpleTest
    {
        private static readonly byte[] pubKeyEnc1 =
        {
            0x30, 0x5a, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
            0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
            0x00, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x41,
            0x00, 0xaa, 0x36, 0xab, 0xce, 0x88, 0xac, 0xfd,
            0xff, 0x55, 0x52, 0x3c, 0x7f, 0xc4, 0x52, 0x3f,
            0x90, 0xef, 0xa0, 0x0d, 0xf3, 0x77, 0x4a, 0x25,
            0x9f, 0x2e, 0x62, 0xb4, 0xc5, 0xd9, 0x9c, 0xb5,
            0xad, 0xb3, 0x00, 0xa0, 0x28, 0x5e, 0x53, 0x01,
            0x93, 0x0e, 0x0c, 0x70, 0xfb, 0x68, 0x76, 0x93,
            0x9c, 0xe6, 0x16, 0xce, 0x62, 0x4a, 0x11, 0xe0,
            0x08, 0x6d, 0x34, 0x1e, 0xbc, 0xac, 0xa0, 0xa1,
            0xf5, 0x02, 0x01, 0x11
        };

        private static readonly byte[] privKeyEnc1 =
        {
            0x30, 0x82, 0x01, 0x52, 0x02, 0x01, 0x00, 0x30,
            0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
            0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82,
            0x01, 0x3c, 0x30, 0x82, 0x01, 0x38, 0x02, 0x01,
            0x00, 0x02, 0x41, 0x00, 0xaa, 0x36, 0xab, 0xce,
            0x88, 0xac, 0xfd, 0xff, 0x55, 0x52, 0x3c, 0x7f,
            0xc4, 0x52, 0x3f, 0x90, 0xef, 0xa0, 0x0d, 0xf3,
            0x77, 0x4a, 0x25, 0x9f, 0x2e, 0x62, 0xb4, 0xc5,
            0xd9, 0x9c, 0xb5, 0xad, 0xb3, 0x00, 0xa0, 0x28,
            0x5e, 0x53, 0x01, 0x93, 0x0e, 0x0c, 0x70, 0xfb,
            0x68, 0x76, 0x93, 0x9c, 0xe6, 0x16, 0xce, 0x62,
            0x4a, 0x11, 0xe0, 0x08, 0x6d, 0x34, 0x1e, 0xbc,
            0xac, 0xa0, 0xa1, 0xf5, 0x02, 0x01, 0x11, 0x02,
            0x40, 0x0a, 0x03, 0x37, 0x48, 0x62, 0x64, 0x87,
            0x69, 0x5f, 0x5f, 0x30, 0xbc, 0x38, 0xb9, 0x8b,
            0x44, 0xc2, 0xcd, 0x2d, 0xff, 0x43, 0x40, 0x98,
            0xcd, 0x20, 0xd8, 0xa1, 0x38, 0xd0, 0x90, 0xbf,
            0x64, 0x79, 0x7c, 0x3f, 0xa7, 0xa2, 0xcd, 0xcb,
            0x3c, 0xd1, 0xe0, 0xbd, 0xba, 0x26, 0x54, 0xb4,
            0xf9, 0xdf, 0x8e, 0x8a, 0xe5, 0x9d, 0x73, 0x3d,
            0x9f, 0x33, 0xb3, 0x01, 0x62, 0x4a, 0xfd, 0x1d,
            0x51, 0x02, 0x21, 0x00, 0xd8, 0x40, 0xb4, 0x16,
            0x66, 0xb4, 0x2e, 0x92, 0xea, 0x0d, 0xa3, 0xb4,
            0x32, 0x04, 0xb5, 0xcf, 0xce, 0x33, 0x52, 0x52,
            0x4d, 0x04, 0x16, 0xa5, 0xa4, 0x41, 0xe7, 0x00,
            0xaf, 0x46, 0x12, 0x0d, 0x02, 0x21, 0x00, 0xc9,
            0x7f, 0xb1, 0xf0, 0x27, 0xf4, 0x53, 0xf6, 0x34,
            0x12, 0x33, 0xea, 0xaa, 0xd1, 0xd9, 0x35, 0x3f,
            0x6c, 0x42, 0xd0, 0x88, 0x66, 0xb1, 0xd0, 0x5a,
            0x0f, 0x20, 0x35, 0x02, 0x8b, 0x9d, 0x89, 0x02,
            0x20, 0x59, 0x0b, 0x95, 0x72, 0xa2, 0xc2, 0xa9,
            0xc4, 0x06, 0x05, 0x9d, 0xc2, 0xab, 0x2f, 0x1d,
            0xaf, 0xeb, 0x7e, 0x8b, 0x4f, 0x10, 0xa7, 0x54,
            0x9e, 0x8e, 0xed, 0xf5, 0xb4, 0xfc, 0xe0, 0x9e,
            0x05, 0x02, 0x21, 0x00, 0x8e, 0x3c, 0x05, 0x21,
            0xfe, 0x15, 0xe0, 0xea, 0x06, 0xa3, 0x6f, 0xf0,
            0xf1, 0x0c, 0x99, 0x52, 0xc3, 0x5b, 0x7a, 0x75,
            0x14, 0xfd, 0x32, 0x38, 0xb8, 0x0a, 0xad, 0x52,
            0x98, 0x62, 0x8d, 0x51, 0x02, 0x20, 0x36, 0x3f,
            0xf7, 0x18, 0x9d, 0xa8, 0xe9, 0x0b, 0x1d, 0x34,
            0x1f, 0x71, 0xd0, 0x9b, 0x76, 0xa8, 0xa9, 0x43,
            0xe1, 0x1d, 0x10, 0xb2, 0x4d, 0x24, 0x9f, 0x2d,
            0xea, 0xfe, 0xf8, 0x0c, 0x18, 0x26
        };

        private static readonly byte[] output1 = 
        {
            0x1b, 0x8f, 0x05, 0xf9, 0xca, 0x1a, 0x79, 0x52,
            0x6e, 0x53, 0xf3, 0xcc, 0x51, 0x4f, 0xdb, 0x89,
            0x2b, 0xfb, 0x91, 0x93, 0x23, 0x1e, 0x78, 0xb9,
            0x92, 0xe6, 0x8d, 0x50, 0xa4, 0x80, 0xcb, 0x52,
            0x33, 0x89, 0x5c, 0x74, 0x95, 0x8d, 0x5d, 0x02,
            0xab, 0x8c, 0x0f, 0xd0, 0x40, 0xeb, 0x58, 0x44,
            0xb0, 0x05, 0xc3, 0x9e, 0xd8, 0x27, 0x4a, 0x9d,
            0xbf, 0xa8, 0x06, 0x71, 0x40, 0x94, 0x39, 0xd2
        };

        private static readonly byte[] pubKeyEnc2 =
        {
            0x30, 0x4c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
            0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
            0x00, 0x03, 0x3b, 0x00, 0x30, 0x38, 0x02, 0x33,
            0x00, 0xa3, 0x07, 0x9a, 0x90, 0xdf, 0x0d, 0xfd,
            0x72, 0xac, 0x09, 0x0c, 0xcc, 0x2a, 0x78, 0xb8,
            0x74, 0x13, 0x13, 0x3e, 0x40, 0x75, 0x9c, 0x98,
            0xfa, 0xf8, 0x20, 0x4f, 0x35, 0x8a, 0x0b, 0x26,
            0x3c, 0x67, 0x70, 0xe7, 0x83, 0xa9, 0x3b, 0x69,
            0x71, 0xb7, 0x37, 0x79, 0xd2, 0x71, 0x7b, 0xe8,
            0x34, 0x77, 0xcf, 0x02, 0x01, 0x03
        };

        private static readonly byte[] privKeyEnc2 =
        {
            0x30, 0x82, 0x01, 0x13, 0x02, 0x01, 0x00, 0x30,
            0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
            0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x81,
            0xfe, 0x30, 0x81, 0xfb, 0x02, 0x01, 0x00, 0x02,
            0x33, 0x00, 0xa3, 0x07, 0x9a, 0x90, 0xdf, 0x0d,
            0xfd, 0x72, 0xac, 0x09, 0x0c, 0xcc, 0x2a, 0x78,
            0xb8, 0x74, 0x13, 0x13, 0x3e, 0x40, 0x75, 0x9c,
            0x98, 0xfa, 0xf8, 0x20, 0x4f, 0x35, 0x8a, 0x0b,
            0x26, 0x3c, 0x67, 0x70, 0xe7, 0x83, 0xa9, 0x3b,
            0x69, 0x71, 0xb7, 0x37, 0x79, 0xd2, 0x71, 0x7b,
            0xe8, 0x34, 0x77, 0xcf, 0x02, 0x01, 0x03, 0x02,
            0x32, 0x6c, 0xaf, 0xbc, 0x60, 0x94, 0xb3, 0xfe,
            0x4c, 0x72, 0xb0, 0xb3, 0x32, 0xc6, 0xfb, 0x25,
            0xa2, 0xb7, 0x62, 0x29, 0x80, 0x4e, 0x68, 0x65,
            0xfc, 0xa4, 0x5a, 0x74, 0xdf, 0x0f, 0x8f, 0xb8,
            0x41, 0x3b, 0x52, 0xc0, 0xd0, 0xe5, 0x3d, 0x9b,
            0x59, 0x0f, 0xf1, 0x9b, 0xe7, 0x9f, 0x49, 0xdd,
            0x21, 0xe5, 0xeb, 0x02, 0x1a, 0x00, 0xcf, 0x20,
            0x35, 0x02, 0x8b, 0x9d, 0x86, 0x98, 0x40, 0xb4,
            0x16, 0x66, 0xb4, 0x2e, 0x92, 0xea, 0x0d, 0xa3,
            0xb4, 0x32, 0x04, 0xb5, 0xcf, 0xce, 0x91, 0x02,
            0x1a, 0x00, 0xc9, 0x7f, 0xb1, 0xf0, 0x27, 0xf4,
            0x53, 0xf6, 0x34, 0x12, 0x33, 0xea, 0xaa, 0xd1,
            0xd9, 0x35, 0x3f, 0x6c, 0x42, 0xd0, 0x88, 0x66,
            0xb1, 0xd0, 0x5f, 0x02, 0x1a, 0x00, 0x8a, 0x15,
            0x78, 0xac, 0x5d, 0x13, 0xaf, 0x10, 0x2b, 0x22,
            0xb9, 0x99, 0xcd, 0x74, 0x61, 0xf1, 0x5e, 0x6d,
            0x22, 0xcc, 0x03, 0x23, 0xdf, 0xdf, 0x0b, 0x02,
            0x1a, 0x00, 0x86, 0x55, 0x21, 0x4a, 0xc5, 0x4d,
            0x8d, 0x4e, 0xcd, 0x61, 0x77, 0xf1, 0xc7, 0x36,
            0x90, 0xce, 0x2a, 0x48, 0x2c, 0x8b, 0x05, 0x99,
            0xcb, 0xe0, 0x3f, 0x02, 0x1a, 0x00, 0x83, 0xef,
            0xef, 0xb8, 0xa9, 0xa4, 0x0d, 0x1d, 0xb6, 0xed,
            0x98, 0xad, 0x84, 0xed, 0x13, 0x35, 0xdc, 0xc1,
            0x08, 0xf3, 0x22, 0xd0, 0x57, 0xcf, 0x8d
        };

        private static readonly byte[] output2 =
        {
            0x14, 0xbd, 0xdd, 0x28, 0xc9, 0x83, 0x35, 0x19,
            0x23, 0x80, 0xe8, 0xe5, 0x49, 0xb1, 0x58, 0x2a,
            0x8b, 0x40, 0xb4, 0x48, 0x6d, 0x03, 0xa6, 0xa5,
            0x31, 0x1f, 0x1f, 0xd5, 0xf0, 0xa1, 0x80, 0xe4,
            0x17, 0x53, 0x03, 0x29, 0xa9, 0x34, 0x90, 0x74,
            0xb1, 0x52, 0x13, 0x54, 0x29, 0x08, 0x24, 0x52,
            0x62, 0x51
        };

        private static readonly byte[] pubKeyEnc3 =
        {
            0x30, 0x81, 0x9d, 0x30, 0x0d, 0x06, 0x09, 0x2a,
            0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
            0x05, 0x00, 0x03, 0x81, 0x8b, 0x00, 0x30, 0x81,
            0x87, 0x02, 0x81, 0x81, 0x00, 0xbb, 0xf8, 0x2f,
            0x09, 0x06, 0x82, 0xce, 0x9c, 0x23, 0x38, 0xac,
            0x2b, 0x9d, 0xa8, 0x71, 0xf7, 0x36, 0x8d, 0x07,
            0xee, 0xd4, 0x10, 0x43, 0xa4, 0x40, 0xd6, 0xb6,
            0xf0, 0x74, 0x54, 0xf5, 0x1f, 0xb8, 0xdf, 0xba,
            0xaf, 0x03, 0x5c, 0x02, 0xab, 0x61, 0xea, 0x48,
            0xce, 0xeb, 0x6f, 0xcd, 0x48, 0x76, 0xed, 0x52,
            0x0d, 0x60, 0xe1, 0xec, 0x46, 0x19, 0x71, 0x9d,
            0x8a, 0x5b, 0x8b, 0x80, 0x7f, 0xaf, 0xb8, 0xe0,
            0xa3, 0xdf, 0xc7, 0x37, 0x72, 0x3e, 0xe6, 0xb4,
            0xb7, 0xd9, 0x3a, 0x25, 0x84, 0xee, 0x6a, 0x64,
            0x9d, 0x06, 0x09, 0x53, 0x74, 0x88, 0x34, 0xb2,
            0x45, 0x45, 0x98, 0x39, 0x4e, 0xe0, 0xaa, 0xb1,
            0x2d, 0x7b, 0x61, 0xa5, 0x1f, 0x52, 0x7a, 0x9a,
            0x41, 0xf6, 0xc1, 0x68, 0x7f, 0xe2, 0x53, 0x72,
            0x98, 0xca, 0x2a, 0x8f, 0x59, 0x46, 0xf8, 0xe5,
            0xfd, 0x09, 0x1d, 0xbd, 0xcb, 0x02, 0x01, 0x11
        };

        private static readonly byte[] privKeyEnc3 =
        {
            0x30, 0x82, 0x02, 0x75, 0x02, 0x01, 0x00, 0x30,
            0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
            0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82,
            0x02, 0x5f, 0x30, 0x82, 0x02, 0x5b, 0x02, 0x01,
            0x00, 0x02, 0x81, 0x81, 0x00, 0xbb, 0xf8, 0x2f,
            0x09, 0x06, 0x82, 0xce, 0x9c, 0x23, 0x38, 0xac,
            0x2b, 0x9d, 0xa8, 0x71, 0xf7, 0x36, 0x8d, 0x07,
            0xee, 0xd4, 0x10, 0x43, 0xa4, 0x40, 0xd6, 0xb6,
            0xf0, 0x74, 0x54, 0xf5, 0x1f, 0xb8, 0xdf, 0xba,
            0xaf, 0x03, 0x5c, 0x02, 0xab, 0x61, 0xea, 0x48,
            0xce, 0xeb, 0x6f, 0xcd, 0x48, 0x76, 0xed, 0x52,
            0x0d, 0x60, 0xe1, 0xec, 0x46, 0x19, 0x71, 0x9d,
            0x8a, 0x5b, 0x8b, 0x80, 0x7f, 0xaf, 0xb8, 0xe0,
            0xa3, 0xdf, 0xc7, 0x37, 0x72, 0x3e, 0xe6, 0xb4,
            0xb7, 0xd9, 0x3a, 0x25, 0x84, 0xee, 0x6a, 0x64,
            0x9d, 0x06, 0x09, 0x53, 0x74, 0x88, 0x34, 0xb2,
            0x45, 0x45, 0x98, 0x39, 0x4e, 0xe0, 0xaa, 0xb1,
            0x2d, 0x7b, 0x61, 0xa5, 0x1f, 0x52, 0x7a, 0x9a,
            0x41, 0xf6, 0xc1, 0x68, 0x7f, 0xe2, 0x53, 0x72,
            0x98, 0xca, 0x2a, 0x8f, 0x59, 0x46, 0xf8, 0xe5,
            0xfd, 0x09, 0x1d, 0xbd, 0xcb, 0x02, 0x01, 0x11,
            0x02, 0x81, 0x81, 0x00, 0xa5, 0xda, 0xfc, 0x53,
            0x41, 0xfa, 0xf2, 0x89, 0xc4, 0xb9, 0x88, 0xdb,
            0x30, 0xc1, 0xcd, 0xf8, 0x3f, 0x31, 0x25, 0x1e,
            0x06, 0x68, 0xb4, 0x27, 0x84, 0x81, 0x38, 0x01,
            0x57, 0x96, 0x41, 0xb2, 0x94, 0x10, 0xb3, 0xc7,
            0x99, 0x8d, 0x6b, 0xc4, 0x65, 0x74, 0x5e, 0x5c,
            0x39, 0x26, 0x69, 0xd6, 0x87, 0x0d, 0xa2, 0xc0,
            0x82, 0xa9, 0x39, 0xe3, 0x7f, 0xdc, 0xb8, 0x2e,
            0xc9, 0x3e, 0xda, 0xc9, 0x7f, 0xf3, 0xad, 0x59,
            0x50, 0xac, 0xcf, 0xbc, 0x11, 0x1c, 0x76, 0xf1,
            0xa9, 0x52, 0x94, 0x44, 0xe5, 0x6a, 0xaf, 0x68,
            0xc5, 0x6c, 0x09, 0x2c, 0xd3, 0x8d, 0xc3, 0xbe,
            0xf5, 0xd2, 0x0a, 0x93, 0x99, 0x26, 0xed, 0x4f,
            0x74, 0xa1, 0x3e, 0xdd, 0xfb, 0xe1, 0xa1, 0xce,
            0xcc, 0x48, 0x94, 0xaf, 0x94, 0x28, 0xc2, 0xb7,
            0xb8, 0x88, 0x3f, 0xe4, 0x46, 0x3a, 0x4b, 0xc8,
            0x5b, 0x1c, 0xb3, 0xc1, 0x02, 0x41, 0x00, 0xee,
            0xcf, 0xae, 0x81, 0xb1, 0xb9, 0xb3, 0xc9, 0x08,
            0x81, 0x0b, 0x10, 0xa1, 0xb5, 0x60, 0x01, 0x99,
            0xeb, 0x9f, 0x44, 0xae, 0xf4, 0xfd, 0xa4, 0x93,
            0xb8, 0x1a, 0x9e, 0x3d, 0x84, 0xf6, 0x32, 0x12,
            0x4e, 0xf0, 0x23, 0x6e, 0x5d, 0x1e, 0x3b, 0x7e,
            0x28, 0xfa, 0xe7, 0xaa, 0x04, 0x0a, 0x2d, 0x5b,
            0x25, 0x21, 0x76, 0x45, 0x9d, 0x1f, 0x39, 0x75,
            0x41, 0xba, 0x2a, 0x58, 0xfb, 0x65, 0x99, 0x02,
            0x41, 0x00, 0xc9, 0x7f, 0xb1, 0xf0, 0x27, 0xf4,
            0x53, 0xf6, 0x34, 0x12, 0x33, 0xea, 0xaa, 0xd1,
            0xd9, 0x35, 0x3f, 0x6c, 0x42, 0xd0, 0x88, 0x66,
            0xb1, 0xd0, 0x5a, 0x0f, 0x20, 0x35, 0x02, 0x8b,
            0x9d, 0x86, 0x98, 0x40, 0xb4, 0x16, 0x66, 0xb4,
            0x2e, 0x92, 0xea, 0x0d, 0xa3, 0xb4, 0x32, 0x04,
            0xb5, 0xcf, 0xce, 0x33, 0x52, 0x52, 0x4d, 0x04,
            0x16, 0xa5, 0xa4, 0x41, 0xe7, 0x00, 0xaf, 0x46,
            0x15, 0x03, 0x02, 0x40, 0x54, 0x49, 0x4c, 0xa6,
            0x3e, 0xba, 0x03, 0x37, 0xe4, 0xe2, 0x40, 0x23,
            0xfc, 0xd6, 0x9a, 0x5a, 0xeb, 0x07, 0xdd, 0xdc,
            0x01, 0x83, 0xa4, 0xd0, 0xac, 0x9b, 0x54, 0xb0,
            0x51, 0xf2, 0xb1, 0x3e, 0xd9, 0x49, 0x09, 0x75,
            0xea, 0xb7, 0x74, 0x14, 0xff, 0x59, 0xc1, 0xf7,
            0x69, 0x2e, 0x9a, 0x2e, 0x20, 0x2b, 0x38, 0xfc,
            0x91, 0x0a, 0x47, 0x41, 0x74, 0xad, 0xc9, 0x3c,
            0x1f, 0x67, 0xc9, 0x81, 0x02, 0x40, 0x47, 0x1e,
            0x02, 0x90, 0xff, 0x0a, 0xf0, 0x75, 0x03, 0x51,
            0xb7, 0xf8, 0x78, 0x86, 0x4c, 0xa9, 0x61, 0xad,
            0xbd, 0x3a, 0x8a, 0x7e, 0x99, 0x1c, 0x5c, 0x05,
            0x56, 0xa9, 0x4c, 0x31, 0x46, 0xa7, 0xf9, 0x80,
            0x3f, 0x8f, 0x6f, 0x8a, 0xe3, 0x42, 0xe9, 0x31,
            0xfd, 0x8a, 0xe4, 0x7a, 0x22, 0x0d, 0x1b, 0x99,
            0xa4, 0x95, 0x84, 0x98, 0x07, 0xfe, 0x39, 0xf9,
            0x24, 0x5a, 0x98, 0x36, 0xda, 0x3d, 0x02, 0x41,
            0x00, 0xb0, 0x6c, 0x4f, 0xda, 0xbb, 0x63, 0x01,
            0x19, 0x8d, 0x26, 0x5b, 0xdb, 0xae, 0x94, 0x23,
            0xb3, 0x80, 0xf2, 0x71, 0xf7, 0x34, 0x53, 0x88,
            0x50, 0x93, 0x07, 0x7f, 0xcd, 0x39, 0xe2, 0x11,
            0x9f, 0xc9, 0x86, 0x32, 0x15, 0x4f, 0x58, 0x83,
            0xb1, 0x67, 0xa9, 0x67, 0xbf, 0x40, 0x2b, 0x4e,
            0x9e, 0x2e, 0x0f, 0x96, 0x56, 0xe6, 0x98, 0xea,
            0x36, 0x66, 0xed, 0xfb, 0x25, 0x79, 0x80, 0x39,
            0xf7
        };

        private static readonly byte[] output3 = Hex.Decode(
              "b8246b56a6ed5881aeb585d9a25b2ad790c417e080681bf1ac2bc3deb69d8bce"
            + "f0c4366fec400af052a72e9b0effb5b3f2f192dbeaca03c12740057113bf1f06"
            + "69ac22e9f3a7852e3c15d913cab0b8863a95c99294ce8674214954610346f4d4"
            + "74b26f7c48b42ee68e1f572a1fc4026ac456b4f59f7b621ea1b9d88f64202fb1");

        private static readonly byte[] seed = {
            0xaa, 0xfd, 0x12, 0xf6, 0x59,
            0xca, 0xe6, 0x34, 0x89, 0xb4,
            0x79, 0xe5, 0x07, 0x6d, 0xde,
            0xc2, 0xf0, 0x6c, 0xb5, 0x8f
        };

        private class VecRand
            : SecureRandom
        {
            private readonly byte[] seed;

            internal VecRand(byte[] seed)
            {
                this.seed = seed;
            }

            public override void NextBytes(
                byte[] bytes)
            {
                Array.Copy(seed, 0, bytes, 0, bytes.Length);
            }
        }

        private void BaseOaepTest(
            int		id,
            byte[]	pubKeyEnc,
            byte[]	privKeyEnc,
            byte[]	output)
        {
            //
            // extract the public key info.
            //
            Asn1Object pubKeyObj = Asn1Object.FromByteArray(pubKeyEnc);
            RsaPublicKeyStructure pubStruct = RsaPublicKeyStructure.GetInstance(
                SubjectPublicKeyInfo.GetInstance(pubKeyObj).GetPublicKey());

            //
            // extract the private key info.
            //
            Asn1Object privKeyObj = Asn1Object.FromByteArray(privKeyEnc);
            RsaPrivateKeyStructure privStruct = RsaPrivateKeyStructure.GetInstance(
                PrivateKeyInfo.GetInstance(privKeyObj).ParsePrivateKey());

            RsaKeyParameters pubParameters = new RsaKeyParameters(
                false,
                pubStruct.Modulus,
                pubStruct.PublicExponent);

            RsaKeyParameters privParameters = new RsaPrivateCrtKeyParameters(
                privStruct.Modulus,
                privStruct.PublicExponent,
                privStruct.PrivateExponent,
                privStruct.Prime1,
                privStruct.Prime2,
                privStruct.Exponent1,
                privStruct.Exponent2,
                privStruct.Coefficient);

            byte[] input = new byte[] {
                0x54, 0x85, 0x9b, 0x34,
                0x2c, 0x49, 0xea, 0x2a
            };

            EncDec("id(" + id + ")", pubParameters, privParameters, seed, input, output);
        }

        private void EncDec(
            string				label,
            RsaKeyParameters	pubParameters,
            RsaKeyParameters	privParameters,
            byte[]				seed,
            byte[]				input,
            byte[]				output)
        {
            IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine());

            cipher.Init(true, new ParametersWithRandom(pubParameters, new VecRand(seed)));

            byte[] outBytes = cipher.ProcessBlock(input, 0, input.Length);

            for (int i = 0; i != output.Length; i++)
            {
                if (outBytes[i] != output[i])
                {
                    Fail(label + " failed encryption");
                }
            }

            cipher.Init(false, privParameters);

            outBytes = cipher.ProcessBlock(output, 0, output.Length);

            for (int i = 0; i != input.Length; i++)
            {
                if (outBytes[i] != input[i])
                {
                    Fail(label + " failed decoding");
                }
            }
        }

        /*
        * RSA vector tests from PKCS#1 page
        */
        private static readonly byte[] modulus_1024 = Hex.Decode(
              "a8b3b284af8eb50b387034a860f146c4"
            + "919f318763cd6c5598c8ae4811a1e0ab"
            + "c4c7e0b082d693a5e7fced675cf46685"
            + "12772c0cbc64a742c6c630f533c8cc72"
            + "f62ae833c40bf25842e984bb78bdbf97"
            + "c0107d55bdb662f5c4e0fab9845cb514"
            + "8ef7392dd3aaff93ae1e6b667bb3d424"
            + "7616d4f5ba10d4cfd226de88d39f16fb");

        private static readonly byte[] pubExp_1024 = Hex.Decode("010001");

        private static readonly byte[] privExp_1024 = Hex.Decode(
              "53339cfdb79fc8466a655c7316aca85c"
            + "55fd8f6dd898fdaf119517ef4f52e8fd"
            + "8e258df93fee180fa0e4ab29693cd83b"
            + "152a553d4ac4d1812b8b9fa5af0e7f55"
            + "fe7304df41570926f3311f15c4d65a73"
            + "2c483116ee3d3d2d0af3549ad9bf7cbf"
            + "b78ad884f84d5beb04724dc7369b31de"
            + "f37d0cf539e9cfcdd3de653729ead5d1");

        private static readonly byte[] prime1_1024 = Hex.Decode(
              "d32737e7267ffe1341b2d5c0d150a81b"
            + "586fb3132bed2f8d5262864a9cb9f30a"
            + "f38be448598d413a172efb802c21acf1"
            + "c11c520c2f26a471dcad212eac7ca39d");

        private static readonly byte[] prime2_1024 = Hex.Decode(
              "cc8853d1d54da630fac004f471f281c7"
            + "b8982d8224a490edbeb33d3e3d5cc93c"
            + "4765703d1dd791642f1f116a0dd852be"
            + "2419b2af72bfe9a030e860b0288b5d77");

        private static readonly byte[] primeExp1_1024 = Hex.Decode(
              "0e12bf1718e9cef5599ba1c3882fe804"
            + "6a90874eefce8f2ccc20e4f2741fb0a3"
            + "3a3848aec9c9305fbecbd2d76819967d"
            + "4671acc6431e4037968db37878e695c1");

        private static readonly byte[] primeExp2_1024 = Hex.Decode(
              "95297b0f95a2fa67d00707d609dfd4fc"
            + "05c89dafc2ef6d6ea55bec771ea33373"
            + "4d9251e79082ecda866efef13c459e1a"
            + "631386b7e354c899f5f112ca85d71583");

        private static readonly byte[] crtCoef_1024 = Hex.Decode(
              "4f456c502493bdc0ed2ab756a3a6ed4d"
            + "67352a697d4216e93212b127a63d5411"
            + "ce6fa98d5dbefd73263e372814274381"
            + "8166ed7dd63687dd2a8ca1d2f4fbd8e1");

        private static readonly byte[] input_1024_1 = Hex.Decode(
              "6628194e12073db03ba94cda9ef95323"
            + "97d50dba79b987004afefe34");

        private static readonly byte[] seed_1024_1 = Hex.Decode(
              "18b776ea21069d69776a33e96bad48e1"
            + "dda0a5ef");

        private static readonly byte[] output_1024_1 = Hex.Decode(
              "354fe67b4a126d5d35fe36c777791a3f"
            + "7ba13def484e2d3908aff722fad468fb"
            + "21696de95d0be911c2d3174f8afcc201"
            + "035f7b6d8e69402de5451618c21a535f"
            + "a9d7bfc5b8dd9fc243f8cf927db31322"
            + "d6e881eaa91a996170e657a05a266426"
            + "d98c88003f8477c1227094a0d9fa1e8c"
            + "4024309ce1ecccb5210035d47ac72e8a");

        private static readonly byte[] input_1024_2 = Hex.Decode(
              "750c4047f547e8e41411856523298ac9"
            + "bae245efaf1397fbe56f9dd5");

        private static readonly byte[] seed_1024_2 = Hex.Decode(
              "0cc742ce4a9b7f32f951bcb251efd925"
            + "fe4fe35f");

        private static readonly byte[] output_1024_2 = Hex.Decode(
              "640db1acc58e0568fe5407e5f9b701df"
            + "f8c3c91e716c536fc7fcec6cb5b71c11"
            + "65988d4a279e1577d730fc7a29932e3f"
            + "00c81515236d8d8e31017a7a09df4352"
            + "d904cdeb79aa583adcc31ea698a4c052"
            + "83daba9089be5491f67c1a4ee48dc74b"
            + "bbe6643aef846679b4cb395a352d5ed1"
            + "15912df696ffe0702932946d71492b44");

        private static readonly byte[] input_1024_3 = Hex.Decode(
              "d94ae0832e6445ce42331cb06d531a82"
            + "b1db4baad30f746dc916df24d4e3c245"
            + "1fff59a6423eb0e1d02d4fe646cf699d"
            + "fd818c6e97b051");

        private static readonly byte[] seed_1024_3 = Hex.Decode(
              "2514df4695755a67b288eaf4905c36ee"
            + "c66fd2fd");

        private static readonly byte[] output_1024_3 = Hex.Decode(
              "423736ed035f6026af276c35c0b3741b"
            + "365e5f76ca091b4e8c29e2f0befee603"
            + "595aa8322d602d2e625e95eb81b2f1c9"
            + "724e822eca76db8618cf09c5343503a4"
            + "360835b5903bc637e3879fb05e0ef326"
            + "85d5aec5067cd7cc96fe4b2670b6eac3"
            + "066b1fcf5686b68589aafb7d629b02d8"
            + "f8625ca3833624d4800fb081b1cf94eb");

        private static readonly byte[] input_1024_4 = Hex.Decode(
              "52e650d98e7f2a048b4f86852153b97e"
            + "01dd316f346a19f67a85");

        private static readonly byte[] seed_1024_4 = Hex.Decode(
              "c4435a3e1a18a68b6820436290a37cef"
            + "b85db3fb");

        private static readonly byte[] output_1024_4 = Hex.Decode(
              "45ead4ca551e662c9800f1aca8283b05"
            + "25e6abae30be4b4aba762fa40fd3d38e"
            + "22abefc69794f6ebbbc05ddbb1121624"
            + "7d2f412fd0fba87c6e3acd888813646f"
            + "d0e48e785204f9c3f73d6d8239562722"
            + "dddd8771fec48b83a31ee6f592c4cfd4"
            + "bc88174f3b13a112aae3b9f7b80e0fc6"
            + "f7255ba880dc7d8021e22ad6a85f0755");

        private static readonly byte[] input_1024_5 = Hex.Decode(
              "8da89fd9e5f974a29feffb462b49180f"
            + "6cf9e802");

        private static readonly byte[] seed_1024_5 = Hex.Decode(
              "b318c42df3be0f83fea823f5a7b47ed5"
            + "e425a3b5");

        private static readonly byte[] output_1024_5 = Hex.Decode(
              "36f6e34d94a8d34daacba33a2139d00a"
            + "d85a9345a86051e73071620056b920e2"
            + "19005855a213a0f23897cdcd731b4525"
            + "7c777fe908202befdd0b58386b1244ea"
            + "0cf539a05d5d10329da44e13030fd760"
            + "dcd644cfef2094d1910d3f433e1c7c6d"
            + "d18bc1f2df7f643d662fb9dd37ead905"
            + "9190f4fa66ca39e869c4eb449cbdc439");

        private static readonly byte[] input_1024_6 = Hex.Decode("26521050844271");

        private static readonly byte[] seed_1024_6 = Hex.Decode(
              "e4ec0982c2336f3a677f6a356174eb0c"
            + "e887abc2");

        private static readonly byte[] output_1024_6 = Hex.Decode(
              "42cee2617b1ecea4db3f4829386fbd61"
            + "dafbf038e180d837c96366df24c097b4"
            + "ab0fac6bdf590d821c9f10642e681ad0"
            + "5b8d78b378c0f46ce2fad63f74e0ad3d"
            + "f06b075d7eb5f5636f8d403b9059ca76"
            + "1b5c62bb52aa45002ea70baace08ded2"
            + "43b9d8cbd62a68ade265832b56564e43"
            + "a6fa42ed199a099769742df1539e8255");

        private static readonly byte[] modulus_1027 = Hex.Decode(
              "051240b6cc0004fa48d0134671c078c7"
            + "c8dec3b3e2f25bc2564467339db38853"
            + "d06b85eea5b2de353bff42ac2e46bc97"
            + "fae6ac9618da9537a5c8f553c1e35762"
            + "5991d6108dcd7885fb3a25413f53efca"
            + "d948cb35cd9b9ae9c1c67626d113d57d"
            + "de4c5bea76bb5bb7de96c00d07372e96"
            + "85a6d75cf9d239fa148d70931b5f3fb0"
            + "39");

        private static readonly byte[] pubExp_1027 = Hex.Decode("010001");

        private static readonly byte[] privExp_1027 = Hex.Decode(
              "0411ffca3b7ca5e9e9be7fe38a85105e"
            + "353896db05c5796aecd2a725161eb365"
            + "1c8629a9b862b904d7b0c7b37f8cb5a1"
            + "c2b54001018a00a1eb2cafe4ee4e9492"
            + "c348bc2bedab4b9ebbf064e8eff322b9"
            + "009f8eec653905f40df88a3cdc49d456"
            + "7f75627d41aca624129b46a0b7c698e5"
            + "e65f2b7ba102c749a10135b6540d0401");

        private static readonly byte[] prime1_1027 = Hex.Decode(
              "027458c19ec1636919e736c9af25d609"
            + "a51b8f561d19c6bf6943dd1ee1ab8a4a"
            + "3f232100bd40b88decc6ba235548b6ef"
            + "792a11c9de823d0a7922c7095b6eba57"
            + "01");

        private static readonly byte[] prime2_1027 = Hex.Decode(
              "0210ee9b33ab61716e27d251bd465f4b"
            + "35a1a232e2da00901c294bf22350ce49"
            + "0d099f642b5375612db63ba1f2038649"
            + "2bf04d34b3c22bceb909d13441b53b51"
            + "39");

        private static readonly byte[] primeExp1_1027 = Hex.Decode(
              "39fa028b826e88c1121b750a8b242fa9"
            + "a35c5b66bdfd1fa637d3cc48a84a4f45"
            + "7a194e7727e49f7bcc6e5a5a412657fc"
            + "470c7322ebc37416ef458c307a8c0901");

        private static readonly byte[] primeExp2_1027 = Hex.Decode(
              "015d99a84195943979fa9e1be2c3c1b6"
            + "9f432f46fd03e47d5befbbbfd6b1d137"
            + "1d83efb330a3e020942b2fed115e5d02"
            + "be24fd92c9019d1cecd6dd4cf1e54cc8"
            + "99");

        private static readonly byte[] crtCoef_1027 = Hex.Decode(
              "01f0b7015170b3f5e42223ba30301c41"
            + "a6d87cbb70e30cb7d3c67d25473db1f6"
            + "cbf03e3f9126e3e97968279a865b2c2b"
            + "426524cfc52a683d31ed30eb984be412"
            + "ba");

        private static readonly byte[] input_1027_1 = Hex.Decode(
              "4a86609534ee434a6cbca3f7e962e76d"
            + "455e3264c19f605f6e5ff6137c65c56d"
            + "7fb344cd52bc93374f3d166c9f0c6f9c"
            + "506bad19330972d2");

        private static readonly byte[] seed_1027_1 = Hex.Decode(
              "1cac19ce993def55f98203f6852896c9"
            + "5ccca1f3");

        private static readonly byte[] output_1027_1 = Hex.Decode(
              "04cce19614845e094152a3fe18e54e33"
            + "30c44e5efbc64ae16886cb1869014cc5"
            + "781b1f8f9e045384d0112a135ca0d12e"
            + "9c88a8e4063416deaae3844f60d6e96f"
            + "e155145f4525b9a34431ca3766180f70"
            + "e15a5e5d8e8b1a516ff870609f13f896"
            + "935ced188279a58ed13d07114277d75c"
            + "6568607e0ab092fd803a223e4a8ee0b1"
            + "a8");

        private static readonly byte[] input_1027_2 = Hex.Decode(
              "b0adc4f3fe11da59ce992773d9059943"
            + "c03046497ee9d9f9a06df1166db46d98"
            + "f58d27ec074c02eee6cbe2449c8b9fc5"
            + "080c5c3f4433092512ec46aa793743c8");

        private static readonly byte[] seed_1027_2 = Hex.Decode(
              "f545d5897585e3db71aa0cb8da76c51d"
            + "032ae963");

        private static readonly byte[] output_1027_2 = Hex.Decode(
              "0097b698c6165645b303486fbf5a2a44"
            + "79c0ee85889b541a6f0b858d6b6597b1"
            + "3b854eb4f839af03399a80d79bda6578"
            + "c841f90d645715b280d37143992dd186"
            + "c80b949b775cae97370e4ec97443136c"
            + "6da484e970ffdb1323a20847821d3b18"
            + "381de13bb49aaea66530c4a4b8271f3e"
            + "ae172cd366e07e6636f1019d2a28aed1"
            + "5e");

        private static readonly byte[] input_1027_3 = Hex.Decode(
              "bf6d42e701707b1d0206b0c8b45a1c72"
            + "641ff12889219a82bdea965b5e79a96b"
            + "0d0163ed9d578ec9ada20f2fbcf1ea3c"
            + "4089d83419ba81b0c60f3606da99");

        private static readonly byte[] seed_1027_3 = Hex.Decode(
              "ad997feef730d6ea7be60d0dc52e72ea"
            + "cbfdd275");

        private static readonly byte[] output_1027_3 = Hex.Decode(
              "0301f935e9c47abcb48acbbe09895d9f"
            + "5971af14839da4ff95417ee453d1fd77"
            + "319072bb7297e1b55d7561cd9d1bb24c"
            + "1a9a37c619864308242804879d86ebd0"
            + "01dce5183975e1506989b70e5a834341"
            + "54d5cbfd6a24787e60eb0c658d2ac193"
            + "302d1192c6e622d4a12ad4b53923bca2"
            + "46df31c6395e37702c6a78ae081fb9d0"
            + "65");

        private static readonly byte[] input_1027_4 = Hex.Decode(
              "fb2ef112f5e766eb94019297934794f7"
            + "be2f6fc1c58e");

        private static readonly byte[] seed_1027_4 = Hex.Decode(
              "136454df5730f73c807a7e40d8c1a312"
            + "ac5b9dd3");

        private static readonly byte[] output_1027_4 = Hex.Decode(
              "02d110ad30afb727beb691dd0cf17d0a"
            + "f1a1e7fa0cc040ec1a4ba26a42c59d0a"
            + "796a2e22c8f357ccc98b6519aceb682e"
            + "945e62cb734614a529407cd452bee3e4"
            + "4fece8423cc19e55548b8b994b849c7e"
            + "cde4933e76037e1d0ce44275b08710c6"
            + "8e430130b929730ed77e09b015642c55"
            + "93f04e4ffb9410798102a8e96ffdfe11"
            + "e4");

        private static readonly byte[] input_1027_5 = Hex.Decode(
              "28ccd447bb9e85166dabb9e5b7d1adad"
            + "c4b9d39f204e96d5e440ce9ad928bc1c"
            + "2284");

        private static readonly byte[] seed_1027_5 = Hex.Decode(
              "bca8057f824b2ea257f2861407eef63d"
            + "33208681");

        private static readonly byte[] output_1027_5 = Hex.Decode(
              "00dbb8a7439d90efd919a377c54fae8f"
            + "e11ec58c3b858362e23ad1b8a4431079"
            + "9066b99347aa525691d2adc58d9b06e3"
            + "4f288c170390c5f0e11c0aa3645959f1"
            + "8ee79e8f2be8d7ac5c23d061f18dd74b"
            + "8c5f2a58fcb5eb0c54f99f01a8324756"
            + "8292536583340948d7a8c97c4acd1e98"
            + "d1e29dc320e97a260532a8aa7a758a1e"
            + "c2");

        private static readonly byte[] input_1027_6 = Hex.Decode("f22242751ec6b1");

        private static readonly byte[] seed_1027_6 = Hex.Decode(
              "2e7e1e17f647b5ddd033e15472f90f68"
            + "12f3ac4e");

        private static readonly byte[] output_1027_6 = Hex.Decode(
              "00a5ffa4768c8bbecaee2db77e8f2eec"
            + "99595933545520835e5ba7db9493d3e1"
            + "7cddefe6a5f567624471908db4e2d83a"
            + "0fbee60608fc84049503b2234a07dc83"
            + "b27b22847ad8920ff42f674ef79b7628"
            + "0b00233d2b51b8cb2703a9d42bfbc825"
            + "0c96ec32c051e57f1b4ba528db89c37e"
            + "4c54e27e6e64ac69635ae887d9541619"
            + "a9");

        private void OaepVecTest(
            int					keySize,
            int					no,
            RsaKeyParameters	pubParam,
            RsaKeyParameters	privParam,
            byte[]				seed,
            byte[]				input,
            byte[]				output)
        {
            EncDec(keySize + " " + no, pubParam, privParam, seed, input, output);
        }

        public override string Name
        {
            get { return "OAEP"; }
        }

        public override void PerformTest()
        {
            BaseOaepTest(1, pubKeyEnc1, privKeyEnc1, output1);
            BaseOaepTest(2, pubKeyEnc2, privKeyEnc2, output2);
            BaseOaepTest(3, pubKeyEnc3, privKeyEnc3, output3);

            RsaKeyParameters pubParam = new RsaKeyParameters(
                false,
                new BigInteger(1, modulus_1024),
                new BigInteger(1, pubExp_1024));
            RsaKeyParameters privParam = new RsaPrivateCrtKeyParameters(
                pubParam.Modulus,
                pubParam.Exponent,
                new BigInteger(1, privExp_1024),
                new BigInteger(1, prime1_1024),
                new BigInteger(1, prime2_1024),
                new BigInteger(1, primeExp1_1024),
                new BigInteger(1, primeExp2_1024),
                new BigInteger(1, crtCoef_1024));

            OaepVecTest(1024, 1, pubParam, privParam, seed_1024_1, input_1024_1, output_1024_1);
            OaepVecTest(1024, 2, pubParam, privParam, seed_1024_2, input_1024_2, output_1024_2);
            OaepVecTest(1024, 3, pubParam, privParam, seed_1024_3, input_1024_3, output_1024_3);
            OaepVecTest(1024, 4, pubParam, privParam, seed_1024_4, input_1024_4, output_1024_4);
            OaepVecTest(1024, 5, pubParam, privParam, seed_1024_5, input_1024_5, output_1024_5);
            OaepVecTest(1024, 6, pubParam, privParam, seed_1024_6, input_1024_6, output_1024_6);

            pubParam = new RsaKeyParameters(
                false,
                new BigInteger(1, modulus_1027),
                new BigInteger(1, pubExp_1027));
            privParam = new RsaPrivateCrtKeyParameters(
                pubParam.Modulus,
                pubParam.Exponent,
                new BigInteger(1, privExp_1027),
                new BigInteger(1, prime1_1027),
                new BigInteger(1, prime2_1027),
                new BigInteger(1, primeExp1_1027),
                new BigInteger(1, primeExp2_1027),
                new BigInteger(1, crtCoef_1027));

            OaepVecTest(1027, 1, pubParam, privParam, seed_1027_1, input_1027_1, output_1027_1);
            OaepVecTest(1027, 2, pubParam, privParam, seed_1027_2, input_1027_2, output_1027_2);
            OaepVecTest(1027, 3, pubParam, privParam, seed_1027_3, input_1027_3, output_1027_3);
            OaepVecTest(1027, 4, pubParam, privParam, seed_1027_4, input_1027_4, output_1027_4);
            OaepVecTest(1027, 5, pubParam, privParam, seed_1027_5, input_1027_5, output_1027_5);
            OaepVecTest(1027, 6, pubParam, privParam, seed_1027_6, input_1027_6, output_1027_6);

            TestForHighByteError("invalidCiphertextOaepTest 1024", 1024);

            //
            // OAEP - public encrypt, private decrypt, differing hashes
            //
            IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine(), new Sha256Digest(), new Sha1Digest(), new byte[10]);

            cipher.Init(true, new ParametersWithRandom(pubParam, new SecureRandom()));

            byte[] input = new byte[10];

            byte[] output = cipher.ProcessBlock(input, 0, input.Length);

            cipher.Init(false, privParam);

            output = cipher.ProcessBlock(output, 0, output.Length);

            for (int i = 0; i != input.Length; i++)
            {
                if (output[i] != input[i])
                {
                    Fail("mixed digest failed decoding");
                }
            }

            cipher = new OaepEncoding(new RsaEngine(), new Sha1Digest(), new Sha256Digest(), new byte[10]);

            cipher.Init(true, new ParametersWithRandom(pubParam, new SecureRandom()));

            output = cipher.ProcessBlock(input, 0, input.Length);

            cipher.Init(false, privParam);

            output = cipher.ProcessBlock(output, 0, output.Length);

            for (int i = 0; i != input.Length; i++)
            {
                if (output[i] != input[i])
                {
                    Fail("mixed digest failed decoding");
                }
            }
        }

        private void TestForHighByteError(string label, int keySizeBits)
        {
            // draw a key of the size asked
            BigInteger e = BigInteger.One.ShiftLeft(16).Add(BigInteger.One);

            IAsymmetricCipherKeyPairGenerator kpGen = new RsaKeyPairGenerator();

            kpGen.Init(new RsaKeyGenerationParameters(e, new SecureRandom(), keySizeBits, 100));

            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine());

            // obtain a known good ciphertext
            cipher.Init(true, new ParametersWithRandom(kp.Public, new VecRand(seed)));
            byte[] m = { 42 };
            byte[] c = cipher.ProcessBlock(m, 0, m.Length);
            int keySizeBytes = (keySizeBits + 7) / 8;
            if (c.Length != keySizeBytes)
            {
                Fail(label + " failed ciphertext size");
            }

            BigInteger n = ((RsaPrivateCrtKeyParameters)kp.Private).Modulus;

            // decipher
            cipher.Init(false, kp.Private);
            byte[] r = cipher.ProcessBlock(c, 0, keySizeBytes);
            if (r.Length != 1 || r[0] != 42)
            {
                Fail(label + " failed first decryption of test message");
            }

            // decipher again
            r = cipher.ProcessBlock(c, 0, keySizeBytes);
            if (r.Length != 1 || r[0] != 42)
            {
                Fail(label + " failed second decryption of test message");
            }

            // check hapazard incorrect ciphertexts
            for (int i = keySizeBytes * 8; --i >= 0; )
            {
                c[i / 8] ^= (byte)(1 << (i & 7));
                bool ko = true;
                try
                {
                    BigInteger cV = new BigInteger(1, c);

                    // don't pass in c if it will be rejected trivially
                    if (cV.CompareTo(n) < 0)
                    {
                        r = cipher.ProcessBlock(c, 0, keySizeBytes);
                    }
                    else
                    {
                        ko = false; // size errors are picked up at start
                    }
                }
                catch (InvalidCipherTextException)
                {
                    ko = false;
                }
                if (ko)
                {
                    Fail(label + " invalid ciphertext caused no exception");
                }
                c[i / 8] ^= (byte)(1 << (i & 7));
            }
        }

        public static void MainOld(string[] args)
        {
            RunTest(new OaepTest());
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
