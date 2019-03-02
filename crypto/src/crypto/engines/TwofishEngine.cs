using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    /**
    * A class that provides Twofish encryption operations.
    *
    * This Java implementation is based on the Java reference
    * implementation provided by Bruce Schneier and developed
    * by Raif S. Naffah.
    */
    public sealed class TwofishEngine
		: IBlockCipher
    {
        private static readonly byte[,] P =  {
        {  // p0
             0xA9,  0x67,  0xB3,  0xE8,
             0x04,  0xFD,  0xA3,  0x76,
             0x9A,  0x92,  0x80,  0x78,
             0xE4,  0xDD,  0xD1,  0x38,
             0x0D,  0xC6,  0x35,  0x98,
             0x18,  0xF7,  0xEC,  0x6C,
             0x43,  0x75,  0x37,  0x26,
             0xFA,  0x13,  0x94,  0x48,
             0xF2,  0xD0,  0x8B,  0x30,
             0x84,  0x54,  0xDF,  0x23,
             0x19,  0x5B,  0x3D,  0x59,
             0xF3,  0xAE,  0xA2,  0x82,
             0x63,  0x01,  0x83,  0x2E,
             0xD9,  0x51,  0x9B,  0x7C,
             0xA6,  0xEB,  0xA5,  0xBE,
             0x16,  0x0C,  0xE3,  0x61,
             0xC0,  0x8C,  0x3A,  0xF5,
             0x73,  0x2C,  0x25,  0x0B,
             0xBB,  0x4E,  0x89,  0x6B,
             0x53,  0x6A,  0xB4,  0xF1,
             0xE1,  0xE6,  0xBD,  0x45,
             0xE2,  0xF4,  0xB6,  0x66,
             0xCC,  0x95,  0x03,  0x56,
             0xD4,  0x1C,  0x1E,  0xD7,
             0xFB,  0xC3,  0x8E,  0xB5,
             0xE9,  0xCF,  0xBF,  0xBA,
             0xEA,  0x77,  0x39,  0xAF,
             0x33,  0xC9,  0x62,  0x71,
             0x81,  0x79,  0x09,  0xAD,
             0x24,  0xCD,  0xF9,  0xD8,
             0xE5,  0xC5,  0xB9,  0x4D,
             0x44,  0x08,  0x86,  0xE7,
             0xA1,  0x1D,  0xAA,  0xED,
             0x06,  0x70,  0xB2,  0xD2,
             0x41,  0x7B,  0xA0,  0x11,
             0x31,  0xC2,  0x27,  0x90,
             0x20,  0xF6,  0x60,  0xFF,
             0x96,  0x5C,  0xB1,  0xAB,
             0x9E,  0x9C,  0x52,  0x1B,
             0x5F,  0x93,  0x0A,  0xEF,
             0x91,  0x85,  0x49,  0xEE,
             0x2D,  0x4F,  0x8F,  0x3B,
             0x47,  0x87,  0x6D,  0x46,
             0xD6,  0x3E,  0x69,  0x64,
             0x2A,  0xCE,  0xCB,  0x2F,
             0xFC,  0x97,  0x05,  0x7A,
             0xAC,  0x7F,  0xD5,  0x1A,
             0x4B,  0x0E,  0xA7,  0x5A,
             0x28,  0x14,  0x3F,  0x29,
             0x88,  0x3C,  0x4C,  0x02,
             0xB8,  0xDA,  0xB0,  0x17,
             0x55,  0x1F,  0x8A,  0x7D,
             0x57,  0xC7,  0x8D,  0x74,
             0xB7,  0xC4,  0x9F,  0x72,
             0x7E,  0x15,  0x22,  0x12,
             0x58,  0x07,  0x99,  0x34,
             0x6E,  0x50,  0xDE,  0x68,
             0x65,  0xBC,  0xDB,  0xF8,
             0xC8,  0xA8,  0x2B,  0x40,
             0xDC,  0xFE,  0x32,  0xA4,
             0xCA,  0x10,  0x21,  0xF0,
             0xD3,  0x5D,  0x0F,  0x00,
             0x6F,  0x9D,  0x36,  0x42,
             0x4A,  0x5E,  0xC1,  0xE0 },
        {  // p1
             0x75,  0xF3,  0xC6,  0xF4,
             0xDB,  0x7B,  0xFB,  0xC8,
             0x4A,  0xD3,  0xE6,  0x6B,
             0x45,  0x7D,  0xE8,  0x4B,
             0xD6,  0x32,  0xD8,  0xFD,
             0x37,  0x71,  0xF1,  0xE1,
             0x30,  0x0F,  0xF8,  0x1B,
             0x87,  0xFA,  0x06,  0x3F,
             0x5E,  0xBA,  0xAE,  0x5B,
             0x8A,  0x00,  0xBC,  0x9D,
             0x6D,  0xC1,  0xB1,  0x0E,
             0x80,  0x5D,  0xD2,  0xD5,
             0xA0,  0x84,  0x07,  0x14,
             0xB5,  0x90,  0x2C,  0xA3,
             0xB2,  0x73,  0x4C,  0x54,
             0x92,  0x74,  0x36,  0x51,
             0x38,  0xB0,  0xBD,  0x5A,
             0xFC,  0x60,  0x62,  0x96,
             0x6C,  0x42,  0xF7,  0x10,
             0x7C,  0x28,  0x27,  0x8C,
             0x13,  0x95,  0x9C,  0xC7,
             0x24,  0x46,  0x3B,  0x70,
             0xCA,  0xE3,  0x85,  0xCB,
             0x11,  0xD0,  0x93,  0xB8,
             0xA6,  0x83,  0x20,  0xFF,
             0x9F,  0x77,  0xC3,  0xCC,
             0x03,  0x6F,  0x08,  0xBF,
             0x40,  0xE7,  0x2B,  0xE2,
             0x79,  0x0C,  0xAA,  0x82,
             0x41,  0x3A,  0xEA,  0xB9,
             0xE4,  0x9A,  0xA4,  0x97,
             0x7E,  0xDA,  0x7A,  0x17,
             0x66,  0x94,  0xA1,  0x1D,
             0x3D,  0xF0,  0xDE,  0xB3,
             0x0B,  0x72,  0xA7,  0x1C,
             0xEF,  0xD1,  0x53,  0x3E,
             0x8F,  0x33,  0x26,  0x5F,
             0xEC,  0x76,  0x2A,  0x49,
             0x81,  0x88,  0xEE,  0x21,
             0xC4,  0x1A,  0xEB,  0xD9,
             0xC5,  0x39,  0x99,  0xCD,
             0xAD,  0x31,  0x8B,  0x01,
             0x18,  0x23,  0xDD,  0x1F,
             0x4E,  0x2D,  0xF9,  0x48,
             0x4F,  0xF2,  0x65,  0x8E,
             0x78,  0x5C,  0x58,  0x19,
             0x8D,  0xE5,  0x98,  0x57,
             0x67,  0x7F,  0x05,  0x64,
             0xAF,  0x63,  0xB6,  0xFE,
             0xF5,  0xB7,  0x3C,  0xA5,
             0xCE,  0xE9,  0x68,  0x44,
             0xE0,  0x4D,  0x43,  0x69,
             0x29,  0x2E,  0xAC,  0x15,
             0x59,  0xA8,  0x0A,  0x9E,
             0x6E,  0x47,  0xDF,  0x34,
             0x35,  0x6A,  0xCF,  0xDC,
             0x22,  0xC9,  0xC0,  0x9B,
             0x89,  0xD4,  0xED,  0xAB,
             0x12,  0xA2,  0x0D,  0x52,
             0xBB,  0x02,  0x2F,  0xA9,
             0xD7,  0x61,  0x1E,  0xB4,
             0x50,  0x04,  0xF6,  0xC2,
             0x16,  0x25,  0x86,  0x56,
             0x55,  0x09,  0xBE,  0x91  }
        };

        /**
        * Define the fixed p0/p1 permutations used in keyed S-box lookup.
        * By changing the following constant definitions, the S-boxes will
        * automatically Get changed in the Twofish engine.
        */
        private const int P_00 = 1;
        private const int P_01 = 0;
        private const int P_02 = 0;
        private const int P_03 = P_01 ^ 1;
        private const int P_04 = 1;

        private const int P_10 = 0;
        private const int P_11 = 0;
        private const int P_12 = 1;
        private const int P_13 = P_11 ^ 1;
        private const int P_14 = 0;

        private const int P_20 = 1;
        private const int P_21 = 1;
        private const int P_22 = 0;
        private const int P_23 = P_21 ^ 1;
        private const int P_24 = 0;

        private const int P_30 = 0;
        private const int P_31 = 1;
        private const int P_32 = 1;
        private const int P_33 = P_31 ^ 1;
        private const int P_34 = 1;

        /* Primitive polynomial for GF(256) */
        private const int GF256_FDBK = 0x169;
        private const int GF256_FDBK_2 = GF256_FDBK / 2;
        private const int GF256_FDBK_4 = GF256_FDBK / 4;

        private const int RS_GF_FDBK = 0x14D; // field generator

        //====================================
        // Useful constants
        //====================================

        private const int    ROUNDS = 16;
        private const int    MAX_ROUNDS = 16;  // bytes = 128 bits
        private const int    BLOCK_SIZE = 16;  // bytes = 128 bits
        private const int    MAX_KEY_BITS = 256;

        private const int    INPUT_WHITEN=0;
        private const int    OUTPUT_WHITEN=INPUT_WHITEN+BLOCK_SIZE/4; // 4
        private const int    ROUND_SUBKEYS=OUTPUT_WHITEN+BLOCK_SIZE/4;// 8

        private const int    TOTAL_SUBKEYS=ROUND_SUBKEYS+2*MAX_ROUNDS;// 40

        private const int    SK_STEP = 0x02020202;
        private const int    SK_BUMP = 0x01010101;
        private const int    SK_ROTL = 9;

        private bool encrypting;

        private int[] gMDS0 = new int[MAX_KEY_BITS];
        private int[] gMDS1 = new int[MAX_KEY_BITS];
        private int[] gMDS2 = new int[MAX_KEY_BITS];
        private int[] gMDS3 = new int[MAX_KEY_BITS];

        /**
        * gSubKeys[] and gSBox[] are eventually used in the
        * encryption and decryption methods.
        */
        private int[] gSubKeys;
        private int[] gSBox;

        private int k64Cnt;

        private byte[] workingKey;

        public TwofishEngine()
        {
            // calculate the MDS matrix
            int[] m1 = new int[2];
            int[] mX = new int[2];
            int[] mY = new int[2];
            int j;

            for (int i=0; i< MAX_KEY_BITS ; i++)
            {
                j = P[0,i] & 0xff;
                m1[0] = j;
                mX[0] = Mx_X(j) & 0xff;
                mY[0] = Mx_Y(j) & 0xff;

                j = P[1,i] & 0xff;
                m1[1] = j;
                mX[1] = Mx_X(j) & 0xff;
                mY[1] = Mx_Y(j) & 0xff;

                gMDS0[i] = m1[P_00]       | mX[P_00] <<  8 |
                            mY[P_00] << 16 | mY[P_00] << 24;

                gMDS1[i] = mY[P_10]       | mY[P_10] <<  8 |
                            mX[P_10] << 16 | m1[P_10] << 24;

                gMDS2[i] = mX[P_20]       | mY[P_20] <<  8 |
                            m1[P_20] << 16 | mY[P_20] << 24;

                gMDS3[i] = mX[P_30]       | m1[P_30] <<  8 |
                            mY[P_30] << 16 | mX[P_30] << 24;
            }
        }

        /**
        * initialise a Twofish cipher.
        *
        * @param forEncryption whether or not we are for encryption.
        * @param parameters the parameters required to set up the cipher.
        * @exception ArgumentException if the parameters argument is
        * inappropriate.
        */
        public void Init(
            bool              forEncryption,
            ICipherParameters parameters)
        {
            if (!(parameters is KeyParameter))
				throw new ArgumentException("invalid parameter passed to Twofish init - " + Platform.GetTypeName(parameters));

			this.encrypting = forEncryption;
			this.workingKey = ((KeyParameter)parameters).GetKey();
			this.k64Cnt = (this.workingKey.Length / 8); // pre-padded ?
			SetKey(this.workingKey);
        }

		public string AlgorithmName
        {
            get { return "Twofish"; }
        }

		public bool IsPartialBlockOkay
		{
			get { return false; }
		}

		public int ProcessBlock(
            byte[]	input,
            int		inOff,
            byte[]	output,
            int		outOff)
        {
            if (workingKey == null)
                throw new InvalidOperationException("Twofish not initialised");

            Check.DataLength(input, inOff, BLOCK_SIZE, "input buffer too short");
            Check.OutputLength(output, outOff, BLOCK_SIZE, "output buffer too short");

            if (encrypting)
            {
                EncryptBlock(input, inOff, output, outOff);
            }
            else
            {
                DecryptBlock(input, inOff, output, outOff);
            }

            return BLOCK_SIZE;
        }

        public void Reset()
        {
            if (this.workingKey != null)
            {
                SetKey(this.workingKey);
            }
        }

        public int GetBlockSize()
        {
            return BLOCK_SIZE;
        }

        //==================================
        // Private Implementation
        //==================================

        private void SetKey(byte[] key)
        {
            int[] k32e = new int[MAX_KEY_BITS/64]; // 4
            int[] k32o = new int[MAX_KEY_BITS/64]; // 4

            int[] sBoxKeys = new int[MAX_KEY_BITS/64]; // 4
            gSubKeys = new int[TOTAL_SUBKEYS];

            if (k64Cnt < 1)
            {
                throw new ArgumentException("Key size less than 64 bits");
            }

            if (k64Cnt > 4)
            {
                throw new ArgumentException("Key size larger than 256 bits");
            }

            /*
            * k64Cnt is the number of 8 byte blocks (64 chunks)
            * that are in the input key.  The input key is a
            * maximum of 32 bytes ( 256 bits ), so the range
            * for k64Cnt is 1..4
            */
            for (int i=0,p=0; i<k64Cnt ; i++)
            {
                p = i* 8;

                k32e[i] = BytesTo32Bits(key, p);
                k32o[i] = BytesTo32Bits(key, p+4);

                sBoxKeys[k64Cnt-1-i] = RS_MDS_Encode(k32e[i], k32o[i]);
            }

            int q,A,B;
            for (int i=0; i < TOTAL_SUBKEYS / 2 ; i++)
            {
                q = i*SK_STEP;
                A = F32(q,         k32e);
                B = F32(q+SK_BUMP, k32o);
                B = B << 8 | (int)((uint)B >> 24);
                A += B;
                gSubKeys[i*2] = A;
                A += B;
                gSubKeys[i*2 + 1] = A << SK_ROTL | (int)((uint)A >> (32-SK_ROTL));
            }

            /*
            * fully expand the table for speed
            */
            int k0 = sBoxKeys[0];
            int k1 = sBoxKeys[1];
            int k2 = sBoxKeys[2];
            int k3 = sBoxKeys[3];
            int b0, b1, b2, b3;
            gSBox = new int[4*MAX_KEY_BITS];
            for (int i=0; i<MAX_KEY_BITS; i++)
            {
                b0 = b1 = b2 = b3 = i;
                switch (k64Cnt & 3)
                {
                    case 1:
                        gSBox[i*2]       = gMDS0[(P[P_01,b0] & 0xff) ^ M_b0(k0)];
                        gSBox[i*2+1]     = gMDS1[(P[P_11,b1] & 0xff) ^ M_b1(k0)];
                        gSBox[i*2+0x200] = gMDS2[(P[P_21,b2] & 0xff) ^ M_b2(k0)];
                        gSBox[i*2+0x201] = gMDS3[(P[P_31,b3] & 0xff) ^ M_b3(k0)];
                    break;
                    case 0: // 256 bits of key
                        b0 = (P[P_04,b0] & 0xff) ^ M_b0(k3);
                        b1 = (P[P_14,b1] & 0xff) ^ M_b1(k3);
                        b2 = (P[P_24,b2] & 0xff) ^ M_b2(k3);
                        b3 = (P[P_34,b3] & 0xff) ^ M_b3(k3);
                        // fall through, having pre-processed b[0]..b[3] with k32[3]
                        goto case 3;
                    case 3: // 192 bits of key
                        b0 = (P[P_03,b0] & 0xff) ^ M_b0(k2);
                        b1 = (P[P_13,b1] & 0xff) ^ M_b1(k2);
                        b2 = (P[P_23,b2] & 0xff) ^ M_b2(k2);
                        b3 = (P[P_33,b3] & 0xff) ^ M_b3(k2);
                        // fall through, having pre-processed b[0]..b[3] with k32[2]
                        goto case 2;
                    case 2: // 128 bits of key
                        gSBox[i * 2] = gMDS0[(P[P_01, (P[P_02, b0] & 0xff) ^ M_b0(k1)] & 0xff) ^ M_b0(k0)];
                        gSBox[i*2+1] = gMDS1[(P[P_11,(P[P_12,b1] & 0xff) ^ M_b1(k1)] & 0xff) ^ M_b1(k0)];
                        gSBox[i*2+0x200] = gMDS2[(P[P_21,(P[P_22,b2] & 0xff) ^ M_b2(k1)] & 0xff) ^ M_b2(k0)];
                        gSBox[i * 2 + 0x201] = gMDS3[(P[P_31, (P[P_32, b3] & 0xff) ^ M_b3(k1)] & 0xff) ^ M_b3(k0)];
                        break;
                }
            }

            /*
            * the function exits having setup the gSBox with the
            * input key material.
            */
        }

        /**
        * Encrypt the given input starting at the given offset and place
        * the result in the provided buffer starting at the given offset.
        * The input will be an exact multiple of our blocksize.
        *
        * encryptBlock uses the pre-calculated gSBox[] and subKey[]
        * arrays.
        */
        private void EncryptBlock(
            byte[] src,
            int srcIndex,
            byte[] dst,
            int dstIndex)
        {
            int x0 = BytesTo32Bits(src, srcIndex) ^ gSubKeys[INPUT_WHITEN];
            int x1 = BytesTo32Bits(src, srcIndex + 4) ^ gSubKeys[INPUT_WHITEN + 1];
            int x2 = BytesTo32Bits(src, srcIndex + 8) ^ gSubKeys[INPUT_WHITEN + 2];
            int x3 = BytesTo32Bits(src, srcIndex + 12) ^ gSubKeys[INPUT_WHITEN + 3];

            int k = ROUND_SUBKEYS;
            int t0, t1;
            for (int r = 0; r < ROUNDS; r +=2)
            {
                t0 = Fe32_0(x0);
                t1 = Fe32_3(x1);
                x2 ^= t0 + t1 + gSubKeys[k++];
                x2 = (int)((uint)x2 >>1) | x2 << 31;
                x3 = (x3 << 1 | (int) ((uint)x3 >> 31)) ^ (t0 + 2*t1 + gSubKeys[k++]);

                t0 = Fe32_0(x2);
                t1 = Fe32_3(x3);
                x0 ^= t0 + t1 + gSubKeys[k++];
                x0 = (int) ((uint)x0 >>1) | x0 << 31;
                x1 = (x1 << 1 | (int)((uint)x1 >> 31)) ^ (t0 + 2*t1 + gSubKeys[k++]);
            }

            Bits32ToBytes(x2 ^ gSubKeys[OUTPUT_WHITEN], dst, dstIndex);
            Bits32ToBytes(x3 ^ gSubKeys[OUTPUT_WHITEN + 1], dst, dstIndex + 4);
            Bits32ToBytes(x0 ^ gSubKeys[OUTPUT_WHITEN + 2], dst, dstIndex + 8);
            Bits32ToBytes(x1 ^ gSubKeys[OUTPUT_WHITEN + 3], dst, dstIndex + 12);
        }

        /**
        * Decrypt the given input starting at the given offset and place
        * the result in the provided buffer starting at the given offset.
        * The input will be an exact multiple of our blocksize.
        */
        private void DecryptBlock(
            byte[] src,
            int srcIndex,
            byte[] dst,
            int dstIndex)
        {
            int x2 = BytesTo32Bits(src, srcIndex) ^ gSubKeys[OUTPUT_WHITEN];
            int x3 = BytesTo32Bits(src, srcIndex+4) ^ gSubKeys[OUTPUT_WHITEN + 1];
            int x0 = BytesTo32Bits(src, srcIndex+8) ^ gSubKeys[OUTPUT_WHITEN + 2];
            int x1 = BytesTo32Bits(src, srcIndex+12) ^ gSubKeys[OUTPUT_WHITEN + 3];

            int k = ROUND_SUBKEYS + 2 * ROUNDS -1 ;
            int t0, t1;
            for (int r = 0; r< ROUNDS ; r +=2)
            {
                t0 = Fe32_0(x2);
                t1 = Fe32_3(x3);
                x1 ^= t0 + 2*t1 + gSubKeys[k--];
                x0 = (x0 << 1 | (int)((uint) x0 >> 31)) ^ (t0 + t1 + gSubKeys[k--]);
                x1 = (int) ((uint)x1 >>1) | x1 << 31;

                t0 = Fe32_0(x0);
                t1 = Fe32_3(x1);
                x3 ^= t0 + 2*t1 + gSubKeys[k--];
                x2 = (x2 << 1 | (int)((uint)x2 >> 31)) ^ (t0 + t1 + gSubKeys[k--]);
                x3 = (int)((uint)x3 >>1) | x3 << 31;
            }

            Bits32ToBytes(x0 ^ gSubKeys[INPUT_WHITEN], dst, dstIndex);
            Bits32ToBytes(x1 ^ gSubKeys[INPUT_WHITEN + 1], dst, dstIndex + 4);
            Bits32ToBytes(x2 ^ gSubKeys[INPUT_WHITEN + 2], dst, dstIndex + 8);
            Bits32ToBytes(x3 ^ gSubKeys[INPUT_WHITEN + 3], dst, dstIndex + 12);
        }

        /*
        * TODO:  This can be optimised and made cleaner by combining
        * the functionality in this function and applying it appropriately
        * to the creation of the subkeys during key setup.
        */
        private  int F32(int x, int[] k32)
        {
            int b0 = M_b0(x);
            int b1 = M_b1(x);
            int b2 = M_b2(x);
            int b3 = M_b3(x);
            int k0 = k32[0];
            int k1 = k32[1];
            int k2 = k32[2];
            int k3 = k32[3];

            int result = 0;
            switch (k64Cnt & 3)
            {
                case 1:
                    result = gMDS0[(P[P_01,b0] & 0xff) ^ M_b0(k0)] ^
                            gMDS1[(P[P_11,b1] & 0xff) ^ M_b1(k0)] ^
                            gMDS2[(P[P_21,b2] & 0xff) ^ M_b2(k0)] ^
                            gMDS3[(P[P_31,b3] & 0xff) ^ M_b3(k0)];
                    break;
                case 0: /* 256 bits of key */
                    b0 = (P[P_04,b0] & 0xff) ^ M_b0(k3);
                    b1 = (P[P_14,b1] & 0xff) ^ M_b1(k3);
                    b2 = (P[P_24,b2] & 0xff) ^ M_b2(k3);
                    b3 = (P[P_34,b3] & 0xff) ^ M_b3(k3);
                    goto case 3;
                case 3:
                    b0 = (P[P_03,b0] & 0xff) ^ M_b0(k2);
                    b1 = (P[P_13,b1] & 0xff) ^ M_b1(k2);
                    b2 = (P[P_23,b2] & 0xff) ^ M_b2(k2);
                    b3 = (P[P_33,b3] & 0xff) ^ M_b3(k2);
                    goto case 2;
                case 2:
                    result =
                    gMDS0[(P[P_01,(P[P_02,b0]&0xff)^M_b0(k1)]&0xff)^M_b0(k0)] ^
                    gMDS1[(P[P_11,(P[P_12,b1]&0xff)^M_b1(k1)]&0xff)^M_b1(k0)] ^
                    gMDS2[(P[P_21,(P[P_22,b2]&0xff)^M_b2(k1)]&0xff)^M_b2(k0)] ^
                    gMDS3[(P[P_31,(P[P_32,b3]&0xff)^M_b3(k1)]&0xff)^M_b3(k0)];
                break;
            }
            return result;
        }

        /**
        * Use (12, 8) Reed-Solomon code over GF(256) to produce
        * a key S-box 32-bit entity from 2 key material 32-bit
        * entities.
        *
        * @param    k0 first 32-bit entity
        * @param    k1 second 32-bit entity
        * @return     Remainder polynomial Generated using RS code
        */
        private  int RS_MDS_Encode(int k0, int k1)
        {
            int r = k1;
            for (int i = 0 ; i < 4 ; i++) // shift 1 byte at a time
            {
                r = RS_rem(r);
            }
            r ^= k0;
            for (int i=0 ; i < 4 ; i++)
            {
                r = RS_rem(r);
            }

            return r;
        }

        /**
        * Reed-Solomon code parameters: (12,8) reversible code:
		* <p>
        * <pre>
        * G(x) = x^4 + (a+1/a)x^3 + ax^2 + (a+1/a)x + 1
        * </pre>
        * where a = primitive root of field generator 0x14D
		* </p>
        */
        private  int RS_rem(int x)
        {
            int b = (int) (((uint)x >> 24) & 0xff);
            int g2 = ((b << 1) ^
                    ((b & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
            int g3 = ( (int)((uint)b >> 1) ^
                    ((b & 0x01) != 0 ? (int)((uint)RS_GF_FDBK >> 1) : 0)) ^ g2 ;
            return ((x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b);
        }

        private  int LFSR1(int x)
        {
            return (x >> 1) ^
                    (((x & 0x01) != 0) ? GF256_FDBK_2 : 0);
        }

        private  int LFSR2(int x)
        {
            return (x >> 2) ^
                    (((x & 0x02) != 0) ? GF256_FDBK_2 : 0) ^
                    (((x & 0x01) != 0) ? GF256_FDBK_4 : 0);
        }

        private  int Mx_X(int x)
        {
            return x ^ LFSR2(x);
        } // 5B

        private  int Mx_Y(int x)
        {
            return x ^ LFSR1(x) ^ LFSR2(x);
        } // EF

        private  int M_b0(int x)
        {
            return x & 0xff;
        }

        private  int M_b1(int x)
        {
            return (int)((uint)x >> 8) & 0xff;
        }

        private  int M_b2(int x)
        {
            return (int)((uint)x >> 16) & 0xff;
        }

        private  int M_b3(int x)
        {
            return (int)((uint)x >> 24) & 0xff;
        }

        private  int Fe32_0(int x)
        {
            return gSBox[ 0x000 + 2*(x & 0xff) ] ^
                gSBox[ 0x001 + 2*((int)((uint)x >> 8) & 0xff) ] ^
                gSBox[ 0x200 + 2*((int)((uint)x >> 16) & 0xff) ] ^
                gSBox[ 0x201 + 2*((int)((uint)x >> 24) & 0xff) ];
        }

        private  int Fe32_3(int x)
        {
            return gSBox[ 0x000 + 2*((int)((uint)x >> 24) & 0xff) ] ^
                gSBox[ 0x001 + 2*(x & 0xff) ] ^
                gSBox[ 0x200 + 2*((int)((uint)x >> 8) & 0xff) ] ^
                gSBox[ 0x201 + 2*((int)((uint)x >> 16) & 0xff) ];
        }

        private  int BytesTo32Bits(byte[] b, int p)
        {
            return ((b[p] & 0xff) ) |
                ((b[p+1] & 0xff) << 8) |
                ((b[p+2] & 0xff) << 16) |
                ((b[p+3] & 0xff) << 24);
        }

        private  void Bits32ToBytes(int inData,  byte[] b, int offset)
        {
            b[offset] = (byte)inData;
            b[offset + 1] = (byte)(inData >> 8);
            b[offset + 2] = (byte)(inData >> 16);
            b[offset + 3] = (byte)(inData >> 24);
        }
    }

}
