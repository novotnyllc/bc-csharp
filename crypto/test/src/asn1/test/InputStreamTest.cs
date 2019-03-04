using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
	[TestFixture]
	public class InputStreamTest
		: SimpleTest
	{
		private static readonly byte[] outOfBoundsLength = new byte[] { 0x30, 0xff, 0xff, 0xff, 0xff, 0xff };
		private static readonly byte[] negativeLength = new byte[] { 0x30, 0x84, 0xff, 0xff, 0xff, 0xff };
		private static readonly byte[] outsideLimitLength = new byte[] { 0x30, 0x83, 0x0f, 0xff, 0xff };

		public override string Name
		{
			get { return "InputStream"; }
		}

		public override void PerformTest()
		{
			Asn1InputStream aIn = new Asn1InputStream(outOfBoundsLength);

			try
			{
				aIn.ReadObject();
				Fail("out of bounds length not detected.");
			}
			catch (IOException e)
			{
				if (!e.Message.StartsWith("DER length more than 4 bytes"))
				{
					Fail("wrong exception: " + e.Message);
				}
			}

			aIn = new Asn1InputStream(negativeLength);

			try
			{
				aIn.ReadObject();
				Fail("negative length not detected.");
			}
			catch (IOException e)
			{
				if (!e.Message.Equals("Corrupted stream - negative length found"))
				{
					Fail("wrong exception: " + e.Message);
				}
			}

			aIn = new Asn1InputStream(outsideLimitLength);

			try
			{
				aIn.ReadObject();
				Fail("outside limit length not detected.");
			}
			catch (IOException e)
			{
				if (!e.Message.Equals("Corrupted stream - out of bounds length found"))
				{
					Fail("wrong exception: " + e.Message);
				}
			}
		}
#if !LIB
		public static void MainOld(
			string[] args)
		{
			RunTest(new InputStreamTest());
		}
#endif

		[Test]
		public void TestFunction()
		{
			string resultText = Perform().ToString();

			Assert.AreEqual(Name + ": Okay", resultText);
		}
	}
}
