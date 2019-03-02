using System;
using System.Collections;
using System.IO;
using System.Reflection;
using System.Text;
using NUnit.Framework;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Utilities.Test
{
    public abstract class SimpleTest
        : ITest
    {
		public abstract string Name
		{
			get;
		}

		private ITestResult Success()
        {
            return SimpleTestResult.Successful(this, "Okay");
        }

        internal void Fail(
            string message)
        {
            Assert.Fail(message);
        }

        internal void Fail(
            string		message,
            Exception	throwable)
        {
            Assert.Fail(message, throwable);
        }

		internal void Fail(
            string message,
            object expected,
            object found)
        {
            Assert.Fail(message, expected, found);
        }

        internal void IsTrue(bool value)
        {
            Assert.IsTrue(value, "no message");
        }

        internal void IsTrue(string message, bool value)
        {
            Assert.IsTrue(value, message);
        }

        internal void IsEquals(object a, object b)
        {
            Assert.AreEqual(a, b, "no message");
        }

        internal void IsEquals(int a, int b)
        {
            Assert.AreEqual(a, b, "no message");
        }

        internal void IsEquals(string message, bool a, bool b)
        {
            Assert.AreEqual(a, b, message);
        }

        internal void IsEquals(string message, long a, long b)
        {
            Assert.AreEqual(a, b, message);
        }

        internal void IsEquals(string message, object a, object b)
        {
            Assert.AreEqual(a, b, message);
        }

        internal bool AreEqual(
            byte[] a,
            byte[] b)
        {
			return Arrays.AreEqual(a, b);
		}

		public virtual ITestResult Perform()
        {
            PerformTest();

			return Success();
        }

		internal static void RunTest(
            ITest test)
        {
            RunTest(test, Console.Out);
        }

		internal static void RunTest(
            ITest		test,
            TextWriter	outStream)
        {
            ITestResult result = test.Perform();

			outStream.WriteLine(result.ToString());
            if (result.GetException() != null)
            {
                outStream.WriteLine(result.GetException().StackTrace);
            }
        }

		internal static Stream GetTestDataAsStream(
			string name)
		{
			string fullName = GetFullName(name);
            
			return typeof(SimpleTest).GetTypeInfo().Assembly.GetManifestResourceStream(fullName);
		}

		internal static string[] GetTestDataEntries(
			string prefix)
		{
			string fullPrefix = GetFullName(prefix);

			var result = new ArrayList();
			string[] fullNames = typeof(SimpleTest).GetTypeInfo().Assembly.GetManifestResourceNames();
			foreach (string fullName in fullNames)
			{
				if (fullName.StartsWith(fullPrefix))
				{
					string name = GetShortName(fullName);
					result.Add(name);
				}
			}
			return (string[])result.ToArray(typeof(String));
		}

		private static string GetFullName(
			string name)
		{
            return "crypto.test.data." + name;
		}

		private static string GetShortName(
			string fullName)
		{
            return fullName.Substring("crypto.test.data.".Length);
		}

#if NETCF_1_0 || NETCF_2_0
		private static string GetNewLine()
		{
			MemoryStream buf = new MemoryStream();
			StreamWriter w = new StreamWriter(buf, Encoding.ASCII);
			w.WriteLine();
			w.Close();
			byte[] bs = buf.ToArray();
			return Encoding.ASCII.GetString(bs, 0, bs.Length);
		}

		internal static string GetEnvironmentVariable(
			string variable)
		{
			return null;
		}
#else
		private static string GetNewLine()
		{
			return Environment.NewLine;
		}
#endif

		internal static readonly string NewLine = GetNewLine();

		public abstract void PerformTest();

        public static DateTime MakeUtcDateTime(int year, int month, int day, int hour, int minute, int second)
        {
#if PORTABLE
            return new DateTime(year, month, day, hour, minute, second, DateTimeKind.Utc);
#else
            return new DateTime(year, month, day, hour, minute, second);
#endif
        }

        public static DateTime MakeUtcDateTime(int year, int month, int day, int hour, int minute, int second, int millisecond)
        {
#if PORTABLE
            return new DateTime(year, month, day, hour, minute, second, millisecond, DateTimeKind.Utc);
#else
            return new DateTime(year, month, day, hour, minute, second, millisecond);
#endif
        }
    }
}
