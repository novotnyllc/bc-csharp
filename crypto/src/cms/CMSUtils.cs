using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace Org.BouncyCastle.Cms
{
    internal class CmsUtilities
    {
		// TODO Is there a .NET equivalent to this?
//		private static readonly Runtime RUNTIME = Runtime.getRuntime();

		internal static int MaximumMemory
		{
			get
			{
				// TODO Is there a .NET equivalent to this?
				long maxMem = int.MaxValue;//RUNTIME.maxMemory();

				if (maxMem > int.MaxValue)
				{
					return int.MaxValue;
				}

				return (int)maxMem;
			}
		}

		internal static ContentInfo ReadContentInfo(
			byte[] input)
		{
			// enforce limit checking as from a byte array
			return ReadContentInfo(new Asn1InputStream(input));
		}

		internal static ContentInfo ReadContentInfo(
			Stream input)
		{
			// enforce some limit checking
			return ReadContentInfo(new Asn1InputStream(input, MaximumMemory));
		}

		private static ContentInfo ReadContentInfo(
			Asn1InputStream aIn)
		{
			try
			{
				return ContentInfo.GetInstance(aIn.ReadObject());
			}
			catch (IOException e)
			{
				throw new CmsException("IOException reading content.", e);
			}
			catch (InvalidCastException e)
			{
				throw new CmsException("Malformed content.", e);
			}
			catch (ArgumentException e)
			{
				throw new CmsException("Malformed content.", e);
			}
		}

		public static byte[] StreamToByteArray(
            Stream inStream)
        {
			return Streams.ReadAll(inStream);
        }

		public static byte[] StreamToByteArray(
            Stream	inStream,
			int		limit)
        {
			return Streams.ReadAllLimited(inStream, limit);
        }

		public static IList<Asn1Encodable> GetCertificatesFromStore(
			IX509Store<X509Certificate> certStore)
		{
			try
			{
				var certs = Platform.CreateList<Asn1Encodable>();

				if (certStore != null)
				{
					foreach (X509Certificate c in certStore.GetMatches(null))
					{
						certs.Add(
							X509CertificateStructure.GetInstance(
								Asn1Object.FromByteArray(c.GetEncoded())));
					}
				}

				return certs;
			}
			catch (CertificateEncodingException e)
			{
				throw new CmsException("error encoding certs", e);
			}
			catch (Exception e)
			{
				throw new CmsException("error processing certs", e);
			}
		}

		public static IList<CertificateList> GetCrlsFromStore(
			IX509Store<X509Crl> crlStore)
		{
			try
			{
                var crls = Platform.CreateList<CertificateList>();

				if (crlStore != null)
				{
					foreach (X509Crl c in crlStore.GetMatches(null))
					{
						crls.Add(
							CertificateList.GetInstance(
								Asn1Object.FromByteArray(c.GetEncoded())));
					}
				}

				return crls;
			}
			catch (CrlException e)
			{
				throw new CmsException("error encoding crls", e);
			}
			catch (Exception e)
			{
				throw new CmsException("error processing crls", e);
			}
		}

		public static Asn1Set CreateBerSetFromList(
			IEnumerable<Asn1Encodable> berObjects)
		{
			Asn1EncodableVector v = new Asn1EncodableVector();

			foreach (Asn1Encodable ae in berObjects)
			{
				v.Add(ae);
			}

			return new BerSet(v);
		}

		public static Asn1Set CreateDerSetFromList(
			IEnumerable<Asn1Encodable> derObjects)
		{
			Asn1EncodableVector v = new Asn1EncodableVector();

			foreach (Asn1Encodable ae in derObjects)
			{
				v.Add(ae);
			}

			return new DerSet(v);
		}

		internal static Stream CreateBerOctetOutputStream(Stream s, int tagNo, bool isExplicit, int bufferSize)
		{
			BerOctetStringGenerator octGen = new BerOctetStringGenerator(s, tagNo, isExplicit);
			return octGen.GetOctetOutputStream(bufferSize);
		}

		internal static TbsCertificateStructure GetTbsCertificateStructure(X509Certificate cert)
		{
			return TbsCertificateStructure.GetInstance(Asn1Object.FromByteArray(cert.GetTbsCertificate()));
		}

		internal static IssuerAndSerialNumber GetIssuerAndSerialNumber(X509Certificate cert)
		{
			TbsCertificateStructure tbsCert = GetTbsCertificateStructure(cert);
			return new IssuerAndSerialNumber(tbsCert.Issuer, tbsCert.SerialNumber.Value);
		}
	}
}
