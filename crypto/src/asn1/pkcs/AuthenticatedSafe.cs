using Org.BouncyCastle.Asn1;
using System.Linq;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class AuthenticatedSafe
        : Asn1Encodable
    {
        private readonly ContentInfo[] info;

		public AuthenticatedSafe(
            Asn1Sequence seq)
        {
            info = new ContentInfo[seq.Count];

			for (int i = 0; i != info.Length; i++)
            {
                info[i] = ContentInfo.GetInstance(seq[i]);
            }
        }

		public AuthenticatedSafe(
            ContentInfo[] info)
        {
            this.info = info.ToArray();
        }

		public ContentInfo[] GetContentInfo()
        {
            return info.ToArray();
        }

		public override Asn1Object ToAsn1Object()
        {
			return new BerSequence(info);
        }
    }
}
