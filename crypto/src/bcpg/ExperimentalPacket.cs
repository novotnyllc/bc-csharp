using System;
using System.IO;
using System.Linq;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Basic packet for an experimental packet.</remarks>
    public class ExperimentalPacket
        : ContainedPacket //, PublicKeyAlgorithmTag
    {
        private readonly PacketTag	tag;
        private readonly byte[]		contents;

		internal ExperimentalPacket(
            PacketTag		tag,
            BcpgInputStream	bcpgIn)
        {
            this.tag = tag;

			this.contents = bcpgIn.ReadAll();
        }

		public PacketTag Tag
        {
			get { return tag; }
        }

		public byte[] GetContents()
        {
			return contents.ToArray();
        }

		public override void Encode(
            BcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(tag, contents, true);
        }
    }
}
