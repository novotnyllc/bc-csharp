using System.IO;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Basic type for a marker packet.</remarks>
    public class MarkerPacket
        : ContainedPacket
    {
        // "PGP"
        byte[] marker = { 0x50, 0x47, 0x50 };

        public MarkerPacket(
            BcpgInputStream bcpgIn)
        {
            bcpgIn.ReadFully(marker);
        }

        public override void Encode(
            BcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(PacketTag.Marker, marker, true);
        }
    }
}
