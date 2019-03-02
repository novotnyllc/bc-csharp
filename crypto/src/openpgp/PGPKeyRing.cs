using System.Collections;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	public abstract class PgpKeyRing
		: PgpObject
	{
		internal PgpKeyRing()
		{
		}

		internal static TrustPacket ReadOptionalTrustPacket(
			BcpgInputStream bcpgInput)
		{
			return (bcpgInput.NextPacketTag() == PacketTag.Trust)
				?	(TrustPacket) bcpgInput.ReadPacket()
				:	null;
		}

		internal static IList<PgpSignature> ReadSignaturesAndTrust(
			BcpgInputStream	bcpgInput)
		{
			try
			{
                var sigList = Platform.CreateList<PgpSignature>();

				while (bcpgInput.NextPacketTag() == PacketTag.Signature)
				{
					SignaturePacket signaturePacket = (SignaturePacket) bcpgInput.ReadPacket();
					TrustPacket trustPacket = ReadOptionalTrustPacket(bcpgInput);

					sigList.Add(new PgpSignature(signaturePacket, trustPacket));
				}

				return sigList;
			}
			catch (PgpException e)
			{
				throw new IOException("can't create signature object: " + e.Message, e);
			}
		}

		internal static void ReadUserIDs(
			BcpgInputStream	bcpgInput,
			out IList<object>       ids,
			out IList<ContainedPacket>       idTrusts,
			out IList<IList<PgpSignature>>       idSigs)
		{
            ids = Platform.CreateList<object>();
            idTrusts = Platform.CreateList<ContainedPacket>();
            idSigs = Platform.CreateList<IList<PgpSignature>>();

			while (bcpgInput.NextPacketTag() == PacketTag.UserId
				|| bcpgInput.NextPacketTag() == PacketTag.UserAttribute)
			{
				Packet obj = bcpgInput.ReadPacket();
				if (obj is UserIdPacket)
				{
					UserIdPacket id = (UserIdPacket)obj;
					ids.Add(id.GetId());
				}
				else
				{
					UserAttributePacket user = (UserAttributePacket) obj;
					ids.Add(new PgpUserAttributeSubpacketVector(user.GetSubpackets()));
				}

				idTrusts.Add(
					ReadOptionalTrustPacket(bcpgInput));

				idSigs.Add(
					ReadSignaturesAndTrust(bcpgInput));
			}
		}
	}
}
