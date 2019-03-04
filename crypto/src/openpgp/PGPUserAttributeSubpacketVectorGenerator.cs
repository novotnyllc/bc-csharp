using System;

using System.Collections.Generic;
using Org.BouncyCastle.Bcpg.Attr;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	public class PgpUserAttributeSubpacketVectorGenerator
	{
		private IList<ImageAttrib> list = Platform.CreateList<ImageAttrib>();

		public virtual void SetImageAttribute(
			ImageAttrib.Format	imageType,
			byte[]				imageData)
		{
			if (imageData == null)
				throw new ArgumentException("attempt to set null image", "imageData");

			list.Add(new ImageAttrib(imageType, imageData));
		}

        public virtual PgpUserAttributeSubpacketVector Generate()
		{
            UserAttributeSubpacket[] a = new UserAttributeSubpacket[list.Count];
            for (int i = 0; i < list.Count; ++i)
            {
                a[i] = list[i];
            }
            return new PgpUserAttributeSubpacketVector(a);
		}
	}
}
