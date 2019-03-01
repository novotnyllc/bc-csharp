using System;
using System.Collections;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pkcs
{
    public class AsymmetricKeyEntry
        : Pkcs12Entry
    {
        private readonly AsymmetricKeyParameter key;

		public AsymmetricKeyEntry(
            AsymmetricKeyParameter key)
			: base(new Dictionary<string, Asn1Encodable>())
        {
            this.key = key;
        }

        public AsymmetricKeyEntry(
            AsymmetricKeyParameter  key,
            IDictionary<string, Asn1Encodable> attributes)
			: base(attributes)
        {
            this.key = key;
        }

		public AsymmetricKeyParameter Key
        {
            get { return this.key; }
        }

		public override bool Equals(object obj)
		{
			AsymmetricKeyEntry other = obj as AsymmetricKeyEntry;

			if (other == null)
				return false;

			return key.Equals(other.key);
		}

		public override int GetHashCode()
		{
			return ~key.GetHashCode();
		}
	}
}
