using System;
using System.Collections;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X509
{
    public class AttributeTable
    {
        private readonly IDictionary<DerObjectIdentifier, AttributeX509> attributes;

        public AttributeTable(
            IDictionary<DerObjectIdentifier, AttributeX509> attrs)
        {
            this.attributes = Platform.CreateDictionary(attrs);
        }

		public AttributeTable(
            Asn1EncodableVector v)
        {
            this.attributes = Platform.CreateDictionary<DerObjectIdentifier, AttributeX509>(v.Count);

			for (int i = 0; i != v.Count; i++)
            {
                AttributeX509 a = AttributeX509.GetInstance(v[i]);

				attributes.Add(a.AttrType, a);
            }
        }

		public AttributeTable(
            Asn1Set s)
        {
            this.attributes = Platform.CreateDictionary<DerObjectIdentifier, AttributeX509>(s.Count);

			for (int i = 0; i != s.Count; i++)
            {
                AttributeX509 a = AttributeX509.GetInstance(s[i]);

				attributes.Add(a.AttrType, a);
            }
        }

		public AttributeX509 Get(
            DerObjectIdentifier oid)
        {
            return attributes[oid];
        }

        public IDictionary<DerObjectIdentifier, AttributeX509> ToDictionary()
        {
            return Platform.CreateDictionary(attributes);
        }
    }
}
