using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Pkcs
{
    public abstract class Pkcs12Entry
    {
        private readonly IDictionary<string, Asn1Encodable> attributes;

		protected internal Pkcs12Entry(
            IDictionary<string, Asn1Encodable> attributes)
        {
            this.attributes = attributes;

			foreach (var entry in attributes)
			{
				if (!(entry.Key is string))
					throw new ArgumentException("Attribute keys must be of type: " + typeof(string).FullName, "attributes");
				if (!(entry.Value is Asn1Encodable))
					throw new ArgumentException("Attribute values must be of type: " + typeof(Asn1Encodable).FullName, "attributes");
			}
        }

		[Obsolete("Use 'object[index]' syntax instead")]
		public Asn1Encodable GetBagAttribute(
            DerObjectIdentifier oid)
        {
            return this.attributes[oid.Id];
        }

		[Obsolete("Use 'object[index]' syntax instead")]
		public Asn1Encodable GetBagAttribute(
            string oid)
        {
            return this.attributes[oid];
        }

		[Obsolete("Use 'BagAttributeKeys' property")]
        public IEnumerator<string> GetBagAttributeKeys()
        {
            return this.attributes.Keys.GetEnumerator();
        }

		public Asn1Encodable this[
			DerObjectIdentifier oid]
		{
            get
            {
                Asn1Encodable attribute;
                this.attributes.TryGetValue(oid.Id, out attribute);
                return attribute;
            }
		}

		public Asn1Encodable this[
			string oid]
		{
            get
            {
                Asn1Encodable attribute;
                this.attributes.TryGetValue(oid, out attribute);
                return attribute;
            }
        }

        public IEnumerable<string> BagAttributeKeys
		{
			get { return new EnumerableProxy<string>(this.attributes.Keys); }
		}
    }
}
