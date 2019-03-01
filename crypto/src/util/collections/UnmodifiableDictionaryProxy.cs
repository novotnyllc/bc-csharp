using System;
using System.Collections;
using System.Collections.Generic;

namespace Org.BouncyCastle.Utilities.Collections
{
	public class UnmodifiableDictionaryProxy<TKey, TValue>
        : UnmodifiableDictionary<TKey, TValue>
    {
		private readonly IDictionary<TKey, TValue> d;

		public UnmodifiableDictionaryProxy(IDictionary<TKey, TValue> d)
		{
			this.d = d;
		}

		public override bool ContainsKey(TKey k)
		{
			return d.ContainsKey(k);
		}

		public override void CopyTo(KeyValuePair<TKey, TValue>[] array, int index)
		{
			d.CopyTo(array, index);
		}

		public override int Count
		{
			get { return d.Count; }
		}

		public override ICollection<TKey> Keys
		{
			get { return d.Keys; }
		}

		public override ICollection<TValue> Values
		{
			get { return d.Values; }
		}

        public override bool IsFixedSize => throw new NotImplementedException();

        protected override TValue GetValue(TKey k)
		{
			return d[k];
		}

        public override bool TryGetValue(TKey key, out TValue value)
        {
            return d.TryGetValue(key, out value);
        }

        public override bool Contains(KeyValuePair<TKey, TValue> item)
        {
            return d.Contains(item);
        }

        public override IEnumerator<KeyValuePair<TKey, TValue>> GetEnumerator()
        {
            return d.GetEnumerator();
        }
    }
}
