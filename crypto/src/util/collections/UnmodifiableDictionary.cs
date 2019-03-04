using System;
using System.Collections;
using System.Collections.Generic;

namespace Org.BouncyCastle.Utilities.Collections
{
	public abstract class UnmodifiableDictionary<TKey, TValue>
        : IDictionary<TKey, TValue>
    {
		protected UnmodifiableDictionary()
		{
		}

		public virtual void Add(TKey k, TValue v)
		{
			throw new NotSupportedException();
		}

		public virtual void Clear()
		{
			throw new NotSupportedException();
		}

		public abstract bool ContainsKey(TKey k);

		public abstract void CopyTo(KeyValuePair<TKey, TValue>[] array, int index);

		public abstract int Count { get; }

		public virtual bool Remove(TKey k)
		{
			throw new NotSupportedException();
		}

		public virtual bool IsReadOnly
		{
			get { return true; }
		}

		public abstract ICollection<TKey> Keys { get; }

		public abstract ICollection<TValue> Values { get; }

		public virtual TValue this[TKey k]
		{
			get { return GetValue(k); }
			set { throw new NotSupportedException(); }
		}

		protected abstract TValue GetValue(TKey k);

        public abstract bool TryGetValue(TKey key, out TValue value);

        public void Add(KeyValuePair<TKey, TValue> item)
        {
            throw new NotImplementedException();
        }

        public abstract bool Contains(KeyValuePair<TKey, TValue> item);

        public bool Remove(KeyValuePair<TKey, TValue> item)
        {
            throw new NotImplementedException();
        }

        public abstract IEnumerator<KeyValuePair<TKey, TValue>> GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
}
