using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace Org.BouncyCastle.Utilities.Collections
{
	public class LinkedDictionary<TKey, TValue>
        : IDictionary<TKey, TValue>
	{
		internal readonly IDictionary<TKey, TValue> hash = Platform.CreateDictionary<TKey, TValue>();
		internal readonly IList<TKey> keys = Platform.CreateList<TKey>();

		public LinkedDictionary()
		{
		}

		public virtual void Add(TKey k, TValue v)
		{
			hash.Add(k, v);
			keys.Add(k);
		}

		public virtual void Clear()
		{
			hash.Clear();
			keys.Clear();
		}

		public virtual bool ContainsKey(TKey k)
		{
			return hash.ContainsKey(k);
		}

		public virtual void CopyTo(KeyValuePair<TKey, TValue>[] array, int index)
		{
			foreach (var k in keys)
			{
				array.SetValue(hash[k], index++);
			}
		}

		public virtual int Count
		{
			get { return hash.Count; }
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			return GetEnumerator();
		}

		public virtual IEnumerator<KeyValuePair<TKey, TValue>> GetEnumerator()
		{
			return new LinkedDictionaryEnumerator<TKey, TValue>(this);
		}

		public virtual bool Remove(TKey k)
		{
            hash.Remove(k);
			return keys.Remove(k);
		}

        public bool TryGetValue(TKey key, out TValue value)
        {
            return hash.TryGetValue(key, out value);
        }

        public void Add(KeyValuePair<TKey, TValue> item)
        {
            hash.Add(item);
            keys.Add(item.Key);
        }

        public bool Contains(KeyValuePair<TKey, TValue> item)
        {
            return hash.Contains(item);
        }

        public bool Remove(KeyValuePair<TKey, TValue> item)
        {
            hash.Remove(item);
            return keys.Remove(item.Key);
        }

        public virtual bool IsReadOnly
		{
			get { return false; }
		}


		public virtual ICollection<TKey> Keys
		{
            get { return keys.ToList(); }
		}

		public virtual ICollection<TValue> Values
		{
			// NB: Order has to be the same as for Keys property
			get
			{
                var values = Platform.CreateList<TValue>(keys.Count);
				foreach (var k in keys)
				{
					values.Add(hash[k]);
				}
				return values.ToList();
			}
		}

		public virtual TValue this[TKey k]
		{
			get
			{
				return hash[k];
			}
			set
			{
				if (!hash.ContainsKey(k))
					keys.Add(k);
				hash[k] = value;
			}
		}
	}

	internal class LinkedDictionaryEnumerator<TKey, TValue> : IEnumerator<KeyValuePair<TKey, TValue>>
	{
		private readonly LinkedDictionary<TKey, TValue> parent;
		private int pos = -1;

		internal LinkedDictionaryEnumerator(LinkedDictionary<TKey, TValue> parent)
		{
			this.parent = parent;
		}

		public virtual KeyValuePair<TKey, TValue> Current
		{
			get { return Entry; }
		}

		public virtual KeyValuePair<TKey, TValue> Entry
		{
			get
			{
				TKey k = CurrentKey;
				return new KeyValuePair<TKey, TValue>(k, parent.hash[k]);
			}
		}

		public virtual TKey Key
		{
			get
			{
				return CurrentKey;
			}
		}

		public virtual bool MoveNext()
		{
			if (pos >= parent.keys.Count)
				return false;
			return ++pos < parent.keys.Count;
		}

		public virtual void Reset()
		{
			this.pos = -1;
		}

        public void Dispose()
        {
        }

        public virtual TValue Value
		{
			get
			{
				return parent.hash[CurrentKey];
			}
		}

		private TKey CurrentKey
		{
			get
			{
				if (pos < 0 || pos >= parent.keys.Count)
					throw new InvalidOperationException();
				return parent.keys[pos];
			}
		}

        object IEnumerator.Current
        {
            get
            {
                return Current;
            }
        }
    }
}
