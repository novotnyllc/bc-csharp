using System;
using System.Collections;
using System.Collections.Generic;

namespace Org.BouncyCastle.Utilities.Collections
{
	public abstract class UnmodifiableList<T>
        : IList<T>
	{
		protected UnmodifiableList()
		{
		}

		public virtual int Add(T o)
		{
			throw new NotSupportedException();
		}

		public virtual void Clear()
		{
			throw new NotSupportedException();
		}

		public abstract bool Contains(T o);

		public abstract void CopyTo(T[] array, int index);

		public abstract int Count { get; }

		public abstract IEnumerator<T> GetEnumerator();

		public abstract int IndexOf(T o);

		public virtual void Insert(int i, T o)
		{
			throw new NotSupportedException();
		}

		public virtual bool IsReadOnly
		{
			get { return true; }
		}

		public virtual bool Remove(T o)
		{
			throw new NotSupportedException();
		}

		public virtual void RemoveAt(int i)
		{
			throw new NotSupportedException();
		}
		
		public virtual T this[int i]
		{
			get { return GetValue(i); }
			set { throw new NotSupportedException(); }
		}

		protected abstract T GetValue(int i);

        void ICollection<T>.Add(T item)
        {
            Add(item);
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
}
