using System;
using System.Collections;
using System.Collections.Generic;

namespace Org.BouncyCastle.Utilities.Collections
{
	public abstract class UnmodifiableSet<T>
        : ISet<T>
    {
		protected UnmodifiableSet()
		{
		}

		public virtual bool Add(T o)
		{
			throw new NotSupportedException();
		}

		public virtual void AddAll(IEnumerable<T> e)
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

		public virtual bool IsReadOnly
		{
			get { return true; }
		}

		public virtual bool Remove(T o)
		{
			throw new NotSupportedException();
		}

		public virtual void RemoveAll(IEnumerable<T> e)
		{
			throw new NotSupportedException();
		}

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        public void ExceptWith(IEnumerable<T> other)
        {
            throw new NotSupportedException();
        }

        public void IntersectWith(IEnumerable<T> other)
        {
            throw new NotSupportedException();
        }

        public abstract bool IsProperSubsetOf(IEnumerable<T> other);

        public abstract bool IsProperSupersetOf(IEnumerable<T> other);

        public abstract bool IsSubsetOf(IEnumerable<T> other);

        public abstract bool IsSupersetOf(IEnumerable<T> other);

        public abstract bool Overlaps(IEnumerable<T> other);

        public abstract bool SetEquals(IEnumerable<T> other);

        public void SymmetricExceptWith(IEnumerable<T> other)
        {
            throw new NotSupportedException();
        }

        public void UnionWith(IEnumerable<T> other)
        {
            throw new NotSupportedException();
        }

        void ICollection<T>.Add(T item)
        {
            Add(item);
        }
    }
}
