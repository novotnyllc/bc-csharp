using System;

using System.Collections.Generic;

namespace Org.BouncyCastle.Utilities.Collections
{
	public class UnmodifiableSetProxy<T>
        : UnmodifiableSet<T>
    {
		private readonly ISet<T> s;

		public UnmodifiableSetProxy (ISet<T> s)
		{
			this.s = s;
		}

		public override bool Contains(T o)
		{
			return s.Contains(o);
		}

		public override void CopyTo(T[] array, int index)
		{
			s.CopyTo(array, index);
		}

		public override int Count
		{
			get { return s.Count; }
		}

		public override IEnumerator<T> GetEnumerator()
		{
			return s.GetEnumerator();
		}

        public override bool IsProperSubsetOf(IEnumerable<T> other)
        {
            return s.IsProperSubsetOf(other);
        }

        public override bool IsProperSupersetOf(IEnumerable<T> other)
        {
            return s.IsProperSupersetOf(other);
        }

        public override bool IsSubsetOf(IEnumerable<T> other)
        {
            return s.IsSubsetOf(other);
        }

        public override bool IsSupersetOf(IEnumerable<T> other)
        {
            return s.IsSupersetOf(other);
        }

        public override bool Overlaps(IEnumerable<T> other)
        {
            return s.Overlaps(other);
        }

        public override bool SetEquals(IEnumerable<T> other)
        {
            return s.SetEquals(other);
        }
    }
}
