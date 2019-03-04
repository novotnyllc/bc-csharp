using System;

using System.Collections.Generic;

namespace Org.BouncyCastle.Utilities.Collections
{
	public class UnmodifiableListProxy<T>
		: UnmodifiableList<T>
	{
		private readonly IList<T> l;

		public UnmodifiableListProxy(IList<T> l)
		{
			this.l = l;
		}

		public override bool Contains(T o)
		{
			return l.Contains(o);
		}

		public override void CopyTo(T[] array, int index)
		{
			l.CopyTo(array, index);
		}

		public override int Count
		{
			get { return l.Count; }
		}

		public override IEnumerator<T> GetEnumerator()
		{
			return l.GetEnumerator();
		}

		public override int IndexOf(T o)
		{
			return l.IndexOf(o);
		}

		protected override T GetValue(int i)
		{
			return l[i];
		}
	}
}
