using System;
using System.Collections;
using System.Collections.Generic;

namespace Org.BouncyCastle.Utilities.Collections
{
	public class HashSet
		: ISet
	{
		private readonly ISet<object> impl = new HashSet<object>();

		public HashSet()
		{
		}

		public HashSet(IEnumerable s)
		{
			foreach (var o in s)
			{
				Add(o);
			}
		}

		public virtual void Add(object o)
		{
			impl.Add(o);
		}

		public virtual void AddAll(IEnumerable e)
		{
			foreach (var o in e)
			{
				Add(o);
			}
		}

		public virtual void Clear()
		{
			impl.Clear();
		}

		public virtual bool Contains(object o)
		{
			return impl.Contains(o);
		}

		public virtual void CopyTo(Array array, int index)
		{
			impl.CopyTo((object[])array, index);
		}

		public virtual int Count
		{
			get { return impl.Count; }
		}

		public virtual IEnumerator GetEnumerator()
		{
			return impl.GetEnumerator();
		}

		public virtual bool IsEmpty
		{
			get { return impl.Count == 0; }
		}

		public virtual bool IsFixedSize
		{
			get { return false; }
		}

		public virtual bool IsReadOnly
		{
			get { return impl.IsReadOnly; }
		}

		public virtual bool IsSynchronized
		{
			get { return false; }
		}

		public virtual void Remove(object o)
		{
			impl.Remove(o);
		}

		public virtual void RemoveAll(IEnumerable e)
		{
			foreach (var o in e)
			{
				Remove(o);
			}
		}

		public virtual object SyncRoot
		{
			get { return impl; }
		}
	}
}
