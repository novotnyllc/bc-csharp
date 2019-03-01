using System;
using System.Collections;
using System.Collections.Generic;

namespace Org.BouncyCastle.Utilities.Collections
{
	public sealed class EnumerableProxy<T>
		: IEnumerable<T>
	{
		private readonly IEnumerable<T> inner;

		public EnumerableProxy(
			IEnumerable<T> inner)
		{
			if (inner == null)
				throw new ArgumentNullException("inner");

			this.inner = inner;
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			return inner.GetEnumerator();
		}

        public IEnumerator<T> GetEnumerator()
        {
            return inner.GetEnumerator();
        }
    }
}
