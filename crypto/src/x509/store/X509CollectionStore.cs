using System;
using System.Collections;
using System.Collections.Generic;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.X509.Store
{
	/**
	 * A simple collection backed store.
	 */
	internal class X509CollectionStore<T>
		: IX509Store<T>
	{
		private ICollection<T> _local;

		/**
		 * Basic constructor.
		 *
		 * @param collection - initial contents for the store, this is copied.
		 */
		internal X509CollectionStore(
			ICollection<T> collection)
		{
			_local = Platform.CreateList(collection);
		}

		/**
		 * Return the matches in the collection for the passed in selector.
		 *
		 * @param selector the selector to match against.
		 * @return a possibly empty collection of matching objects.
		 */
		public ICollection<T> GetMatches(
			IX509Selector selector)
		{
			if (selector == null)
			{
                return Platform.CreateList(_local);
			}

            var result = Platform.CreateList<T>();
			foreach (var obj in _local)
			{
				if (selector.Match(obj))
					result.Add(obj);
			}

			return result;
		}
	}
}
