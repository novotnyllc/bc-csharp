using System;

using System.Collections.Generic;

namespace Org.BouncyCastle.X509.Store
{
	public interface IX509Store<T>
	{
//		void Init(IX509StoreParameters parameters);
		ICollection<T> GetMatches(IX509Selector selector);
	}
}
