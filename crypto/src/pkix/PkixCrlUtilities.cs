using System;
using System.Collections;
using System.Collections.Generic;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace Org.BouncyCastle.Pkix
{
	public class PkixCrlUtilities
	{
		public virtual ISet<X509Crl> FindCrls(X509CrlStoreSelector crlselect, PkixParameters paramsPkix, DateTime currentDate)
		{
		 var initialSet = new HashSet<X509Crl>();

			// get complete CRL(s)
			try
			{
                foreach (var crl in FindCrls(crlselect, paramsPkix.GetAdditionalStores()))
                {
                    initialSet.Add(crl);
                }
                foreach (var crl in FindCrls(crlselect, paramsPkix.GetStores()))
                {
                    initialSet.Add(crl);
                }
			}
			catch (Exception e)
			{
				throw new Exception("Exception obtaining complete CRLs.", e);
			}

		 var finalSet = new HashSet<X509Crl>();
			DateTime validityDate = currentDate;

			if (paramsPkix.Date != null)
			{
				validityDate = paramsPkix.Date.Value;
			}

			// based on RFC 5280 6.3.3
			foreach (X509Crl crl in initialSet)
			{
				if (crl.NextUpdate.Value.CompareTo(validityDate) > 0)
				{
					X509Certificate cert = crlselect.CertificateChecking;

					if (cert != null)
					{
						if (crl.ThisUpdate.CompareTo(cert.NotAfter) < 0)
						{
							finalSet.Add(crl);
						}
					}
					else
					{
						finalSet.Add(crl);
					}
				}
			}

			return finalSet;
		}

		public virtual ISet<X509Crl> FindCrls(X509CrlStoreSelector crlselect, PkixParameters paramsPkix)
		{
		 var completeSet = new HashSet<X509Crl>();

			// get complete CRL(s)
			try
			{
                foreach (var crl in FindCrls(crlselect, paramsPkix.GetStores()))
                {
                    completeSet.Add(crl);
                }
			}
			catch (Exception e)
			{
				throw new Exception("Exception obtaining complete CRLs.", e);
			}

			return completeSet;
		}

		/// <summary>
		/// crl checking
		/// Return a Collection of all CRLs found in the X509Store's that are
		/// matching the crlSelect criteriums.
		/// </summary>
		/// <param name="crlSelect">a {@link X509CRLStoreSelector} object that will be used
		/// to select the CRLs</param>
		/// <param name="crlStores">a List containing only {@link org.bouncycastle.x509.X509Store
		/// X509Store} objects. These are used to search for CRLs</param>
		/// <returns>a Collection of all found {@link X509CRL X509CRL} objects. May be
		/// empty but never <code>null</code>.
		/// </returns>
		private ICollection<X509Crl> FindCrls(X509CrlStoreSelector crlSelect, IList<IX509Store<object>> crlStores)
		{
		 var crls = new HashSet<X509Crl>();

			Exception lastException = null;
			bool foundValidStore = false;

			foreach (var store in crlStores)
			{
				try
				{
                    foreach(X509Crl crl in store.GetMatches(crlSelect))
                    {
                        crls.Add(crl);
                    }
					foundValidStore = true;
				}
				catch (X509StoreException e)
				{
					lastException = new Exception("Exception searching in X.509 CRL store.", e);
				}
			}

	        if (!foundValidStore && lastException != null)
	            throw lastException;

			return crls;
		}
	}
}
