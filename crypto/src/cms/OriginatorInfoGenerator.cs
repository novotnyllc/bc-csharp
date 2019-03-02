using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace Org.BouncyCastle.Cms
{
    public class OriginatorInfoGenerator
    {
        private readonly IList<Asn1Encodable> origCerts;
        private readonly IList<CertificateList> origCrls;

        public OriginatorInfoGenerator(X509Certificate origCert)
        {
            this.origCerts = Platform.CreateList<Asn1Encodable>(1);
            this.origCrls = null;
            origCerts.Add(origCert.CertificateStructure);
        }

        public OriginatorInfoGenerator(IX509Store<X509Certificate> origCerts)
            : this(origCerts, null)
        {
        }

        public OriginatorInfoGenerator(IX509Store<X509Certificate> origCerts, IX509Store<X509Crl> origCrls)
        {
            this.origCerts = CmsUtilities.GetCertificatesFromStore(origCerts);
            this.origCrls = origCrls == null ? null : CmsUtilities.GetCrlsFromStore(origCrls);
        }

        public virtual OriginatorInfo Generate()
        {
            Asn1Set certSet = CmsUtilities.CreateDerSetFromList(origCerts);
            Asn1Set crlSet = origCrls == null ? null : CmsUtilities.CreateDerSetFromList(origCrls);
            return new OriginatorInfo(certSet, crlSet);
        }
    }
}
