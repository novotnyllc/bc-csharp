using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Pkix
{
    public class PkixNameConstraintValidator
    {
        private ISet<Asn1Sequence> excludedSubtreesDN = new HashSet<Asn1Sequence>();

        private ISet<string> excludedSubtreesDNS = new HashSet<string>();

        private ISet<string> excludedSubtreesEmail = new HashSet<string>();

        private ISet<string> excludedSubtreesURI = new HashSet<string>();

        private ISet<byte[]> excludedSubtreesIP = new HashSet<byte[]>();

        private ISet<Asn1Sequence> permittedSubtreesDN;

        private ISet<string> permittedSubtreesDNS;

        private ISet<string> permittedSubtreesEmail;

        private ISet<string> permittedSubtreesURI;

        private ISet<byte[]> permittedSubtreesIP;

        public PkixNameConstraintValidator()
        {
        }

        private static bool WithinDNSubtree(
            Asn1Sequence dns,
            Asn1Sequence subtree)
        {
            if (subtree.Count < 1)
            {
                return false;
            }

            if (subtree.Count > dns.Count)
            {
                return false;
            }

            for (int j = subtree.Count - 1; j >= 0; j--)
            {
                if (!(subtree[j].Equals(dns[j])))
                {
                    return false;
                }
            }

            return true;
        }

        public void CheckPermittedDN(Asn1Sequence dns)
        //throws PkixNameConstraintValidatorException
        {
            CheckPermittedDN(permittedSubtreesDN, dns);
        }

        public void CheckExcludedDN(Asn1Sequence dns)
        //throws PkixNameConstraintValidatorException
        {
            CheckExcludedDN(excludedSubtreesDN, dns);
        }

        private void CheckPermittedDN(ISet<Asn1Sequence> permitted, Asn1Sequence dns)
        //throws PkixNameConstraintValidatorException
        {
            if (permitted == null)
            {
                return;
            }

            if ((permitted.Count == 0) && dns.Count == 0)
            {
                return;
            }

            var it = permitted.GetEnumerator();

            while (it.MoveNext())
            {
                Asn1Sequence subtree = (Asn1Sequence)it.Current;

                if (WithinDNSubtree(dns, subtree))
                {
                    return;
                }
            }

            throw new PkixNameConstraintValidatorException(
                "Subject distinguished name is not from a permitted subtree");
        }

        private void CheckExcludedDN(ISet<Asn1Sequence> excluded, Asn1Sequence dns)
        //throws PkixNameConstraintValidatorException
        {
            if (!excluded.Any())
            {
                return;
            }

            var it = excluded.GetEnumerator();

            while (it.MoveNext())
            {
                Asn1Sequence subtree = (Asn1Sequence)it.Current;

                if (WithinDNSubtree(dns, subtree))
                {
                    throw new PkixNameConstraintValidatorException(
                        "Subject distinguished name is from an excluded subtree");
                }
            }
        }

        private ISet<Asn1Sequence> IntersectDN(ISet<Asn1Sequence> permitted, ISet<GeneralSubtree> dns)
        {
            var intersect = new HashSet<Asn1Sequence>();
            for (var it = dns.GetEnumerator(); it.MoveNext(); )
            {
                Asn1Sequence dn = Asn1Sequence.GetInstance(((GeneralSubtree)it
                    .Current).Base.Name.ToAsn1Object());
                if (permitted == null)
                {
                    if (dn != null)
                    {
                        intersect.Add(dn);
                    }
                }
                else
                {
                    var _iter = permitted.GetEnumerator();
                    while (_iter.MoveNext())
                    {
                        Asn1Sequence subtree = (Asn1Sequence)_iter.Current;

                        if (WithinDNSubtree(dn, subtree))
                        {
                            intersect.Add(dn);
                        }
                        else if (WithinDNSubtree(subtree, dn))
                        {
                            intersect.Add(subtree);
                        }
                    }
                }
            }
            return intersect;
        }

        private ISet<Asn1Sequence> UnionDN(ISet<Asn1Sequence> excluded, Asn1Sequence dn)
        {
            if (!excluded.Any())
            {
                if (dn == null)
                {
                    return excluded;
                }
                excluded.Add(dn);

                return excluded;
            }
            else
            {
                var intersect = new HashSet<Asn1Sequence>();

                var it = excluded.GetEnumerator();
                while (it.MoveNext())
                {
                    Asn1Sequence subtree = (Asn1Sequence)it.Current;

                    if (WithinDNSubtree(dn, subtree))
                    {
                        intersect.Add(subtree);
                    }
                    else if (WithinDNSubtree(subtree, dn))
                    {
                        intersect.Add(dn);
                    }
                    else
                    {
                        intersect.Add(subtree);
                        intersect.Add(dn);
                    }
                }

                return intersect;
            }
        }

        private ISet<string> IntersectEmail(ISet<string> permitted, ISet<GeneralSubtree> emails)
        {
            var intersect = new HashSet<string>();
            for (var it = emails.GetEnumerator(); it.MoveNext(); )
            {
                String email = ExtractNameAsString(((GeneralSubtree)it.Current)
                    .Base);

                if (permitted == null)
                {
                    if (email != null)
                    {
                        intersect.Add(email);
                    }
                }
                else
                {
                    var it2 = permitted.GetEnumerator();
                    while (it2.MoveNext())
                    {
                        String _permitted = (String)it2.Current;

                        intersectEmail(email, _permitted, intersect);
                    }
                }
            }
            return intersect;
        }

        private ISet<string> UnionEmail(ISet<string> excluded, String email)
        {
            if (!excluded.Any())
            {
                if (email == null)
                {
                    return excluded;
                }
                excluded.Add(email);
                return excluded;
            }
            else
            {
                var union = new HashSet<string>();

                var it = excluded.GetEnumerator();
                while (it.MoveNext())
                {
                    String _excluded = (String)it.Current;

                    unionEmail(_excluded, email, union);
                }

                return union;
            }
        }

        /**
         * Returns the intersection of the permitted IP ranges in
         * <code>permitted</code> with <code>ip</code>.
         *
         * @param permitted A <code>Set</code> of permitted IP addresses with
         *                  their subnet mask as byte arrays.
         * @param ips       The IP address with its subnet mask.
         * @return The <code>Set</code> of permitted IP ranges intersected with
         *         <code>ip</code>.
         */
        private ISet<byte[]> IntersectIP(ISet<byte[]> permitted, ISet<GeneralSubtree> ips)
        {
            var intersect = new HashSet<byte[]>();
            for (var it = ips.GetEnumerator(); it.MoveNext(); )
            {
                byte[] ip = Asn1OctetString.GetInstance(
                    ((GeneralSubtree)it.Current).Base.Name).GetOctets();
                if (permitted == null)
                {
                    if (ip != null)
                    {
                        intersect.Add(ip);
                    }
                }
                else
                {
                    var it2 = permitted.GetEnumerator();
                    while (it2.MoveNext())
                    {
                        byte[] _permitted = (byte[])it2.Current;
                        foreach (var bytearray in IntersectIPRange(_permitted, ip))
                        {
                            intersect.Add(bytearray);
                        }
                    }
                }
            }
            return intersect;
        }

        /**
         * Returns the union of the excluded IP ranges in <code>excluded</code>
         * with <code>ip</code>.
         *
         * @param excluded A <code>Set</code> of excluded IP addresses with their
         *                 subnet mask as byte arrays.
         * @param ip       The IP address with its subnet mask.
         * @return The <code>Set</code> of excluded IP ranges unified with
         *         <code>ip</code> as byte arrays.
         */
        private ISet<byte[]> UnionIP(ISet<byte[]> excluded, byte[] ip)
        {
            if (!excluded.Any())
            {
                if (ip == null)
                {
                    return excluded;
                }
                excluded.Add(ip);

                return excluded;
            }
            else
            {
                var union = new HashSet<byte[]>();

                var it = excluded.GetEnumerator();
                while (it.MoveNext())
                {
                    byte[] _excluded = (byte[])it.Current;
                    foreach (var bytearray in UnionIPRange(_excluded, ip))
                    {
                        union.Add(bytearray);
                    }

                }

                return union;
            }
        }

        /**
         * Calculates the union if two IP ranges.
         *
         * @param ipWithSubmask1 The first IP address with its subnet mask.
         * @param ipWithSubmask2 The second IP address with its subnet mask.
         * @return A <code>Set</code> with the union of both addresses.
         */
        private ISet<byte[]> UnionIPRange(byte[] ipWithSubmask1, byte[] ipWithSubmask2)
        {
            var set = new HashSet<byte[]>();

            // difficult, adding always all IPs is not wrong
            if (Org.BouncyCastle.Utilities.Arrays.AreEqual(ipWithSubmask1, ipWithSubmask2))
            {
                set.Add(ipWithSubmask1);
            }
            else
            {
                set.Add(ipWithSubmask1);
                set.Add(ipWithSubmask2);
            }
            return set;
        }

        /**
         * Calculates the interesction if two IP ranges.
         *
         * @param ipWithSubmask1 The first IP address with its subnet mask.
         * @param ipWithSubmask2 The second IP address with its subnet mask.
         * @return A <code>Set</code> with the single IP address with its subnet
         *         mask as a byte array or an empty <code>Set</code>.
         */
        private ISet<byte[]> IntersectIPRange(byte[] ipWithSubmask1, byte[] ipWithSubmask2)
    {
        if (ipWithSubmask1.Length != ipWithSubmask2.Length)
        {
            //Collections.EMPTY_SET;
            return new HashSet<byte[]>();
        }

        byte[][] temp = ExtractIPsAndSubnetMasks(ipWithSubmask1, ipWithSubmask2);
        byte[] ip1 = temp[0];
        byte[] subnetmask1 = temp[1];
        byte[] ip2 = temp[2];
        byte[] subnetmask2 = temp[3];

        byte[][] minMax = MinMaxIPs(ip1, subnetmask1, ip2, subnetmask2);
        byte[] min;
        byte[] max;
        max = Min(minMax[1], minMax[3]);
        min = Max(minMax[0], minMax[2]);

        // minimum IP address must be bigger than max
        if (CompareTo(min, max) == 1)
        {
            //return Collections.EMPTY_SET;
            return new HashSet<byte[]>();
        }
        // OR keeps all significant bits
        byte[] ip = Or(minMax[0], minMax[2]);
        byte[] subnetmask = Or(subnetmask1, subnetmask2);

            //return new HashSet( ICollectionsingleton(IpWithSubnetMask(ip, subnetmask));
        var hs = new HashSet<byte[]>();
        hs.Add(IpWithSubnetMask(ip, subnetmask));

            return hs;
    }

        /**
         * Concatenates the IP address with its subnet mask.
         *
         * @param ip         The IP address.
         * @param subnetMask Its subnet mask.
         * @return The concatenated IP address with its subnet mask.
         */
        private byte[] IpWithSubnetMask(byte[] ip, byte[] subnetMask)
        {
            int ipLength = ip.Length;
            byte[] temp = new byte[ipLength * 2];
            Array.Copy(ip, 0, temp, 0, ipLength);
            Array.Copy(subnetMask, 0, temp, ipLength, ipLength);
            return temp;
        }

        /**
         * Splits the IP addresses and their subnet mask.
         *
         * @param ipWithSubmask1 The first IP address with the subnet mask.
         * @param ipWithSubmask2 The second IP address with the subnet mask.
         * @return An array with two elements. Each element contains the IP address
         *         and the subnet mask in this order.
         */
        private byte[][] ExtractIPsAndSubnetMasks(
            byte[] ipWithSubmask1,
            byte[] ipWithSubmask2)
    {
        int ipLength = ipWithSubmask1.Length / 2;
        byte[] ip1 = new byte[ipLength];
        byte[] subnetmask1 = new byte[ipLength];
        Array.Copy(ipWithSubmask1, 0, ip1, 0, ipLength);
        Array.Copy(ipWithSubmask1, ipLength, subnetmask1, 0, ipLength);

        byte[] ip2 = new byte[ipLength];
        byte[] subnetmask2 = new byte[ipLength];
        Array.Copy(ipWithSubmask2, 0, ip2, 0, ipLength);
        Array.Copy(ipWithSubmask2, ipLength, subnetmask2, 0, ipLength);
        return new byte[][]
            {ip1, subnetmask1, ip2, subnetmask2};
    }

        /**
         * Based on the two IP addresses and their subnet masks the IP range is
         * computed for each IP address - subnet mask pair and returned as the
         * minimum IP address and the maximum address of the range.
         *
         * @param ip1         The first IP address.
         * @param subnetmask1 The subnet mask of the first IP address.
         * @param ip2         The second IP address.
         * @param subnetmask2 The subnet mask of the second IP address.
         * @return A array with two elements. The first/second element contains the
         *         min and max IP address of the first/second IP address and its
         *         subnet mask.
         */
        private byte[][] MinMaxIPs(
            byte[] ip1,
            byte[] subnetmask1,
            byte[] ip2,
            byte[] subnetmask2)
        {
            int ipLength = ip1.Length;
            byte[] min1 = new byte[ipLength];
            byte[] max1 = new byte[ipLength];

            byte[] min2 = new byte[ipLength];
            byte[] max2 = new byte[ipLength];

            for (int i = 0; i < ipLength; i++)
            {
                min1[i] = (byte)(ip1[i] & subnetmask1[i]);
                max1[i] = (byte)(ip1[i] & subnetmask1[i] | ~subnetmask1[i]);

                min2[i] = (byte)(ip2[i] & subnetmask2[i]);
                max2[i] = (byte)(ip2[i] & subnetmask2[i] | ~subnetmask2[i]);
            }

            return new byte[][] { min1, max1, min2, max2 };
        }

        private void CheckPermittedEmail(ISet<string> permitted, String email)
        //throws PkixNameConstraintValidatorException
        {
            if (permitted == null)
            {
                return;
            }

            var it = permitted.GetEnumerator();

            while (it.MoveNext())
            {
                String str = ((String)it.Current);

                if (EmailIsConstrained(email, str))
                {
                    return;
                }
            }

            if (email.Length == 0 && permitted.Count() == 0)
            {
                return;
            }

            throw new PkixNameConstraintValidatorException(
                "Subject email address is not from a permitted subtree.");
        }

        private void CheckExcludedEmail(ISet<string> excluded, String email)
        //throws PkixNameConstraintValidatorException
        {
            if (!excluded.Any())
            {
                return;
            }

            var it = excluded.GetEnumerator();

            while (it.MoveNext())
            {
                String str = (String)it.Current;

                if (EmailIsConstrained(email, str))
                {
                    throw new PkixNameConstraintValidatorException(
                        "Email address is from an excluded subtree.");
                }
            }
        }

        /**
         * Checks if the IP <code>ip</code> is included in the permitted ISet
         * <code>permitted</code>.
         *
         * @param permitted A <code>Set</code> of permitted IP addresses with
         *                  their subnet mask as byte arrays.
         * @param ip        The IP address.
         * @throws PkixNameConstraintValidatorException
         *          if the IP is not permitted.
         */
        private void CheckPermittedIP(ISet<byte[]> permitted, byte[] ip)
        //throws PkixNameConstraintValidatorException
        {
            if (permitted == null)
            {
                return;
            }

            var it = permitted.GetEnumerator();

            while (it.MoveNext())
            {
                byte[] ipWithSubnet = (byte[])it.Current;

                if (IsIPConstrained(ip, ipWithSubnet))
                {
                    return;
                }
            }
            if (ip.Length == 0 && permitted.Count == 0)
            {
                return;
            }
            throw new PkixNameConstraintValidatorException(
                "IP is not from a permitted subtree.");
        }

        /**
         * Checks if the IP <code>ip</code> is included in the excluded ISet
         * <code>excluded</code>.
         *
         * @param excluded A <code>Set</code> of excluded IP addresses with their
         *                 subnet mask as byte arrays.
         * @param ip       The IP address.
         * @throws PkixNameConstraintValidatorException
         *          if the IP is excluded.
         */
        private void checkExcludedIP(ISet<byte[]> excluded, byte[] ip)
        //throws PkixNameConstraintValidatorException
        {
            if (!excluded.Any())
            {
                return;
            }

            var it = excluded.GetEnumerator();

            while (it.MoveNext())
            {
                byte[] ipWithSubnet = (byte[])it.Current;

                if (IsIPConstrained(ip, ipWithSubnet))
                {
                    throw new PkixNameConstraintValidatorException(
                        "IP is from an excluded subtree.");
                }
            }
        }

        /**
         * Checks if the IP address <code>ip</code> is constrained by
         * <code>constraint</code>.
         *
         * @param ip         The IP address.
         * @param constraint The constraint. This is an IP address concatenated with
         *                   its subnetmask.
         * @return <code>true</code> if constrained, <code>false</code>
         *         otherwise.
         */
        private bool IsIPConstrained(byte[] ip, byte[] constraint)
        {
            int ipLength = ip.Length;

            if (ipLength != (constraint.Length / 2))
            {
                return false;
            }

            byte[] subnetMask = new byte[ipLength];
            Array.Copy(constraint, ipLength, subnetMask, 0, ipLength);

            byte[] permittedSubnetAddress = new byte[ipLength];

            byte[] ipSubnetAddress = new byte[ipLength];

            // the resulting IP address by applying the subnet mask
            for (int i = 0; i < ipLength; i++)
            {
                permittedSubnetAddress[i] = (byte)(constraint[i] & subnetMask[i]);
                ipSubnetAddress[i] = (byte)(ip[i] & subnetMask[i]);
            }

            return Org.BouncyCastle.Utilities.Arrays.AreEqual(permittedSubnetAddress, ipSubnetAddress);
        }

        private bool EmailIsConstrained(String email, String constraint)
        {
            String sub = email.Substring(email.IndexOf('@') + 1);
            // a particular mailbox
            if (constraint.IndexOf('@') != -1)
            {
                if (Platform.ToUpperInvariant(email).Equals(Platform.ToUpperInvariant(constraint)))
                {
                    return true;
                }
            }
            // on particular host
            else if (!(constraint[0].Equals('.')))
            {
                if (Platform.ToUpperInvariant(sub).Equals(Platform.ToUpperInvariant(constraint)))
                {
                    return true;
                }
            }
            // address in sub domain
            else if (WithinDomain(sub, constraint))
            {
                return true;
            }
            return false;
        }

        private bool WithinDomain(String testDomain, String domain)
        {
            String tempDomain = domain;
            if (Platform.StartsWith(tempDomain, "."))
            {
                tempDomain = tempDomain.Substring(1);
            }
            String[] domainParts = tempDomain.Split('.'); // Strings.split(tempDomain, '.');
            String[] testDomainParts = testDomain.Split('.'); // Strings.split(testDomain, '.');

            // must have at least one subdomain
            if (testDomainParts.Length <= domainParts.Length)
            {
                return false;
            }

            int d = testDomainParts.Length - domainParts.Length;
            for (int i = -1; i < domainParts.Length; i++)
            {
                if (i == -1)
                {
                    if (testDomainParts[i + d].Equals(""))
                    {
                        return false;
                    }
                }
                else if (!Platform.EqualsIgnoreCase(testDomainParts[i + d], domainParts[i]))
                {
                    return false;
                }
            }
            return true;
        }

        private void CheckPermittedDNS(ISet<string> permitted, String dns)
        //throws PkixNameConstraintValidatorException
        {
            if (permitted == null)
            {
                return;
            }

            var it = permitted.GetEnumerator();

            while (it.MoveNext())
            {
                String str = ((String)it.Current);

                // is sub domain
                if (WithinDomain(dns, str)
                    || Platform.ToUpperInvariant(dns).Equals(Platform.ToUpperInvariant(str)))
                {
                    return;
                }
            }
            if (dns.Length == 0 && permitted.Count == 0)
            {
                return;
            }
            throw new PkixNameConstraintValidatorException(
                "DNS is not from a permitted subtree.");
        }

        private void checkExcludedDNS(ISet<string> excluded, String dns)
        //     throws PkixNameConstraintValidatorException
        {
            if (!excluded.Any())
            {
                return;
            }

            var it = excluded.GetEnumerator();

            while (it.MoveNext())
            {
                String str = ((String)it.Current);

                // is sub domain or the same
				if (WithinDomain(dns, str) || Platform.EqualsIgnoreCase(dns, str))
                {
                    throw new PkixNameConstraintValidatorException(
                        "DNS is from an excluded subtree.");
                }
            }
        }

        /**
         * The common part of <code>email1</code> and <code>email2</code> is
         * added to the union <code>union</code>. If <code>email1</code> and
         * <code>email2</code> have nothing in common they are added both.
         *
         * @param email1 Email address constraint 1.
         * @param email2 Email address constraint 2.
         * @param union  The union.
         */
        private void unionEmail(String email1, String email2, ISet<string> union)
        {
            // email1 is a particular address
            if (email1.IndexOf('@') != -1)
            {
                String _sub = email1.Substring(email1.IndexOf('@') + 1);
                // both are a particular mailbox
                if (email2.IndexOf('@') != -1)
                {
                    if (Platform.EqualsIgnoreCase(email1, email2))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(_sub, email2))
                    {
                        union.Add(email2);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                // email2 specifies a particular host
                else
                {
                    if (Platform.EqualsIgnoreCase(_sub, email2))
                    {
                        union.Add(email2);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
            }
            // email1 specifies a domain
            else if (Platform.StartsWith(email1, "."))
            {
                if (email2.IndexOf('@') != -1)
                {
                    String _sub = email2.Substring(email1.IndexOf('@') + 1);
                    if (WithinDomain(_sub, email1))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(email1, email2) || Platform.EqualsIgnoreCase(email1, email2))
                    {
                        union.Add(email2);
                    }
                    else if (WithinDomain(email2, email1))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                else
                {
                    if (WithinDomain(email2, email1))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
            }
            // email specifies a host
            else
            {
                if (email2.IndexOf('@') != -1)
                {
                    String _sub = email2.Substring(email1.IndexOf('@') + 1);
                    if (Platform.EqualsIgnoreCase(_sub, email1))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(email1, email2))
                    {
                        union.Add(email2);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                // email2 specifies a particular host
                else
                {
                    if (Platform.EqualsIgnoreCase(email1, email2))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
            }
        }

        private void unionURI(String email1, String email2, ISet<string> union)
        {
            // email1 is a particular address
            if (email1.IndexOf('@') != -1)
            {
                String _sub = email1.Substring(email1.IndexOf('@') + 1);
                // both are a particular mailbox
                if (email2.IndexOf('@') != -1)
                {
                    if (Platform.EqualsIgnoreCase(email1, email2))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(_sub, email2))
                    {
                        union.Add(email2);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                // email2 specifies a particular host
                else
                {
                    if (Platform.EqualsIgnoreCase(_sub, email2))
                    {
                        union.Add(email2);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);

                    }
                }
            }
            // email1 specifies a domain
            else if (Platform.StartsWith(email1, "."))
            {
                if (email2.IndexOf('@') != -1)
                {
                    String _sub = email2.Substring(email1.IndexOf('@') + 1);
                    if (WithinDomain(_sub, email1))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(email1, email2) || Platform.EqualsIgnoreCase(email1, email2))
                    {
                        union.Add(email2);
                    }
                    else if (WithinDomain(email2, email1))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                else
                {
                    if (WithinDomain(email2, email1))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
            }
            // email specifies a host
            else
            {
                if (email2.IndexOf('@') != -1)
                {
                    String _sub = email2.Substring(email1.IndexOf('@') + 1);
                    if (Platform.EqualsIgnoreCase(_sub, email1))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(email1, email2))
                    {
                        union.Add(email2);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                // email2 specifies a particular host
                else
                {
                    if (Platform.EqualsIgnoreCase(email1, email2))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
            }
        }

        private ISet<string> intersectDNS(ISet<string> permitted, ISet<GeneralSubtree> dnss)
        {
            var intersect = new HashSet<string>();
            for (var it = dnss.GetEnumerator(); it.MoveNext(); )
            {
                String dns = ExtractNameAsString(((GeneralSubtree)it.Current)
                    .Base);
                if (permitted == null)
                {
                    if (dns != null)
                    {
                        intersect.Add(dns);
                    }
                }
                else
                {
                    var _iter = permitted.GetEnumerator();
                    while (_iter.MoveNext())
                    {
                        String _permitted = (String)_iter.Current;

                        if (WithinDomain(_permitted, dns))
                        {
                            intersect.Add(_permitted);
                        }
                        else if (WithinDomain(dns, _permitted))
                        {
                            intersect.Add(dns);
                        }
                    }
                }
            }

            return intersect;
        }

        protected ISet<string> unionDNS(ISet<string> excluded, String dns)
        {
            if (!excluded.Any())
            {
                if (dns == null)
                {
                    return excluded;
                }
                excluded.Add(dns);

                return excluded;
            }
            else
            {
                var union = new HashSet<string>();

                var _iter = excluded.GetEnumerator();
                while (_iter.MoveNext())
                {
                    String _permitted = (String)_iter.Current;

                    if (WithinDomain(_permitted, dns))
                    {
                        union.Add(dns);
                    }
                    else if (WithinDomain(dns, _permitted))
                    {
                        union.Add(_permitted);
                    }
                    else
                    {
                        union.Add(_permitted);
                        union.Add(dns);
                    }
                }

                return union;
            }
        }

        /**
         * The most restricting part from <code>email1</code> and
         * <code>email2</code> is added to the intersection <code>intersect</code>.
         *
         * @param email1    Email address constraint 1.
         * @param email2    Email address constraint 2.
         * @param intersect The intersection.
         */
        private void intersectEmail(String email1, String email2, ISet<string> intersect)
        {
            // email1 is a particular address
            if (email1.IndexOf('@') != -1)
            {
                String _sub = email1.Substring(email1.IndexOf('@') + 1);
                // both are a particular mailbox
                if (email2.IndexOf('@') != -1)
                {
                    if (Platform.EqualsIgnoreCase(email1, email2))
                    {
                        intersect.Add(email1);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(_sub, email2))
                    {
                        intersect.Add(email1);
                    }
                }
                // email2 specifies a particular host
                else
                {
                    if (Platform.EqualsIgnoreCase(_sub, email2))
                    {
                        intersect.Add(email1);
                    }
                }
            }
            // email specifies a domain
            else if (Platform.StartsWith(email1, "."))
            {
                if (email2.IndexOf('@') != -1)
                {
                    String _sub = email2.Substring(email1.IndexOf('@') + 1);
                    if (WithinDomain(_sub, email1))
                    {
                        intersect.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(email1, email2) || Platform.EqualsIgnoreCase(email1, email2))
                    {
                        intersect.Add(email1);
                    }
                    else if (WithinDomain(email2, email1))
                    {
                        intersect.Add(email2);
                    }
                }
                else
                {
                    if (WithinDomain(email2, email1))
                    {
                        intersect.Add(email2);
                    }
                }
            }
            // email1 specifies a host
            else
            {
                if (email2.IndexOf('@') != -1)
                {
                    String _sub = email2.Substring(email2.IndexOf('@') + 1);
                    if (Platform.EqualsIgnoreCase(_sub, email1))
                    {
                        intersect.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(email1, email2))
                    {
                        intersect.Add(email1);
                    }
                }
                // email2 specifies a particular host
                else
                {
                    if (Platform.EqualsIgnoreCase(email1, email2))
                    {
                        intersect.Add(email1);
                    }
                }
            }
        }

        private void checkExcludedURI(ISet<string> excluded, String uri)
        //       throws PkixNameConstraintValidatorException
        {
            if (!excluded.Any())
            {
                return;
            }

            var it = excluded.GetEnumerator();

            while (it.MoveNext())
            {
                String str = ((String)it.Current);

                if (IsUriConstrained(uri, str))
                {
                    throw new PkixNameConstraintValidatorException(
                        "URI is from an excluded subtree.");
                }
            }
        }

        private ISet<string> intersectURI(ISet<string> permitted, ISet<GeneralSubtree> uris)
        {
            var intersect = new HashSet<string>();
            for (var it = uris.GetEnumerator(); it.MoveNext(); )
            {
                String uri = ExtractNameAsString(((GeneralSubtree)it.Current)
                    .Base);
                if (permitted == null)
                {
                    if (uri != null)
                    {
                        intersect.Add(uri);
                    }
                }
                else
                {
                    var _iter = permitted.GetEnumerator();
                    while (_iter.MoveNext())
                    {
                        String _permitted = (String)_iter.Current;
                        intersectURI(_permitted, uri, intersect);
                    }
                }
            }
            return intersect;
        }

        private ISet<string> unionURI(ISet<string> excluded, String uri)
        {
            if (!excluded.Any())
            {
                if (uri == null)
                {
                    return excluded;
                }
                excluded.Add(uri);

                return excluded;
            }
            else
            {
                var union = new HashSet<string>();

                var _iter = excluded.GetEnumerator();
                while (_iter.MoveNext())
                {
                    String _excluded = (String)_iter.Current;

                    unionURI(_excluded, uri, union);
                }

                return union;
            }
        }

        private void intersectURI(String email1, String email2, ISet<string> intersect)
        {
            // email1 is a particular address
            if (email1.IndexOf('@') != -1)
            {
                String _sub = email1.Substring(email1.IndexOf('@') + 1);
                // both are a particular mailbox
                if (email2.IndexOf('@') != -1)
                {
                    if (Platform.EqualsIgnoreCase(email1, email2))
                    {
                        intersect.Add(email1);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(_sub, email2))
                    {
                        intersect.Add(email1);
                    }
                }
                // email2 specifies a particular host
                else
                {
                    if (Platform.EqualsIgnoreCase(_sub, email2))
                    {
                        intersect.Add(email1);
                    }
                }
            }
            // email specifies a domain
            else if (Platform.StartsWith(email1, "."))
            {
                if (email2.IndexOf('@') != -1)
                {
                    String _sub = email2.Substring(email1.IndexOf('@') + 1);
                    if (WithinDomain(_sub, email1))
                    {
                        intersect.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(email1, email2) || Platform.EqualsIgnoreCase(email1, email2))
                    {
                        intersect.Add(email1);
                    }
                    else if (WithinDomain(email2, email1))
                    {
                        intersect.Add(email2);
                    }
                }
                else
                {
                    if (WithinDomain(email2, email1))
                    {
                        intersect.Add(email2);
                    }
                }
            }
            // email1 specifies a host
            else
            {
                if (email2.IndexOf('@') != -1)
                {
                    String _sub = email2.Substring(email2.IndexOf('@') + 1);
                    if (Platform.EqualsIgnoreCase(_sub, email1))
                    {
                        intersect.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(email1, email2))
                    {
                        intersect.Add(email1);
                    }
                }
                // email2 specifies a particular host
                else
                {
                    if (Platform.EqualsIgnoreCase(email1, email2))
                    {
                        intersect.Add(email1);
                    }
                }
            }
        }

        private void CheckPermittedURI(ISet<string> permitted, String uri)
        //        throws PkixNameConstraintValidatorException
        {
            if (permitted == null)
            {
                return;
            }

            var it = permitted.GetEnumerator();

            while (it.MoveNext())
            {
                String str = ((String)it.Current);

                if (IsUriConstrained(uri, str))
                {
                    return;
                }
            }
            if (uri.Length == 0 && permitted.Count == 0)
            {
                return;
            }
            throw new PkixNameConstraintValidatorException(
                "URI is not from a permitted subtree.");
        }

        private bool IsUriConstrained(String uri, String constraint)
        {
            String host = ExtractHostFromURL(uri);
            // a host
            if (!Platform.StartsWith(constraint, "."))
            {
                if (Platform.EqualsIgnoreCase(host, constraint))
                {
                    return true;
                }
            }

            // in sub domain or domain
            else if (WithinDomain(host, constraint))
            {
                return true;
            }

            return false;
        }

        private static String ExtractHostFromURL(String url)
        {
            // see RFC 1738
            // remove ':' after protocol, e.g. http:
            String sub = url.Substring(url.IndexOf(':') + 1);
            // extract host from Common Internet Scheme Syntax, e.g. http://
            int idxOfSlashes = Platform.IndexOf(sub, "//");
            if (idxOfSlashes != -1)
            {
                sub = sub.Substring(idxOfSlashes + 2);
            }
            // first remove port, e.g. http://test.com:21
            if (sub.LastIndexOf(':') != -1)
            {
                sub = sub.Substring(0, sub.LastIndexOf(':'));
            }
            // remove user and password, e.g. http://john:password@test.com
            sub = sub.Substring(sub.IndexOf(':') + 1);
            sub = sub.Substring(sub.IndexOf('@') + 1);
            // remove local parts, e.g. http://test.com/bla
            if (sub.IndexOf('/') != -1)
            {
                sub = sub.Substring(0, sub.IndexOf('/'));
            }
            return sub;
        }

        /**
         * Checks if the given GeneralName is in the permitted ISet.
         *
         * @param name The GeneralName
         * @throws PkixNameConstraintValidatorException
         *          If the <code>name</code>
         */
        public void checkPermitted(GeneralName name)
        //        throws PkixNameConstraintValidatorException
        {
            switch (name.TagNo)
            {
                case 1:
                    CheckPermittedEmail(permittedSubtreesEmail,
                        ExtractNameAsString(name));
                    break;
                case 2:
                    CheckPermittedDNS(permittedSubtreesDNS, DerIA5String.GetInstance(
                        name.Name).GetString());
                    break;
                case 4:
                    CheckPermittedDN(Asn1Sequence.GetInstance(name.Name.ToAsn1Object()));
                    break;
                case 6:
                    CheckPermittedURI(permittedSubtreesURI, DerIA5String.GetInstance(
                        name.Name).GetString());
                    break;
                case 7:
                    byte[] ip = Asn1OctetString.GetInstance(name.Name).GetOctets();

                    CheckPermittedIP(permittedSubtreesIP, ip);
                    break;
            }
        }

        /**
         * Check if the given GeneralName is contained in the excluded ISet.
         *
         * @param name The GeneralName.
         * @throws PkixNameConstraintValidatorException
         *          If the <code>name</code> is
         *          excluded.
         */
        public void checkExcluded(GeneralName name)
        //        throws PkixNameConstraintValidatorException
        {
            switch (name.TagNo)
            {
                case 1:
                    CheckExcludedEmail(excludedSubtreesEmail, ExtractNameAsString(name));
                    break;
                case 2:
                    checkExcludedDNS(excludedSubtreesDNS, DerIA5String.GetInstance(
                        name.Name).GetString());
                    break;
                case 4:
                    CheckExcludedDN(Asn1Sequence.GetInstance(name.Name.ToAsn1Object()));
                    break;
                case 6:
                    checkExcludedURI(excludedSubtreesURI, DerIA5String.GetInstance(
                        name.Name).GetString());
                    break;
                case 7:
                    byte[] ip = Asn1OctetString.GetInstance(name.Name).GetOctets();

                    checkExcludedIP(excludedSubtreesIP, ip);
                    break;
            }
        }

        /**
         * Updates the permitted ISet<string> of these name constraints with the intersection
         * with the given subtree.
         *
         * @param permitted The permitted subtrees
         */

        public void IntersectPermittedSubtree(Asn1Sequence permitted)
        {
            var subtreesMap = Platform.CreateDictionary<int, ISet<GeneralSubtree>>();

            // group in ISets in a map ordered by tag no.
            for (var e = permitted.GetEnumerator(); e.MoveNext(); )
            {
                GeneralSubtree subtree = GeneralSubtree.GetInstance(e.Current);

                int tagNo = subtree.Base.TagNo;
                ISet<GeneralSubtree> subtreeSet;
                if (!subtreesMap.TryGetValue(tagNo, out subtreeSet))
                {
                    subtreesMap[tagNo] = new HashSet<GeneralSubtree>();
                }

                (subtreesMap[tagNo]).Add(subtree);
            }

            for (var it = subtreesMap.GetEnumerator(); it.MoveNext(); )
            {
                var entry = it.Current;

                // go through all subtree groups
                switch ((int)entry.Key )
                {
                    case 1:
                        permittedSubtreesEmail = IntersectEmail(permittedSubtreesEmail,
                            entry.Value);
                        break;
                    case 2:
                        permittedSubtreesDNS = intersectDNS(permittedSubtreesDNS,
                            entry.Value);
                        break;
                    case 4:
                        permittedSubtreesDN = IntersectDN(permittedSubtreesDN,
                            entry.Value);
                        break;
                    case 6:
                        permittedSubtreesURI = intersectURI(permittedSubtreesURI,
                            entry.Value);
                        break;
                    case 7:
                        permittedSubtreesIP = IntersectIP(permittedSubtreesIP,
                            entry.Value);
                        break;
                }
            }
        }

        private String ExtractNameAsString(GeneralName name)
        {
            return DerIA5String.GetInstance(name.Name).GetString();
        }

        public void IntersectEmptyPermittedSubtree(int nameType)
        {
            switch (nameType)
            {
                case 1:
                    permittedSubtreesEmail = new HashSet<string>();
                    break;
                case 2:
                    permittedSubtreesDNS = new HashSet<string>();
                    break;
                case 4:
                    permittedSubtreesDN = new HashSet<Asn1Sequence>();
                    break;
                case 6:
                    permittedSubtreesURI = new HashSet<string>();
                    break;
                case 7:
                    permittedSubtreesIP = new HashSet<byte[]>();
                    break;
            }
        }

        /**
         * Adds a subtree to the excluded ISet<string> of these name constraints.
         *
         * @param subtree A subtree with an excluded GeneralName.
         */
        public void AddExcludedSubtree(GeneralSubtree subtree)
        {
            GeneralName subTreeBase = subtree.Base;

            switch (subTreeBase.TagNo)
            {
                case 1:
                    excludedSubtreesEmail = UnionEmail(excludedSubtreesEmail,
                        ExtractNameAsString(subTreeBase));
                    break;
                case 2:
                    excludedSubtreesDNS = unionDNS(excludedSubtreesDNS,
                        ExtractNameAsString(subTreeBase));
                    break;
                case 4:
                    excludedSubtreesDN = UnionDN(excludedSubtreesDN,
                        (Asn1Sequence)subTreeBase.Name.ToAsn1Object());
                    break;
                case 6:
                    excludedSubtreesURI = unionURI(excludedSubtreesURI,
                        ExtractNameAsString(subTreeBase));
                    break;
                case 7:
                    excludedSubtreesIP = UnionIP(excludedSubtreesIP, Asn1OctetString
                        .GetInstance(subTreeBase.Name).GetOctets());
                    break;
            }
        }

        /**
         * Returns the maximum IP address.
         *
         * @param ip1 The first IP address.
         * @param ip2 The second IP address.
         * @return The maximum IP address.
         */
        private static byte[] Max(byte[] ip1, byte[] ip2)
        {
            for (int i = 0; i < ip1.Length; i++)
            {
                if ((ip1[i] & 0xFFFF) > (ip2[i] & 0xFFFF))
                {
                    return ip1;
                }
            }
            return ip2;
        }

        /**
         * Returns the minimum IP address.
         *
         * @param ip1 The first IP address.
         * @param ip2 The second IP address.
         * @return The minimum IP address.
         */
        private static byte[] Min(byte[] ip1, byte[] ip2)
        {
            for (int i = 0; i < ip1.Length; i++)
            {
                if ((ip1[i] & 0xFFFF) < (ip2[i] & 0xFFFF))
                {
                    return ip1;
                }
            }
            return ip2;
        }

        /**
         * Compares IP address <code>ip1</code> with <code>ip2</code>. If ip1
         * is equal to ip2 0 is returned. If ip1 is bigger 1 is returned, -1
         * otherwise.
         *
         * @param ip1 The first IP address.
         * @param ip2 The second IP address.
         * @return 0 if ip1 is equal to ip2, 1 if ip1 is bigger, -1 otherwise.
         */
        private static int CompareTo(byte[] ip1, byte[] ip2)
        {
            if (Org.BouncyCastle.Utilities.Arrays.AreEqual(ip1, ip2))
            {
                return 0;
            }
            if (Org.BouncyCastle.Utilities.Arrays.AreEqual(Max(ip1, ip2), ip1))
            {
                return 1;
            }
            return -1;
        }

        /**
         * Returns the logical OR of the IP addresses <code>ip1</code> and
         * <code>ip2</code>.
         *
         * @param ip1 The first IP address.
         * @param ip2 The second IP address.
         * @return The OR of <code>ip1</code> and <code>ip2</code>.
         */
        private static byte[] Or(byte[] ip1, byte[] ip2)
        {
            byte[] temp = new byte[ip1.Length];
            for (int i = 0; i < ip1.Length; i++)
            {
                temp[i] = (byte)(ip1[i] | ip2[i]);
            }
            return temp;
        }

		[Obsolete("Use GetHashCode instead")]
		public int HashCode()
		{
			return GetHashCode();
		}

		public override int GetHashCode()
        {
            return HashCollection(excludedSubtreesDN)
                + HashCollection(excludedSubtreesDNS)
                + HashCollection(excludedSubtreesEmail)
                + HashCollection(excludedSubtreesIP)
                + HashCollection(excludedSubtreesURI)
                + HashCollection(permittedSubtreesDN)
                + HashCollection(permittedSubtreesDNS)
                + HashCollection(permittedSubtreesEmail)
                + HashCollection(permittedSubtreesIP)
                + HashCollection(permittedSubtreesURI);
        }

        private int HashCollection<T>(ICollection<T> coll)
        {
            if (coll == null)
            {
                return 0;
            }
            int hash = 0;
            var it1 = coll.GetEnumerator();
            while (it1.MoveNext())
            {
                T o = it1.Current;
                var bytearray = o as byte[];
                if (bytearray != null)
                {
                    hash += Org.BouncyCastle.Utilities.Arrays.GetHashCode(bytearray);
                }
                else
                {
                    hash += o.GetHashCode();
                }
            }
            return hash;
        }

		public override bool Equals(Object o)
		{
			if (!(o is PkixNameConstraintValidator))
				return false;

			PkixNameConstraintValidator constraintValidator = (PkixNameConstraintValidator)o;

			return CollectionsAreEqual(constraintValidator.excludedSubtreesDN, excludedSubtreesDN)
				&& CollectionsAreEqual(constraintValidator.excludedSubtreesDNS, excludedSubtreesDNS)
				&& CollectionsAreEqual(constraintValidator.excludedSubtreesEmail, excludedSubtreesEmail)
				&& CollectionsAreEqual(constraintValidator.excludedSubtreesIP, excludedSubtreesIP)
				&& CollectionsAreEqual(constraintValidator.excludedSubtreesURI, excludedSubtreesURI)
				&& CollectionsAreEqual(constraintValidator.permittedSubtreesDN, permittedSubtreesDN)
				&& CollectionsAreEqual(constraintValidator.permittedSubtreesDNS, permittedSubtreesDNS)
				&& CollectionsAreEqual(constraintValidator.permittedSubtreesEmail, permittedSubtreesEmail)
				&& CollectionsAreEqual(constraintValidator.permittedSubtreesIP, permittedSubtreesIP)
				&& CollectionsAreEqual(constraintValidator.permittedSubtreesURI, permittedSubtreesURI);
		}

        private bool CollectionsAreEqual<T>(ICollection<T> coll1, ICollection<T> coll2)
        {
            if (coll1 == coll2)
            {
                return true;
            }
            if (coll1 == null || coll2 == null)
            {
                return false;
            }
            if (coll1.Count != coll2.Count)
            {
                return false;
            }
            var it1 = coll1.GetEnumerator();

            while (it1.MoveNext())
            {
                T a = it1.Current;
                var it2 = coll2.GetEnumerator();
                bool found = false;
                while (it2.MoveNext())
                {
                    Object b = it2.Current;
                    if (SpecialEquals(a, b))
                    {
                        found = true;
                        break;
                    }
                }
                if (!found)
                {
                    return false;
                }
            }
            return true;
        }

        private bool SpecialEquals(Object o1, Object o2)
        {
            if (o1 == o2)
            {
                return true;
            }
            if (o1 == null || o2 == null)
            {
                return false;
            }
            if ((o1 is byte[]) && (o2 is byte[]))
            {
                return Org.BouncyCastle.Utilities.Arrays.AreEqual((byte[])o1, (byte[])o2);
            }
            else
            {
                return o1.Equals(o2);
            }
        }

        /**
         * Stringifies an IPv4 or v6 address with subnet mask.
         *
         * @param ip The IP with subnet mask.
         * @return The stringified IP address.
         */
        private String StringifyIP(byte[] ip)
        {
            String temp = "";
            for (int i = 0; i < ip.Length / 2; i++)
            {
                //temp += Integer.toString(ip[i] & 0x00FF) + ".";
                temp += (ip[i] & 0x00FF) + ".";
            }
            temp = temp.Substring(0, temp.Length - 1);
            temp += "/";
            for (int i = ip.Length / 2; i < ip.Length; i++)
            {
                //temp += Integer.toString(ip[i] & 0x00FF) + ".";
                temp += (ip[i] & 0x00FF) + ".";
            }
            temp = temp.Substring(0, temp.Length - 1);
            return temp;
        }

        private String StringifyIPCollection(ISet<byte[]> ips)
        {
            String temp = "";
            temp += "[";
            for (var it = ips.GetEnumerator(); it.MoveNext(); )
            {
                temp += StringifyIP((byte[])it.Current) + ",";
            }
            if (temp.Length > 1)
            {
                temp = temp.Substring(0, temp.Length - 1);
            }
            temp += "]";

            return temp;
        }

        public override String ToString()
        {
            String temp = "";

            temp += "permitted:\n";
            if (permittedSubtreesDN != null)
            {
                temp += "DN:\n";
                temp += permittedSubtreesDN.ToString() + "\n";
            }
            if (permittedSubtreesDNS != null)
            {
                temp += "DNS:\n";
                temp += permittedSubtreesDNS.ToString() + "\n";
            }
            if (permittedSubtreesEmail != null)
            {
                temp += "Email:\n";
                temp += permittedSubtreesEmail.ToString() + "\n";
            }
            if (permittedSubtreesURI != null)
            {
                temp += "URI:\n";
                temp += permittedSubtreesURI.ToString() + "\n";
            }
            if (permittedSubtreesIP != null)
            {
                temp += "IP:\n";
                temp += StringifyIPCollection(permittedSubtreesIP) + "\n";
            }
            temp += "excluded:\n";
            if (excludedSubtreesDN.Any())
            {
                temp += "DN:\n";
                temp += excludedSubtreesDN.ToString() + "\n";
            }
            if (excludedSubtreesDNS.Any())
            {
                temp += "DNS:\n";
                temp += excludedSubtreesDNS.ToString() + "\n";
            }
            if (excludedSubtreesEmail.Any())
            {
                temp += "Email:\n";
                temp += excludedSubtreesEmail.ToString() + "\n";
            }
            if (excludedSubtreesURI.Any())
            {
                temp += "URI:\n";
                temp += excludedSubtreesURI.ToString() + "\n";
            }
            if (excludedSubtreesIP.Any())
            {
                temp += "IP:\n";
                temp += StringifyIPCollection(excludedSubtreesIP) + "\n";
            }
            return temp;
        }

    }
}
