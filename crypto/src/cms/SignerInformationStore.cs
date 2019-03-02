using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cms
{
    public class SignerInformationStore
    {
        private readonly IList<SignerInformation> all;
        private readonly IDictionary<SignerID, IList<SignerInformation>> table = Platform.CreateDictionary<SignerID, IList<SignerInformation>>();

        /**
         * Create a store containing a single SignerInformation object.
         *
         * @param signerInfo the signer information to contain.
         */
        public SignerInformationStore(
            SignerInformation signerInfo)
        {
            this.all = Platform.CreateList<SignerInformation>(1);
            this.all.Add(signerInfo);

            SignerID sid = signerInfo.SignerID;

            table[sid] = all;
        }

        /**
         * Create a store containing a collection of SignerInformation objects.
         *
         * @param signerInfos a collection signer information objects to contain.
         */
        public SignerInformationStore(
            ICollection<SignerInformation> signerInfos)
        {
            foreach (var signer in signerInfos)
            {
                SignerID sid = signer.SignerID;
                IList<SignerInformation> list;

                if (!table.TryGetValue(sid, out list))
                {
                    table[sid] = list = Platform.CreateList<SignerInformation>(1);
                }

                list.Add(signer);
            }

            this.all = Platform.CreateList(signerInfos);
        }

        /**
        * Return the first SignerInformation object that matches the
        * passed in selector. Null if there are no matches.
        *
        * @param selector to identify a signer
        * @return a single SignerInformation object. Null if none matches.
        */
        public SignerInformation GetFirstSigner(
            SignerID selector)
        {
            var list = table[selector];

            return list == null ? null : list[0];
        }

        /// <summary>The number of signers in the collection.</summary>
        public int Count
        {
            get { return all.Count; }
        }

        /// <returns>An ICollection of all signers in the collection</returns>
        public ICollection<SignerInformation> GetSigners()
        {
            return Platform.CreateList(all);
        }

        /**
        * Return possible empty collection with signers matching the passed in SignerID
        *
        * @param selector a signer id to select against.
        * @return a collection of SignerInformation objects.
        */
        public ICollection<SignerInformation> GetSigners(
            SignerID selector)
        {
            var list = table[selector];

            return list == null ? Platform.CreateList<SignerInformation>() : Platform.CreateList(list);
        }
    }
}
