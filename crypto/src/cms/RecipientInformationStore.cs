using System;
using System.Collections;
using System.Collections.Generic;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cms
{
	public class RecipientInformationStore
	{
		private readonly IList<RecipientInformation> all;
		private readonly IDictionary<RecipientID, IList<RecipientInformation>> table = Platform.CreateDictionary<RecipientID, IList<RecipientInformation>>();

		public RecipientInformationStore(
			ICollection<RecipientInformation> recipientInfos)
		{
			foreach (var recipientInformation in recipientInfos)
			{
				RecipientID rid = recipientInformation.RecipientID;
                IList<RecipientInformation> list;

				if (!table.TryGetValue(rid, out list))
				{
					table[rid] = list = Platform.CreateList<RecipientInformation>(1);
				}

				list.Add(recipientInformation);
			}

            this.all = Platform.CreateList(recipientInfos);
		}

		public RecipientInformation this[RecipientID selector]
		{
			get { return GetFirstRecipient(selector); }
		}

		/**
		* Return the first RecipientInformation object that matches the
		* passed in selector. Null if there are no matches.
		*
		* @param selector to identify a recipient
		* @return a single RecipientInformation object. Null if none matches.
		*/
		public RecipientInformation GetFirstRecipient(
			RecipientID selector)
		{
			var list = table[selector];

			return list == null ? null : list[0];
		}

		/**
		* Return the number of recipients in the collection.
		*
		* @return number of recipients identified.
		*/
		public int Count
		{
			get { return all.Count; }
		}

		/**
		* Return all recipients in the collection
		*
		* @return a collection of recipients.
		*/
		public ICollection<RecipientInformation> GetRecipients()
		{
			return Platform.CreateList(all);
		}

		/**
		* Return possible empty collection with recipients matching the passed in RecipientID
		*
		* @param selector a recipient id to select against.
		* @return a collection of RecipientInformation objects.
		*/
		public ICollection<RecipientInformation> GetRecipients(
			RecipientID selector)
		{
            var list = table[selector];

            return list == null ? Platform.CreateList<RecipientInformation>() : Platform.CreateList(list);
		}
	}
}
