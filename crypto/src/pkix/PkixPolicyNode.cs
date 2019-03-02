using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Pkix
{
	/// <summary>
	/// Summary description for PkixPolicyNode.
	/// </summary>
	public class PkixPolicyNode
//		: IPolicyNode
	{
		protected IList<PkixPolicyNode>              mChildren;
		protected int				mDepth;
		protected ISet<string> mExpectedPolicies;
		protected PkixPolicyNode	mParent;
		protected ISet<PolicyQualifierInfo> mPolicyQualifiers;
		protected string			mValidPolicy;
		protected bool				mCritical;

		public virtual int Depth
		{
			get { return this.mDepth; }
		}

		public virtual IEnumerable<PkixPolicyNode> Children
		{
			get { return new EnumerableProxy<PkixPolicyNode>(mChildren); }
		}

		public virtual bool IsCritical
		{
			get { return this.mCritical; }
			set { this.mCritical = value; }
		}

		public virtual ISet<PolicyQualifierInfo> PolicyQualifiers
		{
			get { return new HashSet<PolicyQualifierInfo>(this.mPolicyQualifiers); }
		}

		public virtual string ValidPolicy
		{
			get { return this.mValidPolicy; }
		}

		public virtual bool HasChildren
		{
			get { return mChildren.Count != 0; }
		}

		public virtual ISet<string> ExpectedPolicies
		{
			get { return new HashSet<string>(this.mExpectedPolicies); }
			set { this.mExpectedPolicies = new HashSet<string>(value); }
		}

		public virtual PkixPolicyNode Parent
		{
			get { return this.mParent; }
			set { this.mParent = value; }
		}

		/// Constructors
		public PkixPolicyNode(
			IList<PkixPolicyNode>            children,
			int				depth,
			ISet<string>			expectedPolicies,
			PkixPolicyNode	parent,
			ISet<PolicyQualifierInfo> policyQualifiers,
			string			validPolicy,
			bool			critical)
		{
            if (children == null)
            {
                this.mChildren = Platform.CreateList<PkixPolicyNode>();
            }
            else
            {
                this.mChildren = Platform.CreateList(children);
            }

            this.mDepth = depth;
			this.mExpectedPolicies = expectedPolicies;
			this.mParent = parent;
			this.mPolicyQualifiers = policyQualifiers;
			this.mValidPolicy = validPolicy;
			this.mCritical = critical;
		}

		public virtual void AddChild(
			PkixPolicyNode child)
		{
			child.Parent = this;
			mChildren.Add(child);
		}

		public virtual void RemoveChild(
			PkixPolicyNode child)
		{
			mChildren.Remove(child);
		}

		public override string ToString()
		{
			return ToString("");
		}

		public virtual string ToString(
			string indent)
		{
			StringBuilder buf = new StringBuilder();
			buf.Append(indent);
			buf.Append(mValidPolicy);
			buf.Append(" {");
			buf.Append(Platform.NewLine);

			foreach (var child in mChildren)
			{
				buf.Append(child.ToString(indent + "    "));
			}

			buf.Append(indent);
			buf.Append("}");
			buf.Append(Platform.NewLine);
			return buf.ToString();
		}

		public virtual object Clone()
		{
			return Copy();
		}

		public virtual PkixPolicyNode Copy()
		{
			PkixPolicyNode node = new PkixPolicyNode(
                Platform.CreateList<PkixPolicyNode>(),
				mDepth,
				new HashSet<string>(mExpectedPolicies),
				null,
				new HashSet<PolicyQualifierInfo>(mPolicyQualifiers),
				mValidPolicy,
				mCritical);

			foreach (var child in mChildren)
			{
				PkixPolicyNode copy = child.Copy();
				copy.Parent = node;
				node.AddChild(copy);
			}

			return node;
		}
	}
}
