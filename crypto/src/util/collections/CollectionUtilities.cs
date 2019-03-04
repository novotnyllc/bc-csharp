using System;

using System.Collections.Generic;
using System.Text;

namespace Org.BouncyCastle.Utilities.Collections
{
    public abstract class CollectionUtilities
    {
        public static void AddRange<T>(IList<T> to, IEnumerable<T> range)
        {
            foreach (var o in range)
            {
                to.Add(o);
            }
        }

        public static bool CheckElementsAreOfType(IEnumerable<object> e, Type t)
        {
            foreach (var o in e)
            {
                if (!t.IsInstanceOfType(o))
                    return false;
            }
            return true;
        }

        public static IDictionary<TKey, TValue> ReadOnly<TKey, TValue>(IDictionary<TKey, TValue> d)
        {
            return new UnmodifiableDictionaryProxy<TKey, TValue>(d);
        }

        public static IList<T> ReadOnly<T>(IList<T> l)
        {
            return new UnmodifiableListProxy<T>(l);
        }

        public static ISet<T> ReadOnly<T>(ISet<T> s)
        {
            return new UnmodifiableSetProxy<T>(s);
        }

        public static T RequireNext<T>(IEnumerator<T> e)
        {
            if (!e.MoveNext())
                throw new InvalidOperationException();

            return e.Current;
        }

        public static string ToString<T>(IEnumerable<T> c)
        {
            StringBuilder sb = new StringBuilder("[");

            var e = c.GetEnumerator();

            if (e.MoveNext())
            {
                sb.Append(e.Current.ToString());

                while (e.MoveNext())
                {
                    sb.Append(", ");
                    sb.Append(e.Current.ToString());
                }
            }

            sb.Append(']');

            return sb.ToString();
        }
    }
}
