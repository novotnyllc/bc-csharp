using System;
using System.Text;

#if NETCF_1_0 || NETCF_2_0 || SILVERLIGHT || PORTABLE

using System.Reflection;
#endif

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Utilities
{
    internal abstract class Enums
    {
        internal static TEnum GetEnumValue<TEnum>(string s) where TEnum : struct
        {
            if (!IsEnumType<TEnum>())
                throw new ArgumentException("Not an enumeration type", "enumType");

            // We only want to parse single named constants
            if (s.Length > 0 && char.IsLetter(s[0]) && s.IndexOf(',') < 0)
            {
                s = s.Replace('-', '_');
                s = s.Replace('/', '_');

                TEnum result;
                Enum.TryParse(s, false, out result);
                return result;
            }

            throw new ArgumentException();
        }

        internal static Array GetEnumValues<TEnum>() where TEnum : struct
        {
            if (!IsEnumType<TEnum>())
                throw new ArgumentException("Not an enumeration type", "enumType");

            return Enum.GetValues(typeof(TEnum));
        }

        internal static TEnum GetArbitraryValue<TEnum>() where TEnum : struct
        {
            Array values = GetEnumValues<TEnum>();
            int pos = (int)(DateTimeUtilities.CurrentUnixMs() & int.MaxValue) % values.Length;
            return (TEnum)values.GetValue(pos);
        }

        internal static bool IsEnumType<TEnum>() where TEnum : struct
        {
#if PORTABLE
            return typeof(TEnum).GetTypeInfo().IsEnum;
#else
            return typeof(TEnum).IsEnum;
#endif
        }
    }
}
