using System.Security.Cryptography;
using System.Text;

namespace BStorm.Tools.Encryptions.Hashhage
{
    public static class StringExtensions
    {
        public static string Hash(this string s)
        {
            ArgumentNullException.ThrowIfNull(s, nameof(s));
            byte[] bytes = Encoding.Unicode.GetBytes(s);
            byte[] result = SHA512.HashData(bytes);
            return Convert.ToBase64String(result);
        }
    }
}
