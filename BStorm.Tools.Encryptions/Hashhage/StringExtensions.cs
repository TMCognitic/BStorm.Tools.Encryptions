using System.Security.Cryptography;
using System.Text;

namespace BStorm.Tools.Encryptions.Hashhage
{
    public static class StringExtensions
    {
        public static string Hash(this string s)
        {
            byte[] bytes = Encoding.Default.GetBytes(s);
            byte[] result = SHA512.HashData(bytes);
            return Convert.ToBase64String(result);
        }
    }
}
