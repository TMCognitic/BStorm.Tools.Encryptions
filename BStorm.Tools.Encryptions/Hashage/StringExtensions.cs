using System.Text;

namespace BStorm.Tools.Encryptions.Hashage
{
    public static class StringExtensions
    {
        public static byte[] Hash(this string s)
        {
            ArgumentNullException.ThrowIfNull(s, nameof(s));
            byte[] bytes = Encoding.Unicode.GetBytes(s);
            return bytes.Hash();
        }
    }
}
