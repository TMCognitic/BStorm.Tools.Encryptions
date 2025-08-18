using System.Security.Cryptography;

namespace BStorm.Tools.Encryptions.Hashage
{
    public static class ByteArrayExtensions
    {
        public static byte[] Hash(this byte[] content)
        {
            ArgumentNullException.ThrowIfNull(content, nameof(content));
            return SHA512.HashData(content);
        }
    }
}
