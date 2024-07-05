
using System.Security.Cryptography;
using System.Text;

namespace BStorm.Tools.Encryptions.Cryptography.Symmetric
{
    public class AesEncryption
    {
        private readonly byte[] _key;
        private readonly byte[] _iv;
        public byte[] Key { get { return _key; } }
        public byte[] IV { get { return _iv; } }

        public AesEncryption()
        {
            Aes aes = Aes.Create();
            _key = aes.Key;
            _iv = aes.IV;
        }

        public AesEncryption(byte[] key, byte[] iv)
        {
            _key = key;
            _iv = iv;
        }

        public string Encrypt(string text)
        {
            using (Aes aes = Aes.Create())
            {
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    aes.Key = _key;
                    aes.IV = _iv;

                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        // Par défaut, Le StreamWriter utilise l'UTF-8.
                        using (StreamWriter encryptWriter = new StreamWriter(cryptoStream, Encoding.Default))
                        {
                            encryptWriter.Write(text);
                        }

                        return Convert.ToBase64String(memoryStream.ToArray());
                    }
                }
            }
        }

        public string Decrypt(string cipher)
        {
            byte[] bytes = Convert.FromBase64String(cipher);
            using (Aes aes = Aes.Create())
            {
                using (MemoryStream memoryStream = new MemoryStream(bytes))
                {
                    aes.Key = _key;
                    aes.IV = _iv;

                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        // Par défaut, Le StreamReader utilise l'UTF-8.
                        using (StreamReader decryptWriter = new StreamReader(cryptoStream, Encoding.Default))
                        {
                            return decryptWriter.ReadToEndAsync().Result;
                        }
                    }
                }
            }
        }
    }
}
