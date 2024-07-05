using System.Security.Cryptography;
using System.Text;

namespace BStorm.Tools.Encryptions.Cryptography.Asymmetric
{
    public class RsaEncryption
    {
        private readonly RSACryptoServiceProvider _serviceProvider;

        public RsaEncryption(in int keySize = 2048)
        {
            _serviceProvider = new RSACryptoServiceProvider(keySize);
        }

        public RsaEncryption(in byte[] keyBlob)
        {
            _serviceProvider = new RSACryptoServiceProvider();
            _serviceProvider.ImportCspBlob(keyBlob);
        }

        public RsaEncryption(in string keyPem)
        {
            _serviceProvider = new RSACryptoServiceProvider();
            _serviceProvider.ImportFromPem(keyPem);
        }

        public int KeySize
        {
            get { return _serviceProvider.KeySize; }
        }

        public int MaxContentSize
        {
            //Key Size in Byte - 2 * Hash Size in octet - 2
            get { return (KeySize / 8) - (2 * 20) - 2; }
        }

        public bool PublicKeyOnly
        {
            get { return _serviceProvider.PublicOnly; }
        }

        public string ToPublicKeyPem()
        {
            return _serviceProvider.ExportRSAPublicKeyPem();
        }

        public string ToPrivateKeyPem()
        {
            return _serviceProvider.ExportRSAPrivateKeyPem();
        }

        public string ToXml(in bool includePrivateKey)
        {
            return _serviceProvider.ToXmlString(includePrivateKey);
        }

        public byte[] ToByteArray(in bool includePrivateKey)
        {
            return _serviceProvider.ExportCspBlob(includePrivateKey);
        }

        public byte[] Encrypt(in string content)
        {
            if (content.Length > MaxContentSize)
                throw new InvalidOperationException($"With the current key you can encrypt a string with max size : {MaxContentSize}");

            byte[] toEncode = Encoding.Unicode.GetBytes(content);
            return _serviceProvider.Encrypt(toEncode, true);
        }

        public string Decrypt(in byte[] cypher)
        {
            if (PublicKeyOnly)
                throw new InvalidOperationException("Only the private key can decrypt.");

            byte[] decodedData = _serviceProvider.Decrypt(cypher, true);
            return Encoding.Unicode.GetString(decodedData);
        }
    }
}
