using System.Security.Cryptography;
using System.Text;

namespace BStorm.Tools.Encryptions.Cryptography.Asymmetric
{
    public class RsaEncryption
    {
        private readonly RSACryptoServiceProvider _serviceProvider;

        public RsaEncryption(in int keySize = 4096)
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

        public string ToPem(in bool includePrivateKey)
        {
            return includePrivateKey ? _serviceProvider.ExportRSAPrivateKeyPem() : _serviceProvider.ExportRSAPublicKeyPem();
        }

        public byte[] ToBlob(in bool includePrivateKey)
        {            
            return _serviceProvider.ExportCspBlob(includePrivateKey);
        }

        public byte[] Encrypt(in string content)
        {            
            byte[] toEncode = Encoding.Unicode.GetBytes(content);
            return Encrypt(toEncode);
        }

        public byte[] Encrypt(in byte[] content)
        {
            if (content.Length > MaxContentSize)
                throw new InvalidOperationException($"With the current key you can encrypt a content with max size in bytes : {MaxContentSize}");

            return _serviceProvider.Encrypt(content, true);
        }

        public byte[] Decrypt(in byte[] cypher)
        {
            if (PublicKeyOnly)
                throw new InvalidOperationException("Only the private key can decrypt.");

            return _serviceProvider.Decrypt(cypher, true);
        }

        public string DecryptAsString(in byte[] cypher)
        {
            byte[] decodedData = Decrypt(cypher);
            return Encoding.Unicode.GetString(decodedData);
        }
    }
}
