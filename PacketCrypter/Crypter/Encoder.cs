using System.Security.Cryptography;

namespace PackerCrypt
{
    /// <summary>
    /// Provides methods for encoding and decoding data using XOR and AES encryption algorithms.
    /// </summary>
    public static class Encoder
    {
        /// <summary>
        /// Encodes the provided data using XOR encryption with the specified key.
        /// </summary>
        /// <param name="data">The data to be encoded.</param>
        /// <param name="size">The size of the data.</param>
        /// <param name="xorKey">The XOR encryption key.</param>
        /// <returns>The encoded data.</returns>
        public static byte[] EncodeXor(byte[] data, int size, int xorKey)
        {
            byte[] encoded = new byte[size];

            for (int i = 0; i < size; i++)
            {
                byte x = data[i];
                encoded[i] = (byte)(x ^ xorKey);
            }

            return encoded;
        }

        /// <summary>
        /// Decrypts the provided data encoded using XOR encryption with the specified key.
        /// </summary>
        /// <param name="encodedData">The encoded data.</param>
        /// <param name="size">The size of the data.</param>
        /// <param name="xorKey">The XOR encryption key.</param>
        /// <returns>The decrypted data.</returns>
        public static byte[] DecryptXor(byte[] encodedData, int size, int xorKey)
        {
            byte[] decrypted = new byte[size];

            for (int i = 0; i < size; i++)
            {
                byte x = encodedData[i];
                decrypted[i] = (byte)(x ^ xorKey);
            }

            return decrypted;
        }

        /// <summary>
        /// Generates a random AES key of the specified size.
        /// </summary>
        /// <param name="aes_key_size">The size of the AES key.</param>
        /// <returns>The generated AES key.</returns>
        public static byte[] CreateAESKey(int aes_key_size)
        {
            byte[] aes_key = new byte[aes_key_size];
            Random rand = new();
            rand.NextBytes(aes_key);

            return aes_key;
        }

        /// <summary>
        /// Encrypts the provided data using AES encryption with the specified key.
        /// </summary>
        /// <param name="data">The data to be encrypted.</param>
        /// <param name="aesKey">The AES encryption key.</param>
        /// <returns>The encrypted data as a Base64 string.</returns>
        public static string EncryptAes(byte[] data, byte[] aesKey)
        {
            using Aes aesAlg = Aes.Create();
            aesAlg.Key = aesKey;
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.PKCS7;

            aesAlg.GenerateIV();
            byte[] iv = aesAlg.IV;

            using MemoryStream msEncrypt = new MemoryStream();
            msEncrypt.Write(iv, 0, iv.Length);
            using (ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
            {
                using CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
                csEncrypt.Write(data, 0, data.Length);
                csEncrypt.FlushFinalBlock();
            }
            return Convert.ToBase64String(msEncrypt.ToArray());
        }

        /// <summary>
        /// Decrypts the provided AES encrypted data using the specified key.
        /// </summary>
        /// <param name="encryptedData">The AES encrypted data as a Base64 string.</param>
        /// <param name="aesKey">The AES encryption key.</param>
        /// <returns>The decrypted data.</returns>
        public static byte[] DecryptAes(string encryptedData, byte[] aesKey)
        {
            byte[] cipherText = Convert.FromBase64String(encryptedData);

            using Aes aesAlg = Aes.Create();
            aesAlg.Key = aesKey;
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.PKCS7;

            byte[] iv = new byte[aesAlg.BlockSize / 8];
            Array.Copy(cipherText, iv, iv.Length);
            aesAlg.IV = iv;

            using MemoryStream msDecrypt = new();
            using (ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
            {
                using CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Write);
                csDecrypt.Write(cipherText, iv.Length, cipherText.Length - iv.Length);
                csDecrypt.FlushFinalBlock();
            }
            return msDecrypt.ToArray();
        }
    }
}
