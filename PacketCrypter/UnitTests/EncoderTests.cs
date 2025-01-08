using PackerCrypt;

namespace UnitTests
{
    public class EncoderTests
    {
        [Fact]
        public void EncodeXor_WithValidData_ReturnsEncodedData()
        {
            // Arrange
            byte[] data = { 1, 2, 3, 4, 5 };
            int size = data.Length;
            int xorKey = 7;

            // Act
            byte[] encoded = Encoder.EncodeXor(data, size, xorKey);

            // Assert
            byte[] expected = { 6, 5, 4, 3, 2 };
            Assert.Equal(expected, encoded);
        }

        [Fact]
        public void CreateAESKey_WithValidKeySize_ReturnsKeyWithSpecifiedSize()
        {
            // Arrange
            int aes_key_size = 16; // 128 bits

            // Act
            byte[] aesKey = Encoder.CreateAESKey(aes_key_size);

            // Assert
            Assert.Equal(aes_key_size, aesKey.Length);
        }

        [Fact]
        public void EncryptAes_DecryptAes_WithValidData_ReturnsOriginalData()
        {
            // Arrange
            byte[] data = { 1, 2, 3, 4, 5 };
            byte[] aesKey = Encoder.CreateAESKey(16); // 128 bits

            // Act
            string encryptedData = Encoder.EncryptAes(data, aesKey);
            byte[] decryptedData = Encoder.DecryptAes(encryptedData, aesKey);

            // Assert
            Assert.Equal(data, decryptedData);
        }

        [Fact]
        public void DecryptXor_WithValidEncodedData_ReturnsDecodedData()
        {
            // Arrange
            byte[] encodedData = { 6, 5, 4, 3, 2 };
            int size = encodedData.Length;
            int xorKey = 7;

            // Act
            byte[] decoded = Encoder.DecryptXor(encodedData, size, xorKey);

            // Assert
            byte[] expected = { 1, 2, 3, 4, 5 };
            Assert.Equal(expected, decoded);
        }
    }
}
