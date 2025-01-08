using PackerCrypt;

namespace UnitTests
{
    public class FileToolsTests
    {
        [Fact]
        public void CountFileSize_WithValidPath_ReturnsFileSize()
        {
            // Arrange
            string filePath = "test_file.txt";
            File.WriteAllText(filePath, "Test content");

            // Act
            long fileSize = FileTools.CountFileSize(filePath);

            // Assert
            Assert.Equal(12, fileSize); // Size of "Test content" is 12 bytes
        }

        [Fact]
        public void CountFileSize_WithInvalidPath_ReturnsZero()
        {
            // Arrange
            string filePath = "invalid_path.txt";

            // Act
            long fileSize = FileTools.CountFileSize(filePath);

            // Assert
            Assert.Equal(0, fileSize);
        }

        [Fact]
        public void ReadFile_WithValidPathAndSize_ReturnsTrueAndReadsData()
        {
            // Arrange
            string filePath = "test_file.txt";
            byte[] imageData = new byte[12]; // Assuming the file size is 12 bytes
            File.WriteAllText(filePath, "Test content");
            long fileSize = FileTools.CountFileSize(filePath);

            // Act
            bool result = FileTools.ReadFile(filePath, imageData, fileSize);

            // Assert
            Assert.True(result);
            Assert.Equal("Test content", System.Text.Encoding.Default.GetString(imageData));
        }

        [Fact]
        public void ReadFile_WithInvalidPath_ReturnsFalse()
        {
            // Arrange
            string filePath = "invalid_path.txt";
            byte[] imageData = new byte[12]; // Assuming the file size is 12 bytes

            // Act
            bool result = FileTools.ReadFile(filePath, imageData, 12);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void WriteFile_WithValidPathAndData_ReturnsTrue()
        {
            // Arrange
            string filePath = "test_output.txt";
            byte[] fileContent = System.Text.Encoding.Default.GetBytes("Test content");

            // Act
            bool result = FileTools.WriteFile(filePath, fileContent, fileContent.Length);

            // Assert
            Assert.True(result);
            Assert.True(File.Exists(filePath));
            Assert.Equal("Test content", File.ReadAllText(filePath));
        }

        [Fact]
        public void WriteFile_WithInvalidPath_ReturnsFalse()
        {
            // Arrange
            string filePath = "invalid_path/test_output.txt";
            byte[] fileContent = System.Text.Encoding.Default.GetBytes("Test content");

            // Act
            bool result = FileTools.WriteFile(filePath, fileContent, fileContent.Length);

            // Assert
            Assert.False(result);
        }
    }
}
