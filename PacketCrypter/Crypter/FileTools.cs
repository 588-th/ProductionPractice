namespace PackerCrypt
{
    /// <summary>
    /// Provides methods for interacting with files, such as reading file size, reading file content, and writing file content.
    /// </summary>
    public static class FileTools
    {
        /// <summary>
        /// Retrieves the size of the file at the specified path.
        /// </summary>
        /// <param name="path">The path to the file.</param>
        /// <returns>The size of the file in bytes, or 0 if the file does not exist.</returns>
        public static long CountFileSize(string path)
        {
            FileInfo fileInfo = new(path);
            if (fileInfo.Exists)
            {
                return fileInfo.Length;
            }
            else
            {
                Console.WriteLine("Failed to read file!");
                Console.WriteLine(path);
                return 0;
            }
        }

        /// <summary>
        /// Reads the content of the file at the specified path into the provided byte array.
        /// </summary>
        /// <param name="path">The path to the file.</param>
        /// <param name="image">The byte array to store the file content.</param>
        /// <param name="size">The size of the file.</param>
        /// <returns>True if the file was successfully read; otherwise, false.</returns>
        public static bool ReadFile(string path, byte[] image, long size)
        {
            try
            {
                using BinaryReader inputPayload = new(File.Open(path, FileMode.Open));
                for (long i = 0; i < size; i++)
                {
                    image[i] = inputPayload.ReadByte();
                }
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine($"[FileTools] Failed to read file: {path} " + e.Message);
                return false;
            }
        }

        /// <summary>
        /// Writes the provided file content to the file at the specified path.
        /// </summary>
        /// <param name="path">The path to the file.</param>
        /// <param name="filecontent">The content to write to the file.</param>
        /// <param name="filecontentSize">The size of the content to write.</param>
        /// <returns>True if the file was successfully written; otherwise, false.</returns>
        public static bool WriteFile(string path, byte[] filecontent, long filecontentSize)
        {
            try
            {
                using BinaryWriter outputFile = new(File.Open(path, FileMode.Create));
                outputFile.Write(filecontent, 0, (int)filecontentSize);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine($"[FileTools] Failed to write file: {path} " + e.Message);
                return false;
            }
        }
    }
}