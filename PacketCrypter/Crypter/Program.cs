using System.Text;

namespace PackerCrypt
{
    /// <summary>
    /// Provides functionality for encrypting and decrypting files using AES encryption and XOR encryption algorithms.
    /// </summary>
    class Program
    {
        private const int AES_KEY_SIZE = 32;
        private const int XOR_KEY = 23;

        private static string[]? args;
        private static string? sourseFile;
        private static string? outFile;
        private static int operation;

        /// <summary>
        /// The entry point of the application.
        /// </summary>
        /// <param name="argv">The command-line arguments.</param>
        private static void Main(string[] argv)
        {
            if (argv.Length == 3)
                args = argv;
            else
                OutputInformation();

            while (true)
            {
                if (argv.Length != 3)
                {
                    if (!GetUserInputArguments())
                    {
                        argv = [];
                        continue;
                    }
                }

                if (!ProcessArguments())
                    continue;

                switch (operation)
                {
                    case 1:
                        Encrypt();
                        break;
                    case 2:
                        Decrypt();
                        break;
                    default:
                        break;
                }
            }
        }

        /// <summary>
        /// Outputs information about the usage of the program.
        /// </summary>
        private static void OutputInformation()
        {
            Console.WriteLine("Usage: operation sourseFile outfile");
            Console.WriteLine("Operations:");
            Console.WriteLine("--encrypt -encrypts the input file");
            Console.WriteLine("--decrypt -decrypts the input file");
            Console.WriteLine("");
        }

        /// <summary>
        /// Retrieves user input arguments from the console.
        /// </summary>
        /// <returns>True if the arguments were successfully obtained; otherwise, false.</returns>
        private static bool GetUserInputArguments()
        {
            string userInput = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(userInput))
            {
                Console.WriteLine("No arguments provided.");
            }
            args = userInput.Split(' ');

            return args.Length == 3;
        }

        /// <summary>
        /// Processes the command-line arguments.
        /// </summary>
        /// <returns>True if the arguments were processed successfully; otherwise, false.</returns>
        private static bool ProcessArguments()
        {
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--encrypt":
                        operation = 1;
                        break;
                    case "--decrypt":
                        operation = 2;
                        break;
                    default:
                        if (sourseFile == null)
                        {
                            sourseFile = args[i];
                        }
                        else if (outFile == null)
                        {
                            outFile = args[i];
                        }
                        else
                        {
                            return false;
                        }
                        break;
                }
            }

            return true;
        }

        /// <summary>
        /// Encrypts the input file.
        /// </summary>
        private static void Encrypt()
        {
            long dwImageSize = FileTools.CountFileSize(sourseFile);
            if (dwImageSize == 0)
                return;
            Console.WriteLine("[Program] CountStubSize OK");

            byte[] lpImage = new byte[dwImageSize];
            bool imageReadOk = FileTools.ReadFile(sourseFile, lpImage, dwImageSize);
            if (!imageReadOk)
                return;
            Console.WriteLine("[Program] ReadPayload OK");

            bool payload_pe_status = PETools.CheckPE(lpImage);
            if (!payload_pe_status)
                return;
            Console.WriteLine("[Program] CheckPE OK");

            byte[] AESKey = Encoder.CreateAESKey(AES_KEY_SIZE);
            byte[] AESKeyReal = Encoder.EncodeXor(AESKey, AES_KEY_SIZE, XOR_KEY);
            Console.WriteLine("[Program] CreateAESKeys OK");

            string encryptedImage = Encoder.EncryptAes(lpImage, AESKeyReal);
            Console.WriteLine("[Program] EcryptImageWithAES OK");

            byte[] encryptedBytes = Encoding.UTF8.GetBytes(encryptedImage);

            byte[] combinedData = new byte[encryptedBytes.Length + AESKey.Length];
            Array.Copy(encryptedBytes, combinedData, encryptedBytes.Length);
            Array.Copy(AESKey, 0, combinedData, encryptedBytes.Length, AESKey.Length);

            bool write_file_ok = FileTools.WriteFile(outFile, combinedData, (uint)combinedData.Length);

            if (write_file_ok)
                Console.WriteLine("[Program] File " + outFile + " successfully generated.");
            else
                Console.WriteLine("[Program] Error generating output file!");

            sourseFile = null;
            outFile = null;
        }

        /// <summary>
        /// Decrypts the input file.
        /// </summary>
        private static void Decrypt()
        {
            byte[] file = File.ReadAllBytes(sourseFile);
            Console.WriteLine("[Program] ReadFile OK");

            byte[] AESKey = new byte[AES_KEY_SIZE];
            Array.Copy(file, file.Length - AES_KEY_SIZE, AESKey, 0, AES_KEY_SIZE);
            Array.Resize(ref file, file.Length - AES_KEY_SIZE);
            Console.WriteLine("[Program] AESKeyRead OK");

            string decodedString = Encoding.UTF8.GetString(file);
            Console.WriteLine("[Program] DecodeFile OK");

            byte[] AESKeyReal = Encoder.DecryptXor(AESKey, AESKey.Length, XOR_KEY);
            Console.WriteLine("[Program] DecryptAESKey OK");

            byte[] image = Encoder.DecryptAes(decodedString, AESKeyReal);
            Console.WriteLine("[Program] DecryptFile OK");

            if (FileTools.WriteFile(outFile, image, (uint)image.Length))
                Console.WriteLine("[Program] File " + outFile + " successfully generated.");
            else
                Console.WriteLine("[Program] Error generating output file!");

            sourseFile = null;
            outFile = null;
        }
    }
}
