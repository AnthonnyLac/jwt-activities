using System.Text;

namespace Cryptography.App
{
    class Program
    {
        private readonly static Base64 _base64 = new();
        private readonly static MACSHA25 _MACSHA25 = new();

        static void Main(string[] args)
        {
            StartBase64();
            StartMACSHA25();
        }

        static void StartBase64()
        {
            Console.WriteLine("Por favor, insira uma string para codificar em Base64:");
            string input = Console.ReadLine();

            if (string.IsNullOrEmpty(input))
            {
                Console.WriteLine("valor invalido");
                return;
            }

            Console.Clear();

            string base64Encoded = _base64.Base64Encode(input);

            Console.WriteLine($"{input} foi codificado em Base64 para: {base64Encoded}");

            Console.WriteLine("Por favor, insira uma string para decodificar em Base64:");
            string base64Input = Console.ReadLine();

            if (string.IsNullOrEmpty(base64Input))
            {
                Console.WriteLine("Valor inválido.");
                return;
            }

            string decodedString = _base64.Base64Decode(base64Input);

            Console.WriteLine($"{base64Input} foi decodificado de Base64 para: {decodedString}");
        }
        static void StartMACSHA25()
        {
            string key = "EE45F1E35FBB68C2B0AB529A6C8DEFA55AF036D6D0C5E40D874BF8722C8D93F7";

            Console.WriteLine("Digite a mensagem secreta:");
            string message = Console.ReadLine();

            if (string.IsNullOrEmpty(message))
            {
                Console.WriteLine("Valor inválido.");
                return;
            }

            string encodedHash = _MACSHA25.ComputeHmacSha256(key, message);
            Console.WriteLine($"Hash HMAC SHA256: {encodedHash}");

            Console.WriteLine("\nVerificação:");
            Console.WriteLine("Digite o hash a ser verificado:");
            string hashToVerify = Console.ReadLine();

            if (string.IsNullOrEmpty(hashToVerify))
            {
                Console.WriteLine("Valor inválido.");
                return;
            }

            bool isValid = _MACSHA25.VerifyHmacSha256(key, message, hashToVerify);

            if (isValid)
                Console.WriteLine($"O hash fornecido é válido para mensagem: {message}");
            else
                Console.WriteLine($"O hash fornecido não é válido para: {message}");


        }

    }

    public class Base64
    {
        private const string base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        public string Base64Encode(string text)
        {
            StringBuilder result = new();

            byte[] bytes = new byte[text.Length];

            for (int i = 0; i < text.Length; i++)
            {
                bytes[i] = (byte)text[i];
            }


            int charCount = 0;
            int carry = 0;

            foreach (byte b in bytes)
            {
                switch (charCount % 3)
                {
                    case 0:
                        result.Append(base64Chars[b >> 2]);
                        carry = (b & 0x03) << 4;
                        break;
                    case 1:
                        result.Append(base64Chars[carry | (b >> 4)]);
                        carry = (b & 0x0F) << 2;
                        break;
                    case 2:
                        result.Append(base64Chars[carry | (b >> 6)]);
                        result.Append(base64Chars[b & 0x3F]);
                        break;
                }
                charCount++;
            }

            if (charCount % 3 != 0)
            {
                result.Append(base64Chars[carry]);
                if (charCount % 3 == 1)
                    result.Append("==");
                else
                    result.Append("=");
            }

            return result.ToString();
        }

        public string Base64Decode(string base64Text)
        {

            int charCount = 0;
            int carry = 0;
            int byteIndex = 0;
            byte[] result = new byte[(base64Text.Length * 3 / 4) - (base64Text.EndsWith("==") ? 2 : base64Text.EndsWith("=") ? 1 : 0)];


            foreach (char c in base64Text)
            {
                if (c == '=')
                    break;

                int index = base64Chars.IndexOf(c);
                switch (charCount % 4)
                {
                    case 0:
                        carry = index << 2;
                        break;
                    case 1:
                        result[byteIndex++] = (byte)(carry | (index >> 4));
                        carry = (index & 0x0F) << 4;
                        break;
                    case 2:
                        result[byteIndex++] = (byte)(carry | (index >> 2));
                        carry = (index & 0x03) << 6;
                        break;
                    case 3:
                        result[byteIndex++] = (byte)(carry | index);
                        break;
                }
                charCount++;
            }

            char[] charArray = new char[byteIndex];
            for (int i = 0; i < byteIndex; i++)
            {
                charArray[i] = (char)result[i];
            }
            return new string(charArray);
        }
    }

    public class MACSHA25
    {
        public string ComputeHmacSha256(string key, string message)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);

            if (keyBytes.Length < 64)
            {
                byte[] paddedKey = new byte[64];
                Array.Copy(keyBytes, paddedKey, keyBytes.Length);
                keyBytes = paddedKey;
            }

            byte[] oKeyPad = new byte[64];
            byte[] iKeyPad = new byte[64];
            for (int i = 0; i < 64; i++)
            {
                oKeyPad[i] = (byte)(keyBytes[i] ^ 0x5c);
                iKeyPad[i] = (byte)(keyBytes[i] ^ 0x36);
            }

            byte[] hashInner = Sha256(iKeyPad, messageBytes);

            return Convert.ToBase64String(Sha256(oKeyPad, hashInner));
        }

        public bool VerifyHmacSha256(string key, string message, string encodedHash)
        {
            string computedHash = ComputeHmacSha256(key, message);
            return string.Equals(encodedHash, computedHash);
        }

        static byte[] Sha256(byte[] key, byte[] message)
        {
            byte[] result = new byte[key.Length];

            for (int i = 0; i < key.Length; i++)
            {
                if (i < message.Length)
                {
                    result[i] = (byte)(key[i] ^ message[i]);
                }
                else
                {
                    result[i] = key[i];
                }
            }

            return result;
        }
    }
}