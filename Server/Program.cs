using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

// Socket Listener acts as a server and listens to the incoming
// messages on the specified port and protocol.
public class Server
{
    private const string SECU_KEY = "TestSampleKey";
    public static void Main(String[] args)
    {
        StartServer();
        return;
    }

    public static void StartServer()
    {
        IPHostEntry host = Dns.GetHostEntry("127.0.0.1");
        IPAddress ipAddress = host.AddressList[0];
        IPEndPoint localEndPoint = new IPEndPoint(ipAddress, 11000);

        try
        {
            Socket listener = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(localEndPoint);
            listener.Listen(10);
            Console.WriteLine("Waiting for a connection...");

            Socket handler = listener.Accept();
            string data = null;
            byte[] bytes = null;
            while (true)
            {
                while (true)
                {
                    bytes = new byte[1024];
                    int bytesRec = handler.Receive(bytes);
                    data += Encoding.ASCII.GetString(bytes, 0, bytesRec);
                    if (data.IndexOf("<F>") > -1)
                    {
                        break;
                    }
                }
                Console.WriteLine("Command received : {0}", data);
                data = data.Remove(data.Length - 3);
                switch (data)
                {
                    case "BRUT":
                        #region Brut
                        data = null;
                        byte[] msg = Encoding.ASCII.GetBytes("ok pour brut");
                        handler.Send(msg);
                        while (true)
                        {
                            bytes = new byte[1024];
                            int bytesRec = handler.Receive(bytes);
                            data += Encoding.ASCII.GetString(bytes, 0, bytesRec);
                            if (data.IndexOf("<F>") > -1)
                            {
                                break;
                            }
                        }

                        Console.WriteLine("Text received : {0}", data);

                        msg = Encoding.ASCII.GetBytes(data);
                        handler.Send(msg);
                        data = null;
                        #endregion
                        break;
                    case "TRIPLEDES":
                        #region DES
                        data = null;
                        msg = Encoding.ASCII.GetBytes("ok pour tripleDES");
                        handler.Send(msg);
                        while (true)
                        {
                            bytes = new byte[1024];
                            int bytesRec = handler.Receive(bytes);
                            data += Encoding.ASCII.GetString(bytes, 0, bytesRec);
                            if (data.IndexOf("<F>") > -1)
                            {
                                break;
                            }
                        }
                        Console.WriteLine("Text received : {0}", data);
                        Console.WriteLine("Text decrypted : {0}", DES_Decrypt(data));
                        msg = Encoding.ASCII.GetBytes(data);
                        handler.Send(msg);
                        data = null;
                        #endregion
                        break;
                    case "AES":
                        #region AES
                        data = null;
                        msg = Encoding.ASCII.GetBytes("ok pour AES");
                        handler.Send(msg);
                        while (true)
                        {
                            bytes = new byte[1024];
                            int bytesRec = handler.Receive(bytes);
                            data += Encoding.ASCII.GetString(bytes, 0, bytesRec);
                            if (data.IndexOf("<F>") > -1)
                            {
                                break;
                            }
                        }
                        Console.WriteLine(data);
                        Console.WriteLine("Text decrypted : {0}", AES_Decrypt(data, SECU_KEY));
                        msg = Encoding.ASCII.GetBytes(data);
                        handler.Send(msg);
                        data = null;
                        #endregion
                        break;
                    default:
                        break;
                }
            }
            handler.Shutdown(SocketShutdown.Both);
            handler.Close();

        }
        catch (Exception e)
        {
            Console.WriteLine(e.ToString());
        }

        Console.WriteLine("\n Press any key to continue...");
        Console.ReadKey();
    }

    public static string AES_Decrypt(string TextToDecrypt, string pass)
    {
        TextToDecrypt = TextToDecrypt.Remove(TextToDecrypt.Length - 3);
        byte[] cipherText = Encoding.ASCII.GetBytes(TextToDecrypt);
        Console.WriteLine(TextToDecrypt);
        Console.WriteLine(cipherText.Length);
        string plaintext;

        // Create an Aes object
        // with the specified key and IV.
        byte[] Key, IV;
        UnicodeEncoding UE = new UnicodeEncoding();
        using (Aes aesAlg = Aes.Create())
        {
            byte[] passwordBytes = UE.GetBytes(pass);
            Key = SHA256Managed.Create().ComputeHash(passwordBytes);
            IV = MD5.Create().ComputeHash(passwordBytes);
            aesAlg.Key = Key;
            aesAlg.Mode = CipherMode.ECB;
            aesAlg.Padding = PaddingMode.PKCS7;
            aesAlg.IV = IV;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream())
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
                {
                    csDecrypt.Write(cipherText, 0, cipherText.Length);
                }
                byte[]tmp = msDecrypt.ToArray();
                plaintext = Encoding.ASCII.GetString(tmp);
            }
        }
        return plaintext;
    }

    public static string DES_Decrypt(string TextToDecrypt)
    {

        TextToDecrypt = TextToDecrypt.Remove(TextToDecrypt.Length - 3);
        byte[] MyDecryptArray = Convert.FromBase64String(TextToDecrypt);
        /*
        MD5CryptoServiceProvider MyMD5CryptoService = new MD5CryptoServiceProvider();

        byte[] MysecurityKeyArray = MyMD5CryptoService.ComputeHash
           (UTF8Encoding.UTF8.GetBytes(SECU_KEY));

        MyMD5CryptoService.Clear(); 
        */
        var MyTripleDESCryptoService = new TripleDESCryptoServiceProvider();

        PasswordDeriveBytes pdb = new PasswordDeriveBytes(SECU_KEY, null);
        MyTripleDESCryptoService.Key = pdb.CryptDeriveKey("TripleDES", "SHA1", 192, MyTripleDESCryptoService.IV);
        //MyTripleDESCryptoService.Key = MysecurityKeyArray;
        Console.WriteLine(Convert.ToBase64String(MyTripleDESCryptoService.Key));
        MyTripleDESCryptoService.Mode = CipherMode.ECB;
        MyTripleDESCryptoService.Padding = PaddingMode.PKCS7;

        var MyCrytpoTransform = MyTripleDESCryptoService.CreateDecryptor(MyTripleDESCryptoService.Key, MyTripleDESCryptoService.IV);

        byte[] MyresultArray = MyCrytpoTransform.TransformFinalBlock(MyDecryptArray, 0, MyDecryptArray.Length);

        MyTripleDESCryptoService.Clear();

        return UTF8Encoding.UTF8.GetString(MyresultArray);
    }
    /*
    public static byte[] CreateRandomSalt(int length)
    {
        // Create a buffer
        byte[] randBytes;

        if (length >= 1)
        {
            randBytes = new byte[length];
        }
        else
        {
            randBytes = new byte[1];
        }

        // Create a new RNGCryptoServiceProvider.
        RNGCryptoServiceProvider rand = new RNGCryptoServiceProvider();

        // Fill the buffer with random bytes.
        rand.GetBytes(randBytes);

        // return the bytes.
        return randBytes;
    }*/
}