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
        ECDiffieHellmanCng ECDH = null;
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
                    data += Encoding.UTF8.GetString(bytes, 0, bytesRec);
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
                        byte[] msg = Encoding.UTF8.GetBytes("ok pour brut");
                        handler.Send(msg);
                        while (true)
                        {
                            bytes = new byte[1024];
                            int bytesRec = handler.Receive(bytes);
                            data += Encoding.UTF8.GetString(bytes, 0, bytesRec);
                            if (data.IndexOf("<F>") > -1)
                            {
                                break;
                            }
                        }

                        Console.WriteLine("Text received : {0}", data);

                        msg = Encoding.UTF8.GetBytes(data);
                        handler.Send(msg);
                        data = null;
                        #endregion
                        break;
                    case "TRIPLEDES":
                        #region DES
                        data = null;
                        msg = Encoding.UTF8.GetBytes("ok pour tripleDES");
                        handler.Send(msg);
                        while (true)
                        {
                            bytes = new byte[1024];
                            int bytesRec = handler.Receive(bytes);
                            data += Encoding.UTF8.GetString(bytes, 0, bytesRec);
                            if (data.IndexOf("<F>") > -1)
                            {
                                break;
                            }
                        }
                        Console.WriteLine("Text received : {0}", data);
                        Console.WriteLine("Text decrypted : {0}", DES_Decrypt(data));
                        msg = Encoding.UTF8.GetBytes(data);
                        handler.Send(msg);
                        data = null;
                        #endregion
                        break;
                    case "AES":
                        #region AES
                        data = null;
                        //2
                        msg = Encoding.UTF8.GetBytes("ok pour AES.");
                        Console.WriteLine("- Envoi réponse au client ...\n");
                        handler.Send(msg);

                        ECDH = new ECDiffieHellmanCng
                        {
                            KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
                            HashAlgorithm = CngAlgorithm.Sha256
                        };
                        byte[] ServerPubKey = ECDH.PublicKey.ToByteArray();
                        msg = ServerPubKey;
                        Console.WriteLine("- Envoi clé publique\n");
                        handler.Send(msg);

                        bytes = new byte[32];
                        Console.WriteLine("- Demande de clé...");
                        int bytesRecKey = handler.Receive(bytes);
                        byte[] key = bytes;
                        Console.WriteLine("Clé: " + BitConverter.ToString(key));
                        data = null;
                        Console.WriteLine("- ACK clé client ...");
                        msg = Encoding.UTF8.GetBytes("Clé recu.");
                        handler.Send(msg);
                        Console.WriteLine("- Reception du texte crypté ...");
                        while (true)
                        {
                            bytes = new byte[1024];
                            int bytesRec = handler.Receive(bytes);
                            data += Encoding.UTF8.GetString(bytes, 0, bytesRec);
                            if (data.IndexOf("<F>") > -1)
                            {
                                break;
                            }
                        }
                        string msgDec = AES_decrypt(data, key);
                        Console.WriteLine("- Texte décrypté => " + msgDec + "\n");
                        Console.WriteLine("- Verification auprès du client.");
                        msg = Encoding.UTF8.GetBytes(msgDec);
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

    public static string AES_decrypt(string TextToDecrypt, byte[] key)
    {
        Console.WriteLine("------------AES_decrypt--------------");
        TextToDecrypt = TextToDecrypt.Remove(TextToDecrypt.Length - 3);
        Console.WriteLine("Texte crypté  => " + TextToDecrypt + "\n");
        string plaintext = null;
        byte[] cipherTextCombined = Convert.FromBase64String(TextToDecrypt);
        using (Aes aesAlg = Aes.Create())
        {
            Console.WriteLine(
            "Config:\n"+
            "aesAlg.KeySize = 256;\n" +
            "aesAlg.BlockSize = 128;\n" +
            "aesAlg.Padding = PaddingMode.PKCS7;\n" +
            "aesAlg.Mode = CipherMode.CBC;");
            aesAlg.KeySize = 256;
            aesAlg.BlockSize = 128;
            aesAlg.Padding = PaddingMode.PKCS7;
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.GenerateIV();
            aesAlg.Key = key;
            byte[] IV = new byte[aesAlg.BlockSize / 8];
            byte[] cipherText = new byte[cipherTextCombined.Length - IV.Length];
            Array.Copy(cipherTextCombined, IV, IV.Length);
            Array.Copy(cipherTextCombined, IV.Length, cipherText, 0, cipherText.Length);
            Console.WriteLine("Clé: " + BitConverter.ToString(key));
            Console.WriteLine("Taille clé: " + key.Length);
            Console.WriteLine("Texte: " + BitConverter.ToString(cipherTextCombined));
            Console.WriteLine("Taille texte: " + cipherText.Length);
            aesAlg.IV = IV;
            aesAlg.Mode = CipherMode.CBC;
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
            plaintext = Encoding.UTF8.GetString(decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length));
        }
        Console.WriteLine("------------FIN AES_decrypt--------------");
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