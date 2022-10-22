using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
                        //recpetion commande 2
                        data = null;
                        msg = Encoding.UTF8.GetBytes("ok pour AES.");
                        Console.WriteLine("- Envoi réponse au client ...\n");
                        handler.Send(msg); //envoie réponse 3
                        ECDH = new ECDiffieHellmanCng
                        {
                            KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
                            HashAlgorithm = CngAlgorithm.Sha256
                        };
                        byte[] ServerPubKey = ECDH.PublicKey.ToByteArray(); //clé publique server
                        msg = ServerPubKey;
                        Console.WriteLine("Clé serveur: " + BitConverter.ToString(ServerPubKey) + "\n");
                        Console.WriteLine("- Envoi clé publique\n");
                        handler.Send(msg);//envoie la clé publique 5

                        //recetpion clé client 8
                        bytes = new byte[140];
                        int bytesRecKey = handler.Receive(bytes);
                        byte[] ClientPubKey = bytes;
                        byte[] derivedKey = ECDH.DeriveKeyMaterial(CngKey.Import(ClientPubKey, CngKeyBlobFormat.EccPublicBlob));
                        Console.WriteLine("Clé client: " + BitConverter.ToString(ClientPubKey)+"\n");
                        Console.WriteLine("Clé dérivé: " + BitConverter.ToString(derivedKey) + "\n");
                        data = null;
                        Console.WriteLine("- ACK clé client ...");
                        //envoie acc de recpet clé client 9
                        msg = Encoding.UTF8.GetBytes("Clé recu.");
                        handler.Send(msg);

                        //recept texte crypt 12
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
                        string msgDec = AES_DH_decrypt(data, derivedKey);
                        Console.WriteLine("- Texte décrypté => " + msgDec + "\n");
                        Console.WriteLine("- Verification auprès du client.");
                        msg = Encoding.UTF8.GetBytes(msgDec);
                        handler.Send(msg);
                        data = null;
                        #endregion
                        break;
                    case "SHA1":
                        #region SHA1
                        data = null;
                        msg = Encoding.UTF8.GetBytes("ok pour SHA1");
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
                        data = data.Remove(data.Length - 3);
                        Console.WriteLine("Signature client : {0}", data);
                        string datadec = SHA1_HASH("This is a test");
                        Console.WriteLine("Signature server : {0}", datadec);
                        string result = HASH_compare(data, datadec);
                        Console.WriteLine(result);
                        msg = Encoding.UTF8.GetBytes(result);
                        handler.Send(msg);
                        data = null;
                        #endregion 
                        break;

                    case "HMACMD5":
                        #region HMACMD5
                        data = null;
                        msg = Encoding.UTF8.GetBytes("ok pour HMACMD5");
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
                        data = data.Remove(data.Length - 3);
                        Console.WriteLine("Signature client : {0}", data);
                        string datadec1 = HMACMD5_HASH("This is a test", SECU_KEY);
                        Console.WriteLine("Signature server : {0}", datadec1);
                        string result1 = HASH_compare(data, datadec1);
                        Console.WriteLine(result1);
                        msg = Encoding.UTF8.GetBytes(result1);
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

    private static string HASH_compare(string data, string datadec)
    {
        if (String.Compare(data, datadec) == 0)
        {
            return "Signature ok";
        }
        else
        {
            return "Signature invalide";
        }
    }
    private static string HMACMD5_HASH(string msg, string SECU_KEY)
    {
        byte[] Enc = Encoding.UTF8.GetBytes(SECU_KEY);
        var md5 = new HMACMD5(Enc);
        byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(msg));
        var result = BitConverter.ToString(hash).Replace("-", string.Empty);
        return result;
    }
    private static string SHA1_HASH(string data)
    {
        using SHA1 sha1 = SHA1.Create();
        var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(data));
        var sb = new StringBuilder(hash.Length * 2);
        foreach (byte b in hash)
        {
            sb.Append(b.ToString("X2"));
        }
        return sb.ToString();
    }

    private static string AES_decrypt(string TextToDecrypt, byte[] key)
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

    private static string AES_DH_decrypt(string TextToDecrypt, byte[] Derivedkey)
    {
        Console.WriteLine("------------AES_DH_decrypt--------------");
        TextToDecrypt = TextToDecrypt.Remove(TextToDecrypt.Length - 3);
        Console.WriteLine("Texte crypté  => " + TextToDecrypt + "\n");
        string plaintext = null;
        byte[] cipherTextCombined = Convert.FromBase64String(TextToDecrypt);
        using (Aes aesAlg = Aes.Create())
        {
            Console.WriteLine(
            "Config:\n" +
            "aesAlg.KeySize = 256;\n" +
            "aesAlg.BlockSize = 128;\n" +
            "aesAlg.Padding = PaddingMode.PKCS7;\n" +
            "aesAlg.Mode = CipherMode.CBC;");
            aesAlg.KeySize = 256;
            aesAlg.BlockSize = 128;
            aesAlg.Padding = PaddingMode.PKCS7;
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.GenerateIV();
            aesAlg.Key = Derivedkey;
            byte[] IV = new byte[aesAlg.BlockSize / 8];
            byte[] cipherText = new byte[cipherTextCombined.Length - IV.Length];
            Array.Copy(cipherTextCombined, IV, IV.Length);
            Array.Copy(cipherTextCombined, IV.Length, cipherText, 0, cipherText.Length);
            Console.WriteLine("Clé: " + BitConverter.ToString(Derivedkey));
            Console.WriteLine("Taille clé: " + Derivedkey.Length);
            Console.WriteLine("Texte: " + BitConverter.ToString(cipherTextCombined));
            Console.WriteLine("Taille texte: " + cipherText.Length);
            aesAlg.IV = IV;
            aesAlg.Mode = CipherMode.CBC;
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
            plaintext = Encoding.UTF8.GetString(decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length));
        }
        Console.WriteLine("------------FIN AES_DH_decrypt--------------");
        return plaintext;
    }

    private static string DES_Decrypt(string TextToDecrypt)
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
}