using System;
using System.Collections;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

public class Client
{
    private const string SECU_KEY = "TestSampleKey";
    public static void Main(String[] args)
    {
        StartClient();
        return;
    }

    public static void StartClient()
    {
        byte[] bytes = new byte[1024];
        ECDiffieHellmanCng ECDH = null;
        try
        {
            bool exit = false;
            IPHostEntry host = Dns.GetHostEntry("127.0.0.1");
            IPAddress ipAddress = host.AddressList[0];
            IPEndPoint remoteEP = new IPEndPoint(ipAddress, 11000);
            Socket sender = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                sender.Connect(remoteEP);
                Console.WriteLine("Socket connected to {0}",
                sender.RemoteEndPoint.ToString());
                do
                {
                    switch (DisplayMenu().ToString())
                    {
                        case "1":

                            #region Brut
                            byte[] msgBRUT = Encoding.UTF8.GetBytes("BRUT<F>");
                            int bytesSentBRUT = sender.Send(msgBRUT);
                            int bytesRec = sender.Receive(bytes);
                            Console.WriteLine("Server: {0}", Encoding.UTF8.GetString(bytes, 0, bytesRec));

                            byte[] msg = Encoding.UTF8.GetBytes("This is a test<F>");
                            int bytesSent = sender.Send(msg);

                            // Receive the response from the remote device.
                            bytesRec = sender.Receive(bytes);
                            Console.WriteLine("Echoed test = {0}", Encoding.UTF8.GetString(bytes, 0, bytesRec));

                            #endregion Brut

                            break;

                        case "2":

                            #region DES
                            byte[] msgTDES = Encoding.UTF8.GetBytes("TRIPLEDES<F>");
                            int bytesSentTDES = sender.Send(msgTDES);
                            bytesRec = sender.Receive(bytes);
                            Console.WriteLine("Server: {0}", Encoding.UTF8.GetString(bytes, 0, bytesRec));

                            byte[] msg1 = Encoding.UTF8.GetBytes(DES_Encrypt("This is a test") + "<F>");
                            int bytesSent1 = sender.Send(msg1);

                            int bytesRec1 = sender.Receive(bytes);
                            Console.WriteLine("Echoed test = {0}", Encoding.UTF8.GetString(bytes, 0, bytesRec1));

                            #endregion DES

                            break;

                        case "3":

                            #region AES
                            using (Aes myAesKey = Aes.Create())
                            {

                                ECDH = new ECDiffieHellmanCng
                                {
                                    KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
                                    HashAlgorithm = CngAlgorithm.Sha256
                                };
                                byte[] ClientPubKey = ECDH.PublicKey.ToByteArray(); //clé publique Client

                                //commande 1
                                byte[] msgAES = Encoding.UTF8.GetBytes("AES<F>");
                                int bytesSentAES = sender.Send(msgAES);
                                //réception réponse 4
                                bytesRec = sender.Receive(bytes);
                                Console.WriteLine("Server: {0}", Encoding.UTF8.GetString(bytes, 0, bytesRec));
                                //recoit la clé du serveur 6
                                bytes = new byte[140];
                                int bytesRecKey = sender.Receive(bytes);
                                byte[] ServerPubkey = bytes;
                                Console.WriteLine("Clé publique du serveur :" + BitConverter.ToString(ServerPubkey));
                                byte[] derivedKey = ECDH.DeriveKeyMaterial(CngKey.Import(ServerPubkey, CngKeyBlobFormat.EccPublicBlob)); //dérive la clé avant encrypt
                                myAesKey.Key = derivedKey;
                                string msg2 = AES_DH_encrypt("This is a test", derivedKey) + "<F>";

                                //envoie clé client 7
                                bytesSentAES = sender.Send(ClientPubKey);
                                //accusé de recept serveur 10
                                bytesRec = sender.Receive(bytes);
                                Console.WriteLine("Server: {0}", Encoding.UTF8.GetString(bytes, 0, bytesRec));

                                //texte
                                Console.WriteLine("Texte crypté: " + msg2 + "\n");
                                byte[] msgAES2 = Encoding.UTF8.GetBytes(msg2);
                                int bytesSent2 = sender.Send(msgAES2); //envoie msg crypté 11
                                int bytesRec2 = sender.Receive(bytes);
                                Console.WriteLine("Echoed test = {0} \n", Encoding.UTF8.GetString(bytes, 0, bytesRec2));
                            }
                            #endregion
                            break;

                        case "4":

                            #region SHA1
                            byte[] msgSHA1 = Encoding.UTF8.GetBytes("SHA1<F>");
                            int bytesSentSHA1 = sender.Send(msgSHA1);
                            bytesRec = sender.Receive(bytes);
                            Console.WriteLine("Server: {0}", Encoding.UTF8.GetString(bytes, 0, bytesRec));

                            msgSHA1 = Encoding.UTF8.GetBytes(SHA1_HASH(SECU_KEY) + "<F>");
                            Console.WriteLine("Signature envoyé: "+ Encoding.UTF8.GetString(msgSHA1) + "\n");
                            int bytesSentSHA12 = sender.Send(msgSHA1);
                            int bytesSentSHA13 = sender.Receive(bytes);
                            Console.WriteLine("Echoed test = {0}", Encoding.UTF8.GetString(bytes, 0, bytesSentSHA13));

                            #endregion
                            break;

                        case "8":

                            exit = true;

                            break;

                        default:
                            break;
                    }
                }
                while (exit == false);
            }
            catch (ArgumentNullException ane)
            {
                Console.WriteLine("ArgumentNullException : {0}", ane.ToString());
            }
            catch (SocketException se)
            {
                Console.WriteLine("SocketException : {0}", se.ToString());
            }
            catch (Exception e)
            {
                Console.WriteLine("Unexpected exception : {0}", e.ToString());
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e.ToString());
        }
    }
    public static string DES_Encrypt(string TextToEncrypt)
    {
        byte[] MyEncryptedArray = Encoding.UTF8.GetBytes(TextToEncrypt); //transfo string en bytes
        /*
        MD5CryptoServiceProvider MyMD5CryptoService = new MD5CryptoServiceProvider();
        byte[] MysecurityKeyArray = MyMD5CryptoService.ComputeHash(UTF8Encoding.UTF8.GetBytes(SECU_KEY));
        Console.WriteLine(BitConverter.ToString(MysecurityKeyArray));
        
        MyMD5CryptoService.Clear();
        //md5 hash la clé
        */
        PasswordDeriveBytes pdb = new PasswordDeriveBytes(SECU_KEY, null);
        var MyTripleDESCryptoService = new TripleDESCryptoServiceProvider();
        MyTripleDESCryptoService.BlockSize = 64;
        MyTripleDESCryptoService.KeySize = 192;
        MyTripleDESCryptoService.Key = pdb.CryptDeriveKey("TripleDES", "SHA1", 192, MyTripleDESCryptoService.IV);
        Console.WriteLine(Convert.ToBase64String(MyTripleDESCryptoService.Key));
        //MyTripleDESCryptoService.Key = MysecurityKeyArray;
        MyTripleDESCryptoService.Mode = CipherMode.ECB;
        MyTripleDESCryptoService.Padding = PaddingMode.PKCS7;

        var MyCrytpoTransform = MyTripleDESCryptoService.CreateEncryptor(MyTripleDESCryptoService.Key, MyTripleDESCryptoService.IV);
        byte[] MyresultArray = MyCrytpoTransform.TransformFinalBlock(MyEncryptedArray, 0, MyEncryptedArray.Length);

        MyTripleDESCryptoService.Clear();
        Console.WriteLine(Convert.ToBase64String(MyresultArray, 0, MyresultArray.Length));

        return Convert.ToBase64String(MyresultArray, 0, MyresultArray.Length);
    }

    public static string AES_encrypt(string plainText, byte[] key)
    {
        Console.WriteLine("------------AES_encrypt--------------");
        Console.WriteLine("Texte non crypté  => " + plainText + "\n");
        byte[] IV;
        byte[] encrypted;
        byte[] buffer = Encoding.UTF8.GetBytes(plainText);
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
            aesAlg.Key = key;
            aesAlg.GenerateIV();
            IV = aesAlg.IV;
            var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
            encrypted = encryptor.TransformFinalBlock(buffer, 0, buffer.Length);
        }
        var combinedIvCt = new byte[IV.Length + encrypted.Length];
        Array.Copy(IV, 0, combinedIvCt, 0, IV.Length);
        Array.Copy(encrypted, 0, combinedIvCt, IV.Length, encrypted.Length);
        Console.WriteLine("Texte crypté  => "+ BitConverter.ToString(combinedIvCt));
        Console.WriteLine("------------FIN encrypt--------------");
        return Convert.ToBase64String(combinedIvCt);
    }

    public static string AES_DH_encrypt(string plainText, byte[] DerivedKey)
    {
        Console.WriteLine("------------AES_DH_encrypt--------------");
        Console.WriteLine("Texte non crypté  => " + plainText + "\n");
        byte[] IV;
        byte[] encrypted;
        byte[] buffer = Encoding.UTF8.GetBytes(plainText);
        using (Aes aes = Aes.Create())
        {
            Console.WriteLine(
            "Config:\n" +
            "aes.KeySize = 256;\n" +
            "aes.BlockSize = 128;\n" +
            "aes.Padding = PaddingMode.PKCS7;\n" +
            "aes.Mode = CipherMode.CBC;");
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;
            aes.GenerateIV();
            aes.Key = DerivedKey;
            IV = aes.IV;
            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            encrypted = encryptor.TransformFinalBlock(buffer, 0, buffer.Length);
        }
        var combinedIvCt = new byte[IV.Length + encrypted.Length];
        Array.Copy(IV, 0, combinedIvCt, 0, IV.Length);
        Array.Copy(encrypted, 0, combinedIvCt, IV.Length, encrypted.Length);
        Console.WriteLine("Texte crypté  => " + BitConverter.ToString(combinedIvCt));
        Console.WriteLine("------------FIN AES_DH_encrypt--------------");
        return Convert.ToBase64String(combinedIvCt);
    }

    public static string SHA1_HASH(string TextToEncrypt)
    {
        using SHA1 sha1 = SHA1.Create();
        var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(TextToEncrypt));
        var sb = new StringBuilder(hash.Length * 2);
        foreach (byte b in hash)
        {
            sb.Append(b.ToString("X2"));
        }
        return sb.ToString();
    }

    public static int DisplayMenu()
    {
        Console.WriteLine("Crypto - CLIENT\n");
        Console.WriteLine("1. Communication Brut");
        Console.WriteLine("2. Communication TripleDES");
        Console.WriteLine("3. Communication AES");
        Console.WriteLine("4. Hash SHA1");
        Console.WriteLine("5. Authentification HMAC-MD5");
        Console.WriteLine("6. Communication SHA1-RSA");
        Console.WriteLine("7. Communication RSA et certificat");
        Console.WriteLine("\n8. Exit");
        var result = Console.ReadLine();
        return Convert.ToInt32(result);
    }
}