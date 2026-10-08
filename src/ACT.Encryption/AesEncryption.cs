using System.Security.Cryptography;

namespace ACT.Encryption;

public class AesEncryption
{
    private readonly byte[] _key;
    private readonly byte[] _iv;

    public AesEncryption(byte[] key, byte[] iv)
    {
        if (key.Length != 32) throw new ArgumentException("Key must be 256 bits (32 bytes)");
        if (iv.Length != 16) throw new ArgumentException("IV must be 128 bits (16 bytes)");
        _key = key;
        _iv = iv;
    }

    public static AesEncryption CreateRandom()
    {
        var key = new byte[32];
        var iv = new byte[16];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(iv);
        return new AesEncryption(key, iv);
    }

    public byte[] Encrypt(byte[] plaintext)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
    }

    public byte[] Decrypt(byte[] ciphertext)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
    }

    public string EncryptString(string plaintext)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(plaintext);
        var encrypted = Encrypt(bytes);
        return Convert.ToBase64String(encrypted);
    }

    public string DecryptString(string ciphertext)
    {
        var bytes = Convert.FromBase64String(ciphertext);
        var decrypted = Decrypt(bytes);
        return System.Text.Encoding.UTF8.GetString(decrypted);
    }
}
