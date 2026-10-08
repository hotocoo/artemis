using System.Security.Cryptography;

namespace ACT.Encryption;

public class DatabaseEncryption
{
    private readonly AesEncryption _encryption;

    public DatabaseEncryption(AesEncryption encryption)
    {
        _encryption = encryption ?? throw new ArgumentNullException(nameof(encryption));
    }

    public string EncryptColumnValue(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }
        return _encryption.EncryptString(value);
    }

    public string DecryptColumnValue(string encryptedValue)
    {
        if (string.IsNullOrEmpty(encryptedValue))
        {
            return encryptedValue;
        }
        return _encryption.DecryptString(encryptedValue);
    }
}
