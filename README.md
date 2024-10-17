public string Decrypt(string base64EncryptedText)
{
    base64EncryptedText = base64EncryptedText.Trim('"');
    base64EncryptedText = base64EncryptedText.Replace("\r", "").Replace("\n", "").Replace(" ", "");

    foreach (char c in base64EncryptedText)
    {
        if (!char.IsLetterOrDigit(c) && c != '+' && c != '/' && c != '=')
        {
            throw new ArgumentException($"Unexpected character: {c} (Unicode: {(int)c})");
        }
    }
    byte[] encryptedBytes = Convert.FromBase64String(base64EncryptedText);
    return DecryptFromBase64(encryptedBytes);
}
public string DecryptFromBase64(byte[] cipherTextWithIv)
{
    try
    {
        using (var aes = Aes.Create())
        {
            aes.Key = key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            if (cipherTextWithIv.Length < aes.BlockSize / 8)
            {
                throw new ArgumentException("The cipher Text With Iv array is too short to contain the IV.");
            }
            byte[] iv = new byte[aes.BlockSize / 8];
            Array.Copy(cipherTextWithIv, 0, iv, 0, iv.Length);
            byte[] cipherText = new byte[cipherTextWithIv.Length - iv.Length];
            Array.Copy(cipherTextWithIv, iv.Length, cipherText, 0, cipherText.Length);
            using (var decryptor = aes.CreateDecryptor(key, iv))
            using (var ms = new MemoryStream(cipherText))
            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (var sr = new StreamReader(cs))
            {
                return sr.ReadToEnd();
            }
        }
    }
    catch (Exception ex)
    {
        return ex.ToString();
    }
}

# Library-Management
Library Management System is a system which maintains the information about the books present in the library, their authors, the members of library to whom books are 
issued and all. This is very difficult to organize manually. Maintenance of all this information manually is a very complex task. Owing to the advancement of technology, 
organization of an Online Library becomes much simple.The maintenance of the records is made efficient, as all the records are stored in the ACCESS database, through 
which data can be retrieved easily. It makes entire process online where student can search books, staff can generate reports and do book transactions.The navigation 
control is provided in all the forms to navigate through the large amount of records. 
The Library Management has been designed to computerize and automate the operations performed over the information about the members, book issues and returns and all 
other operations. This computerization of library helps in many instances of its maintenance. It reduces the workload of management as most of the manual work done is 
reduced.
