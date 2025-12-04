using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace LicensingVault
{
    // License model
    public class License
    {
        public DateTime TrialExpirationDate { get; set; }
        public string LicenseKey { get; set; }
        public bool IsActive { get; set; }
    }

    // App configuration model
    public class AppConfig
    {
        public string AppName { get; set; }
        public string Version { get; set; }
        public Dictionary<string, string> Settings { get; set; }
    }

    public class LicenseVault
    {
        private const int KeySize = 256;
        private const int IvSize = 128;
        private readonly string _licenseFilePath;
        private readonly string _configFilePath;

        public LicenseVault(string licenseFilePath, string configFilePath)
        {
            _licenseFilePath = licenseFilePath;
            _configFilePath = configFilePath;
        }

        // Generate a new license with trial period
        public License CreateTrialLicense(int trialDays)
        {
            return new License
            {
                TrialExpirationDate = DateTime.UtcNow.AddDays(trialDays),
                LicenseKey = GenerateLicenseKey(),
                IsActive = true
            };
        }

        // Save license to file
        public void SaveLicense(License license)
        {
            string strencoded = EncodeLicenseToken(license.TrialExpirationDate, license.LicenseKey, license.IsActive);
            //var json = JsonSerializer.Serialize(license);
            File.WriteAllText(_licenseFilePath, strencoded);
        }


        public static string EncodeLicenseToken(DateTime trialExpirationUtc, string licenseKey, bool isActive)
        {
            // Payload format: ISO-8601 UTC + '|' + licenseKey
            var payload = $"{trialExpirationUtc.ToString("O")}|{licenseKey}|{isActive}";
            var bytes = Encoding.UTF8.GetBytes(payload);
            return Base64UrlEncode(bytes);
        }


        // ---- Base64Url helpers (no external dependencies) ----
        private static string Base64UrlEncode(byte[] data)
        {
            var s = Convert.ToBase64String(data);
            return s.Replace('+', '-').Replace('/', '_').TrimEnd('=');
        }


        private static byte[] Base64UrlDecode(string s)
        {
            s = s.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
                case 0: break;
                default: throw new FormatException("Invalid Base64Url length.");
            }
            return Convert.FromBase64String(s);
        }



        // Load license from file
        public License LoadLicense()
        {
            if (!File.Exists(_licenseFilePath))
                throw new FileNotFoundException("License file not found");

            var json = File.ReadAllText(_licenseFilePath);
            //return JsonSerializer.Deserialize<License>(json);
            (DateTime TrialExpirationUtc, string LicenseKey, bool isActive) = DecodeLicenseToken(json);
            var licenseKey = new License();
            licenseKey.TrialExpirationDate = TrialExpirationUtc;
            licenseKey.LicenseKey = LicenseKey;
            licenseKey.IsActive = isActive;

            return licenseKey;
        }


        public static (DateTime TrialExpirationUtc, string LicenseKey, bool IsActive) DecodeLicenseToken(string token)
        {
            var bytes = Base64UrlDecode(token);
            var payload = Encoding.UTF8.GetString(bytes);

            var parts = payload.Split('|');
            if (parts.Length != 3)
                throw new FormatException("Invalid token format.");

            // Parse as UTC; tolerate presence/absence of 'Z'
            var expUtc = DateTime.Parse(
                parts[0],
                provider: null,
                styles: System.Globalization.DateTimeStyles.AssumeUniversal |
                        System.Globalization.DateTimeStyles.AdjustToUniversal);

            return (expUtc, parts[1], bool.Parse(parts[2]));
        }


        // Validate if license is still valid
        public bool IsLicenseValid()
        {
            try
            {
                var license = LoadLicense();
                return license.IsActive && DateTime.UtcNow <= license.TrialExpirationDate;
            }
            catch
            {
                return false;
            }
        }

        // Encrypt and save config file
        public void EncryptAndSaveConfig(AppConfig config)
        {
            var license = LoadLicense();

            if (!license.IsActive)
                throw new InvalidOperationException("License is not active");

            var json = JsonSerializer.Serialize(config);
            var encrypted = EncryptString(json, license.LicenseKey);
            File.WriteAllText(_configFilePath, encrypted);
        }

        // Decrypt and load config file
        public AppConfig DecryptAndLoadConfig()
        {
            if (!IsLicenseValid())
                throw new InvalidOperationException("License has expired or is invalid. Cannot decrypt configuration.");

            var license = LoadLicense();

            if (!File.Exists(_configFilePath))
                throw new FileNotFoundException("Config file not found");

            var encrypted = File.ReadAllText(_configFilePath);
            var decrypted = DecryptString(encrypted, license.LicenseKey);

            return JsonSerializer.Deserialize<AppConfig>(decrypted);
        }

        // Generate a random license key
        private string GenerateLicenseKey()
        {
            //Creates a cryptographically secure random number generator
            //Cryptographic random number generators create cryptographically strong random values
            using (var rng = RandomNumberGenerator.Create())
            {
                var keyBytes = new byte[32];                    //32 bytes = 256 bits, which is a common key size for AES 256
                rng.GetBytes(keyBytes);                         //Fills the array [keyBytes] with cryptographically strong random bytes. 
                                                                //After this call, keybytes contain 256-bit value for symmetric key, token seed.
                return Convert.ToBase64String(keyBytes);        //Encodes raw bytes to Base64 string
                                                                //Resulting Base64 string will typcially be 44 char cos 32 bytes -> 43 characters + padding
            }
        }

        // Encrypt string using AES
        private string EncryptString(string plainText, string key)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = KeySize;
                aes.Key = DeriveKey(key);
                aes.GenerateIV();

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                using (var ms = new MemoryStream())
                {
                    // Write IV to the beginning of the stream
                    ms.Write(aes.IV, 0, aes.IV.Length);

                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    using (var sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                    }

                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        // Decrypt string using AES
        private string DecryptString(string cipherText, string key)
        {
            var fullCipher = Convert.FromBase64String(cipherText);

            using (var aes = Aes.Create())
            {
                aes.KeySize = KeySize;
                aes.Key = DeriveKey(key);

                // Extract IV from the beginning
                var iv = new byte[IvSize / 8];
                Array.Copy(fullCipher, 0, iv, 0, iv.Length);
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                using (var ms = new MemoryStream(fullCipher, iv.Length, fullCipher.Length - iv.Length))
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (var sr = new StreamReader(cs))
                {
                    return sr.ReadToEnd();
                }
            }
        }

        // Derive a 256-bit key from the license key
        private byte[] DeriveKey(string licenseKey)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(licenseKey));
            }
        }

        // Get days remaining in trial
        public int GetDaysRemaining()
        {
            var license = LoadLicense();
            var remaining = (license.TrialExpirationDate - DateTime.UtcNow).Days;
            return Math.Max(0, remaining);
        }
    }

}
