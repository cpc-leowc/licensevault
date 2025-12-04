namespace LicensingVault
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var vault = new LicenseVault("license.json", "app.config.encrypted");

            try
            {
                // Create and save a 30-day trial license
                var license = vault.CreateTrialLicense(30);
                vault.SaveLicense(license);
                Console.WriteLine($"Trial license created. Expires: {license.TrialExpirationDate}");
                Console.WriteLine($"Days remaining: {vault.GetDaysRemaining()}");

                // Create sample config
                var config = new AppConfig
                {
                    AppName = "MyApplication",
                    Version = "1.0.0",
                    Settings = new Dictionary<string, string>
                    {
                        { "DatabaseConnection", "Server=localhost;Database=MyDB;" },
                        { "ApiKey", "secret-api-key-12345" },
                        { "MaxConnections", "100" }
                    }
                };

                // Encrypt and save config
                vault.EncryptAndSaveConfig(config);
                Console.WriteLine("Config encrypted and saved successfully");

                // Decrypt and load config
                var loadedConfig = vault.DecryptAndLoadConfig();
                Console.WriteLine($"\nLoaded Config:");
                Console.WriteLine($"App Name: {loadedConfig.AppName}");
                Console.WriteLine($"Version: {loadedConfig.Version}");
                Console.WriteLine($"Settings:");
                foreach (var setting in loadedConfig.Settings)
                {
                    Console.WriteLine($" {setting.Key}: {setting.Value}");
                }

                // Check license validity
                if (vault.IsLicenseValid())
                {
                    Console.WriteLine("\n✓ License is valid");
                }
                else
                {
                    Console.WriteLine("\n✗ License has expired");
                }
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error: {ex.Message}");
            }

        }
    }
}
