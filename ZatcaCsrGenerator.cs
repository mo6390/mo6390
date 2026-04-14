using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace SewPro.Services
{
    public enum ZatcaCsrEnvironment
    {
        NonProduction,
        Simulation,
        Production
    }

    public sealed class ZatcaCsrRequest
    {
        // Unique EGS unit identifier / asset tracking identifier
        public string CommonName { get; set; } = "EGS-UNIT-01";

        // Branch name. Use MAIN if you do not maintain branches.
        public string OrganizationUnitName { get; set; } = "MAIN";

        // English legal / taxpayer name
        public string OrganizationName { get; set; } = string.Empty;

        public string CountryName { get; set; } = "SA";

        // VAT number only: 15 digits, starts and ends with 3
        public string OrganizationIdentifier { get; set; } = string.Empty;

        // Format: 1-<Manufacturer>|2-<Model>|3-<SerialNumber>
        public string EgsSerialNumber { get; set; } = string.Empty;

        // 4-bit binary map like 1100 / 1000 / 0100
        public string InvoiceType { get; set; } = "1100";

        public string RegisteredAddress { get; set; } = "RIYADH";

        // In CSR for ZATCA this should carry the invoice type code value
        public string BusinessCategory { get; set; } = "1100";

        public ZatcaCsrEnvironment Environment { get; set; } = ZatcaCsrEnvironment.Simulation;
    }

    public sealed class ZatcaCsrResult
    {
        public bool IsValid { get; set; }
        public string CsrPem { get; set; } = string.Empty;
        public string CsrBase64 { get; set; } = string.Empty;
        public string PrivateKeyPem { get; set; } = string.Empty;
        public string PublicKeyPem { get; set; } = string.Empty;
        public string SubjectPreview { get; set; } = string.Empty;
        public string SubjectAltNamePreview { get; set; } = string.Empty;
        public string DetailedSubjectAsText { get; set; } = string.Empty;
        public string DetailedSanAsText { get; set; } = string.Empty;
        public List<string> ValidationErrors { get; set; } = new();
    }

    public sealed class ZatcaCsrValidationResult
    {
        public bool IsValid { get; set; }
        public string ErrorCode { get; set; } = string.Empty;
        public string ErrorCategory { get; set; } = string.Empty;
        public string ErrorMessage { get; set; } = string.Empty;
        public string RawResponse { get; set; } = string.Empty;
        public List<string> Diagnostics { get; set; } = new();
    }

    public interface IZatcaCsrGenerator
    {
        ZatcaCsrResult Generate(ZatcaCsrRequest request);

        Task<ZatcaCsrValidationResult> ValidateWithZatcaAsync(
            string csrBase64,
            string otp,
            string environment,
            ILogger? logger = null);
    }

    public static class ZatcaCsrGenerator
    {
        private static readonly DerObjectIdentifier Secp256r1Oid = SecObjectIdentifiers.SecP256r1;

        // Subject field: organizationIdentifier
        private static readonly DerObjectIdentifier OidOrganizationIdentifier =
            new("2.5.4.97");

        // SAN directoryName fields
        private static readonly DerObjectIdentifier OidSerialNumber =
            new("2.5.4.5");

        private static readonly DerObjectIdentifier OidUid =
            new("0.9.2342.19200300.100.1.1");

        private static readonly DerObjectIdentifier OidRegisteredAddress =
            new("2.5.4.26");

        private static readonly DerObjectIdentifier OidBusinessCategory =
            new("2.5.4.15");

        public static ZatcaCsrResult Generate(ZatcaCsrRequest request)
        {
            var result = new ZatcaCsrResult();

            try
            {
                if (request == null)
                    throw new ArgumentNullException(nameof(request));

                var normalized = NormalizeRequest(request);

                AsymmetricCipherKeyPair keyPair = GenerateEcKeyPair();
                X509Name subject = BuildSubject(normalized);
                GeneralNames san = BuildSubjectAlternativeName(normalized);
                X509Extensions extensions = BuildExtensions(san);

                var extensionRequestAttribute = new AttributePkcs(
                    PkcsObjectIdentifiers.Pkcs9AtExtensionRequest,
                    new DerSet(extensions));

                var csr = new Pkcs10CertificationRequest(
                    "SHA256withECDSA",
                    subject,
                    keyPair.Public,
                    new DerSet(extensionRequestAttribute),
                    keyPair.Private);

                if (!csr.Verify())
                    throw new InvalidOperationException("CSR signature verification failed.");

                string csrPem = ToPem(csr);
                string csrBase64 = ExtractBase64FromPem(csrPem);
                string privateKeyPem = ToPem(keyPair.Private);
                string publicKeyPem = ToPem(keyPair.Public);

                result.IsValid = true;
                result.CsrPem = csrPem;
                result.CsrBase64 = csrBase64;
                result.PrivateKeyPem = privateKeyPem;
                result.PublicKeyPem = publicKeyPem;
                result.SubjectPreview = BuildSubjectPreview(normalized);
                result.SubjectAltNamePreview = BuildSanPreview(normalized);
                result.DetailedSubjectAsText = subject.ToString();
                result.DetailedSanAsText = san.ToString();

                if (!Regex.IsMatch(csrBase64, @"^[A-Za-z0-9+/=]+$"))
                {
                    result.IsValid = false;
                    result.ValidationErrors.Add("CSR Base64 contains invalid characters.");
                }
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.ValidationErrors.Add(ex.Message);
            }

            return result;
        }

        public static async Task<ZatcaCsrValidationResult> ValidateWithZatcaAsync(
            string csrBase64,
            string otp,
            string environment,
            ILogger? logger = null)
        {
            var result = new ZatcaCsrValidationResult();
            var diagnostics = new List<string>();

            try
            {
                if (string.IsNullOrWhiteSpace(csrBase64))
                    throw new InvalidOperationException("CSR Base64 is required.");

                if (string.IsNullOrWhiteSpace(otp))
                    throw new InvalidOperationException("OTP is required.");

                string cleanCsr = Regex.Replace(csrBase64, @"\s+", "");
                string cleanOtp = Regex.Replace(otp, @"\s+", "");

                string url = environment?.Trim().ToLowerInvariant() switch
                {
                    "production" => "https://gw-fatoora.zatca.gov.sa/e-invoicing/production/compliance",
                    "simulation" => "https://gw-fatoora.zatca.gov.sa/e-invoicing/simulation/compliance",
                    "sandbox" => "https://gw-fatoora.zatca.gov.sa/e-invoicing/simulation/compliance",
                    _ => "https://gw-fatoora.zatca.gov.sa/e-invoicing/simulation/compliance"
                };

                diagnostics.Add($"URL: {url}");
                diagnostics.Add($"CSR Length: {cleanCsr.Length}");

                using var httpClient = new HttpClient
                {
                    Timeout = TimeSpan.FromSeconds(30)
                };

                httpClient.DefaultRequestHeaders.Clear();
                httpClient.DefaultRequestHeaders.Add("Accept-Version", "V2");
                httpClient.DefaultRequestHeaders.Add("Accept-Language", "en");
                httpClient.DefaultRequestHeaders.Add("OTP", cleanOtp);

                string body = JsonSerializer.Serialize(new
                {
                    csr = cleanCsr
                });

                using var content = new StringContent(body, Encoding.UTF8, "application/json");
                using HttpResponseMessage response = await httpClient.PostAsync(url, content);
                string responseBody = await response.Content.ReadAsStringAsync();

                result.RawResponse = responseBody;
                diagnostics.Add($"Status: {(int)response.StatusCode}");
                diagnostics.Add($"Response: {responseBody}");

                if (response.IsSuccessStatusCode)
                {
                    result.IsValid = true;
                }
                else
                {
                    result.IsValid = false;

                    try
                    {
                        var error = JsonSerializer.Deserialize<Dictionary<string, string>>(responseBody);
                        if (error != null)
                        {
                            result.ErrorCode = error.GetValueOrDefault("errorCode", string.Empty);
                            result.ErrorCategory = error.GetValueOrDefault("errorCategory", string.Empty);
                            result.ErrorMessage = error.GetValueOrDefault("errorMessage", string.Empty);
                        }
                    }
                    catch
                    {
                        result.ErrorMessage = responseBody;
                    }
                }
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.ErrorMessage = ex.Message;
                diagnostics.Add(ex.Message);
            }

            result.Diagnostics = diagnostics;

            if (logger != null)
            {
                foreach (string line in diagnostics)
                    logger.LogInformation(line);
            }

            return result;
        }

        public static string GenerateDeviceSerialNumber()
        {
            return $"SN-{DateTime.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}".ToUpperInvariant();
        }

        public static string GenerateEgsSerial(string manufacturer, string model, string serial)
        {
            string cleanManufacturer = CleanToken(manufacturer, 40, "SEWPRO");
            string cleanModel = CleanToken(model, 40, "1.0");
            string cleanSerial = CleanToken(serial, 120, GenerateDeviceSerialNumber());

            return $"1-{cleanManufacturer}|2-{cleanModel}|3-{cleanSerial}";
        }

        private static ZatcaCsrRequest NormalizeRequest(ZatcaCsrRequest request)
        {
            string vat = CleanVat(request.OrganizationIdentifier);
            string commonName = CleanCommonName(request.CommonName);
            string organizationUnit = CleanOrganizationUnit(request.OrganizationUnitName, vat);
            string organizationName = CleanSafeAsciiText(request.OrganizationName, 100, "OrganizationName");
            string country = CleanCountry(request.CountryName);
            string egsSerial = CleanEgsSerialNumber(request.EgsSerialNumber);
            string invoiceType = CleanInvoiceTypeBinary(request.InvoiceType);
            string registeredAddress = CleanRegisteredAddress(request.RegisteredAddress);

            string businessCategory = CleanInvoiceTypeBinary(
                string.IsNullOrWhiteSpace(request.BusinessCategory)
                    ? request.InvoiceType
                    : request.BusinessCategory);

            return new ZatcaCsrRequest
            {
                CommonName = commonName,
                OrganizationUnitName = organizationUnit,
                OrganizationName = organizationName,
                CountryName = country,
                OrganizationIdentifier = vat,
                EgsSerialNumber = egsSerial,
                InvoiceType = invoiceType,
                RegisteredAddress = registeredAddress,
                BusinessCategory = businessCategory,
                Environment = request.Environment
            };
        }

        private static AsymmetricCipherKeyPair GenerateEcKeyPair()
        {
            var random = new SecureRandom();

            X9ECParameters curve = ECNamedCurveTable.GetByName("secp256r1")
                ?? throw new InvalidOperationException("Unable to load curve secp256r1.");

            var domainParameters = new ECNamedDomainParameters(
                Secp256r1Oid,
                curve.Curve,
                curve.G,
                curve.N,
                curve.H,
                curve.GetSeed());

            var generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(domainParameters, random));

            return generator.GenerateKeyPair();
        }

        private static X509Name BuildSubject(ZatcaCsrRequest request)
        {
            var oids = new List<DerObjectIdentifier>
            {
                X509Name.C,
                X509Name.O,
                X509Name.OU,
                X509Name.CN,
                OidOrganizationIdentifier
            };

            var values = new List<string>
            {
                request.CountryName,
                request.OrganizationName,
                request.OrganizationUnitName,
                request.CommonName,
                request.OrganizationIdentifier
            };

            return new X509Name(oids, values);
        }

        private static GeneralNames BuildSubjectAlternativeName(ZatcaCsrRequest request)
        {
            // Correct order:
            // serialNumber -> UID -> registeredAddress -> businessCategory
            var oids = new List<DerObjectIdentifier>
            {
                OidSerialNumber,
                OidUid,
                OidRegisteredAddress,
                OidBusinessCategory
            };

            var values = new List<string>
            {
                request.EgsSerialNumber,
                request.OrganizationIdentifier,
                request.RegisteredAddress,
                request.BusinessCategory
            };

            var directoryName = new X509Name(oids, values);
            return new GeneralNames(new GeneralName(GeneralName.DirectoryName, directoryName));
        }

        private static X509Extensions BuildExtensions(GeneralNames san)
        {
            var extensionsGenerator = new X509ExtensionsGenerator();

            extensionsGenerator.AddExtension(
                X509Extensions.SubjectAlternativeName,
                false,
                san);

            extensionsGenerator.AddExtension(
                X509Extensions.KeyUsage,
                true,
                new KeyUsage(KeyUsage.DigitalSignature));

            extensionsGenerator.AddExtension(
                X509Extensions.ExtendedKeyUsage,
                false,
                new ExtendedKeyUsage(KeyPurposeID.IdKPClientAuth));

            return extensionsGenerator.Generate();
        }

        private static string CleanVat(string value)
        {
            string cleaned = new string((value ?? string.Empty).Where(char.IsDigit).ToArray());

            if (!Regex.IsMatch(cleaned, @"^3\d{13}3$"))
                throw new InvalidOperationException("OrganizationIdentifier must be a 15-digit VAT number starting and ending with 3.");

            return cleaned;
        }

        private static string CleanCommonName(string value)
        {
            string cleaned = CleanSafeAsciiText(value, 64, "CommonName");

            if (Regex.IsMatch(cleaned, @"^\d+$"))
                throw new InvalidOperationException("CommonName must not be only digits.");

            return cleaned;
        }

        private static string CleanOrganizationUnit(string value, string vat)
        {
            string cleaned = CleanSafeAsciiText(
                string.IsNullOrWhiteSpace(value) ? "MAIN" : value,
                64,
                "OrganizationUnitName");

            if (vat.Length >= 11 && vat[10] == '1')
            {
                string digitsOnly = new string(cleaned.Where(char.IsDigit).ToArray());
                if (!Regex.IsMatch(digitsOnly, @"^\d{10}$"))
                    throw new InvalidOperationException("For VAT groups, OrganizationUnitName must be the 10-digit TIN of the group member.");

                return digitsOnly;
            }

            return cleaned;
        }

        private static string CleanCountry(string value)
        {
            string cleaned = CleanSafeAsciiText(value, 2, "CountryName").ToUpperInvariant();

            if (cleaned != "SA")
                throw new InvalidOperationException("CountryName must be SA.");

            return cleaned;
        }

        private static string CleanInvoiceTypeBinary(string value)
        {
            string cleaned = (value ?? string.Empty).Trim();

            if (!Regex.IsMatch(cleaned, @"^[01]{4}$"))
                throw new InvalidOperationException("InvoiceType must be a 4-bit binary value such as 1100.");

            if (cleaned == "0000")
                throw new InvalidOperationException("InvoiceType cannot be 0000.");

            return cleaned;
        }

        private static string CleanEgsSerialNumber(string value)
        {
            string cleaned = NormalizeAsciiWhitespace(value);
            cleaned = Regex.Replace(cleaned, @"[^A-Za-z0-9\-\|_.]", "");

            if (!Regex.IsMatch(cleaned, @"^1\-[^|]+\|2\-[^|]+\|3\-[^|]+$"))
                throw new InvalidOperationException("EgsSerialNumber must match 1-...|2-...|3-...");

            if (cleaned.Length > 200)
                throw new InvalidOperationException("EgsSerialNumber is too long.");

            return cleaned.ToUpperInvariant();
        }

        private static string CleanRegisteredAddress(string value)
        {
            string cleaned = NormalizeAsciiWhitespace(value);
            cleaned = Regex.Replace(cleaned, @"[^A-Za-z0-9\- /]", "");

            if (string.IsNullOrWhiteSpace(cleaned))
                throw new InvalidOperationException("RegisteredAddress is required.");

            if (cleaned.Length > 200)
                throw new InvalidOperationException("RegisteredAddress is too long.");

            return cleaned.ToUpperInvariant();
        }

        private static string CleanSafeAsciiText(string value, int maxLength, string fieldName)
        {
            string cleaned = NormalizeAsciiWhitespace(value);
            cleaned = Regex.Replace(cleaned, @"[^A-Za-z0-9\-_\. /]", "");

            if (string.IsNullOrWhiteSpace(cleaned))
                throw new InvalidOperationException($"{fieldName} is invalid.");

            if (cleaned.Length > maxLength)
                throw new InvalidOperationException($"{fieldName} exceeds {maxLength} characters.");

            return cleaned;
        }

        private static string NormalizeAsciiWhitespace(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return string.Empty;

            string cleaned = value.Trim()
                .Replace("\r", " ")
                .Replace("\n", " ")
                .Replace("\t", " ");

            return Regex.Replace(cleaned, @"\s{2,}", " ").Trim();
        }

        private static string CleanToken(string value, int maxLength, string fallback)
        {
            string candidate = string.IsNullOrWhiteSpace(value) ? fallback : value;
            candidate = NormalizeAsciiWhitespace(candidate).ToUpperInvariant();
            candidate = Regex.Replace(candidate, @"[^A-Z0-9\-_\.]", "");

            if (string.IsNullOrWhiteSpace(candidate))
                candidate = fallback;

            if (candidate.Length > maxLength)
                candidate = candidate.Substring(0, maxLength);

            return candidate;
        }

        private static string BuildSubjectPreview(ZatcaCsrRequest request)
        {
            return $"C={request.CountryName}, O={request.OrganizationName}, OU={request.OrganizationUnitName}, CN={request.CommonName}, 2.5.4.97={request.OrganizationIdentifier}";
        }

        private static string BuildSanPreview(ZatcaCsrRequest request)
        {
            return $"serialNumber={request.EgsSerialNumber}, UID={request.OrganizationIdentifier}, registeredAddress={request.RegisteredAddress}, businessCategory={request.BusinessCategory}";
        }

        private static string ToPem(object obj)
        {
            using var sw = new StringWriter();
            var pw = new PemWriter(sw);
            pw.WriteObject(obj);
            pw.Writer.Flush();
            return sw.ToString();
        }

        private static string ExtractBase64FromPem(string pem)
        {
            if (string.IsNullOrWhiteSpace(pem))
                return string.Empty;

            var sb = new StringBuilder();

            using var sr = new StringReader(pem);
            string? line;
            while ((line = sr.ReadLine()) != null)
            {
                if (line.StartsWith("-----BEGIN", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (line.StartsWith("-----END", StringComparison.OrdinalIgnoreCase))
                    continue;

                sb.Append(line.Trim());
            }

            return sb.ToString();
        }
    }
}
