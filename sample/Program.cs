using AuthenticodeExaminer;
using System;
using System.IO;

namespace sample
{
    class Program
    {
        static int Main(string[] args)
        {
            Console.Write("Type a program path: ");
            var path = Console.ReadLine();
            if (!File.Exists(path))
            {
                Console.WriteLine("File doesn't exist.");
                return 1;
            }
            var extractor = new FileInspector(path);
            var validationResult = extractor.Validate();
            switch(validationResult)
            {
                case SignatureCheckResult.Valid:
                    Console.WriteLine("The file is valid.");
                    break;
                case SignatureCheckResult.NoSignature:
                    Console.WriteLine("The file is not signed.");
                    return 1;
                case SignatureCheckResult.BadDigest:
                    Console.WriteLine("The file's signature is not valid.");
                    return 1;
                default:
                    Console.WriteLine($"The file is not valid: {validationResult}");
                    return 1;
            }

            var signatures = extractor.GetSignatures();
            foreach (var signature in signatures)
            {
                DumpSignatureDetails(signature);
            }
            return 0;
        }

        static void DumpSignatureDetails(AuthenticodeSignature signature)
        {
            Console.WriteLine("Signing Certificate:");
            Console.WriteLine($"Signer: {signature.SigningCertificate?.Subject}");
            Console.WriteLine($"Issuer: {signature.SigningCertificate?.Issuer}");
            Console.WriteLine($"Not Before: {signature.SigningCertificate?.NotBefore}");
            Console.WriteLine($"Not After: {signature.SigningCertificate?.NotAfter}");
            Console.WriteLine();
            Console.WriteLine("Signature:");
            Console.WriteLine($"Digest algorithm: {signature.DigestAlgorithmName}");
            if (signature.PublisherInformation == null)
            {
                Console.WriteLine("Publisher Site: No publisher information");
                Console.WriteLine("Publisher Description: No publisher information");
            }
            else
            {
                Console.WriteLine($"Publisher Site: {signature.PublisherInformation.UrlLink}");
                Console.WriteLine($"Publisher Description: {signature.PublisherInformation.Description}");
            }
            Console.WriteLine($"Signature: {HexHelpers.HexEncode(signature.Signature)}");
            Console.WriteLine();

            foreach (var timestamp in signature.TimestampSignatures)
            {
                if (timestamp != null)
                {
                    Console.WriteLine("\tTimestamp Certificate:");
                    Console.WriteLine($"\tSigner: {timestamp.SigningCertificate?.Subject}");
                    Console.WriteLine($"\tIssuer: {timestamp.SigningCertificate?.Issuer}");
                    Console.WriteLine($"\tNot Before: {timestamp.SigningCertificate?.NotBefore}");
                    Console.WriteLine($"\tNot After: {timestamp.SigningCertificate?.NotAfter}");
                    Console.WriteLine();
                    Console.WriteLine($"\tSignature: {HexHelpers.HexEncode(timestamp.Signature)}");
                    Console.WriteLine();
                    Console.WriteLine($"\tTimestamp Time: {(timestamp.TimestampDateTime?.ToString() ?? "Unknown")}");
                    Console.WriteLine();
                }
            }

            Console.WriteLine();
            Console.WriteLine(new string('-', 30));
        }
    }
}
