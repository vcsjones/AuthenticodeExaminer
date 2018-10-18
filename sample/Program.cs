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
            var path = @"C:\Users\KevinJones\Desktop\foo.dll"; //Console.ReadLine();
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

        static void DumpSignatureDetails(ISignature signature)
        {
            Console.WriteLine("Signing Certificate:");
            Console.WriteLine($"Signer: {signature.Certificate.Subject}");
            Console.WriteLine($"Issuer: {signature.Certificate.Issuer}");
            Console.WriteLine($"Not Before: {signature.Certificate.NotBefore}");
            Console.WriteLine($"Not After: {signature.Certificate.NotAfter}");
            Console.WriteLine();
            Console.WriteLine("Signature:");
            Console.WriteLine($"Digest algorithm: {signature.DigestAlgorithmName}");
            PublisherInformation info = signature.GetPublisherInformation();
            if (info == null)
            {
                Console.WriteLine("Publisher Site: No publisher information");
                Console.WriteLine("Publisher Description: No publisher information");
            }
            else
            {
                Console.WriteLine($"Publisher Site: {info.UrlLink}");
                Console.WriteLine($"Publisher Description: {info.Description}");
            }
            Console.WriteLine();

            var timestamp = signature.GetTimestampSignature();
            if (timestamp != null)
            {
                Console.WriteLine("\tTimestamp Certificate:");
                Console.WriteLine($"\tSigner: {timestamp.Certificate.Subject}");
                Console.WriteLine($"\tIssuer: {timestamp.Certificate.Issuer}");
                Console.WriteLine($"\tNot Before: {timestamp.Certificate.NotBefore}");
                Console.WriteLine($"\tNot After: {timestamp.Certificate.NotAfter}");
                Console.WriteLine();
                Console.WriteLine($"\tTimestamp Time: {(timestamp.GetTimestampSigningTime()?.ToString() ?? "Unknown")}");
                Console.WriteLine();
            }

            Console.WriteLine();
            Console.WriteLine(new string('-', 30));
        }
    }
}
