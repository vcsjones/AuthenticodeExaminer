using AuthenticodeExaminer;
using System;
using System.IO;

namespace sample
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Write("Type a program path: ");
            var path = Console.ReadLine();
            if (!File.Exists(path))
            {
                Console.WriteLine("File doesn't exist.");
                return;
            }
            var extractor = new SignatureExtractor();
            var results = extractor.Extract(path);
            if (results.Count == 0)
            {
                Console.WriteLine("File is not signed.");
                return;
            }

            var hasGoodSignature = FileSignatureVerifier.IsFileSignatureValid(path);
            Console.WriteLine($"File signature is good: {(hasGoodSignature ? "Yes" : "No")}");

            foreach (var signature in results)
            {
                DumpSignatureDetails(signature);
            }
        }

        static void DumpSignatureDetails(ISignature signature, int level = 0)
        {
            void WriteLine(string message)
            {
                string indent = new string(' ', level * 4);
                Console.Write(indent);
                Console.WriteLine(message);
            }
            WriteLine("Certificate:");
            WriteLine($"Signer: {signature.Certificate.Subject}");
            WriteLine($"Issuer: {signature.Certificate.Issuer}");
            WriteLine($"Not Before: {signature.Certificate.NotBefore}");
            WriteLine($"Not After: {signature.Certificate.NotAfter}");
            Console.WriteLine();
            WriteLine("Signature:");

            if (signature.Kind == SignatureKind.Signature || signature.Kind == SignatureKind.NestedSignature)
            {
                PublisherInformation info = null;
                foreach (var attribute in signature.SignedAttributes)
                {
                    if (attribute.Oid.Value == KnownOids.OpusInfo)
                    {
                        info = new PublisherInformation(attribute.Values[0]);
                        break;
                    }
                }
                if (info == null)
                {
                    WriteLine("Publisher Site: No publisher information");
                    WriteLine("Publisher Description: No publisher information");
                }
                else
                {
                    WriteLine($"Publisher Site: {info.UrlLink}");
                    WriteLine($"Publisher Description: {info.Description}");
                }
            }
            else if (signature.Kind == SignatureKind.Rfc3161Timestamp || signature.Kind == SignatureKind.AuthenticodeTimestamp)
            {
                SigningTime time = null;
                foreach (var attribute in signature.SignedAttributes)
                {
                    if (attribute.Oid.Value == KnownOids.SigningTime)
                    {
                        time = new SigningTime(attribute.Values[0]);
                        break;
                    }
                }
                if (time == null)
                {
                    WriteLine("Timestamp does not contain a signing time.");
                }
                else
                {
                    WriteLine($"Timestamp time: {time.Time}");
                }
            }

            WriteLine($"Kind: {signature.Kind}");
            Console.WriteLine();
            Console.WriteLine();

            foreach (var nested in signature.GetNestedSignatures())
            {
                DumpSignatureDetails(nested, level + 1);
            }
        }
    }
}
