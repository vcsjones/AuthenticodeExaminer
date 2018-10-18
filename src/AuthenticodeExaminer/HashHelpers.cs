using System.Linq;
using System.Text;

namespace AuthenticodeExaminer
{
    internal static class HashHelpers
    {
        public static string HexEncodeBigEndian(byte[] data)
        {
            return data.Aggregate(new StringBuilder(), (acc, b) => acc.Insert(0, string.Format("{0:x2}", b))).ToString();
        }
    }
}
