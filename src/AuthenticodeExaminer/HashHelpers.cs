using System;

namespace AuthenticodeExaminer
{
    internal static class HexHelpers
    {
        private static ReadOnlySpan<byte> LookupTable => new byte[]
        {
            (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4',
            (byte)'5', (byte)'6', (byte)'7', (byte)'8', (byte)'9',
            (byte)'A', (byte)'B', (byte)'C', (byte)'D', (byte)'E',
            (byte)'F',
        };

        public static bool TryHexEncodeBigEndian(ReadOnlySpan<byte> data, Span<char> buffer)
        {
            if (data.Length == 0)
            {
                return true;
            }

            var charsRequired = data.Length * 2;
            if (buffer.Length < charsRequired)
            {
                return false;
            }
            for (int i = 0, j = data.Length * 2 - 2; i < data.Length; i++, j -= 2)
            {
                var value = data[i];
                buffer[j] = (char)LookupTable[(value & 0xF0) >> 4];
                buffer[j + 1] = (char)LookupTable[value & 0x0F];
            }
            return true;
        }

        public static string HexEncodeBigEndian(ReadOnlySpan<byte> data)
        {
            if (data.Length == 0)
            {
                return string.Empty;
            }

            var bufferSize = data.Length * 2;
            const int MAX_BUFFER_STACK = 256;
            Span<char> buffer = bufferSize < MAX_BUFFER_STACK ? stackalloc char[MAX_BUFFER_STACK] : new char[bufferSize];
            if (!TryHexEncodeBigEndian(data, buffer))
            {
                throw new InvalidOperationException("Incorrectly sized buffer.");
            }
            return buffer.Slice(0, bufferSize).ToString();
        }
    }
}
