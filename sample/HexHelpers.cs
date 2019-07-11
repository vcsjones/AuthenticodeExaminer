using System;

namespace sample
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

        public static string HexEncode(ReadOnlyMemory<byte> data)
        {
            void StringBuilder(Span<char> chars, ReadOnlyMemory<byte> memory)
            {
                var span = memory.Span;
                for (int i = 0, j = 0; i < data.Length; i++, j += 2)
                {
                    var value = span[i];
                    chars[j] = (char)LookupTable[(value & 0xF0) >> 4];
                    chars[j+1] = (char)LookupTable[value & 0x0F];
                }
            }
            return string.Create(data.Length * 2, data, StringBuilder);
        }
    }
}