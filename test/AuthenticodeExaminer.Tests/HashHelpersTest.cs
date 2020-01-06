using System;
using Xunit;

namespace AuthenticodeExaminer.Tests
{
    public static class HashHelpersTest
    {
        [Fact]
        public static void ShouldHexEncodeBigEndian()
        {
            var input = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            var result = HexHelpers.HexEncodeBigEndian(input);
            Assert.Equal("100F0E0D0C0B0A09080706050403020100", result);
        }

        [Fact]
        public static void ShouldHexEncodeBigEndianExceedingStackLimit()
        {
            Span<byte> input = new byte[10 * 1024 * 1024]; //A 10 MB string would normally blow the stack.
            input.Fill(1);
            var result = HexHelpers.HexEncodeBigEndian(input);
            Assert.Equal(input.Length * 2, result.Length);
        }

        [Fact]
        public static void ShouldHexEncodeEmpty()
        {
            Span<byte> input = default;
            var result = HexHelpers.HexEncodeBigEndian(input);
            Assert.Empty(result);
        }

        [Fact]
        public static void ShouldReturnEmptyTryHexEncodeEmpty()
        {
            Span<byte> input = default;
            Span<char> buffer = default;
            var result = HexHelpers.TryHexEncodeBigEndian(input, buffer);
            Assert.True(result);
        }

        [Fact]
        public static void ShouldReturnFalseForIncompleteBuffer()
        {
            Span<byte> input = new byte[] { 1, 2, 3 };
            Span<char> buffer = new char[1];
            var result = HexHelpers.TryHexEncodeBigEndian(input, buffer);
            Assert.False(result);
        }
    }
}
