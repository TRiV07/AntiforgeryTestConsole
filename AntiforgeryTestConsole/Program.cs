using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AntiforgeryTestConsole
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddDataProtection()
                .PersistKeysToFileSystem(new DirectoryInfo(@"c:\temp-keys"))
                .SetApplicationName("Commodious");
            builder.Services.AddAntiforgery();

            var app = builder.Build();

            Deserialize(app, "Cookie[.AspNetCore.Antiforgery.***]", "CfDJ8PKHrWlgrp5FgkCcN6-JXahyNezqlcl6ozbpDmzUxTvSJxg9xG4HUR0d1w6ZvLlc4Gqgrnmi3nqYJN_6PEDO46NuljbmJkASs6YQ_0F1MkZDMOHj_mcWyjR7KYWasLCc6X9mHbli-KeDFHGIImMqmxY");

            Deserialize(app, "From[__RequestVerificationToken]", "CfDJ8PKHrWlgrp5FgkCcN6-JXainrBKjExqju66sm7hZwk4p1bO0vHF_l3VfyfctGI6K243QeOpv8jQkwhwRuWzB3t8STxJdvnERq73Hh7PbjvnWPeVg_B2-eQT43T-lP2yetQ7xpUmGQ9NvtJIKY7WADzDRniK5jxMT5JFefLRcFeP35QD7Q3BjcrR-CcFOpsh6bQ");
        }

        private static void Deserialize(WebApplication app, string name, string serializedToken)
        {
            var count = serializedToken.Length;
            var charsRequired = WebEncoders.GetArraySizeRequiredToDecode(count);
            var chars = new char[charsRequired];
            var tokenBytes = WebEncoders.Base64UrlDecode(
                serializedToken,
                offset: 0,
                buffer: chars,
                bufferOffset: 0,
                count: count);


            var testBytes = app.Services.GetDataProtector("Microsoft.AspNetCore.Antiforgery.AntiforgeryToken.v1").Unprotect(tokenBytes);

            using var binaryReader = new BinaryReader(new MemoryStream(testBytes));
            var test = DeserializeInternal(binaryReader);

            Console.WriteLine($"{name}:");
            Console.WriteLine(JsonSerializer.Serialize(test, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine();
        }

        private const byte TokenVersion = 0x01;

        /* The serialized format of the anti-XSRF token is as follows:
         * Version: 1 byte integer
         * SecurityToken: 16 byte binary blob
         * IsCookieToken: 1 byte Boolean
         * [if IsCookieToken != true]
         *   +- IsClaimsBased: 1 byte Boolean
         *   |  [if IsClaimsBased = true]
         *   |    `- ClaimUid: 32 byte binary blob
         *   |  [if IsClaimsBased = false]
         *   |    `- Username: UTF-8 string with 7-bit integer length prefix
         *   `- AdditionalData: UTF-8 string with 7-bit integer length prefix
         */
        private static AntiforgeryToken? DeserializeInternal(BinaryReader reader)
        {
            // we can only consume tokens of the same serialized version that we generate
            var embeddedVersion = reader.ReadByte();
            if (embeddedVersion != TokenVersion)
            {
                return null;
            }

            var deserializedToken = new AntiforgeryToken();
            var securityTokenBytes = reader.ReadBytes(AntiforgeryToken.SecurityTokenBitLength / 8);
            deserializedToken.SecurityToken =
                new BinaryBlob(AntiforgeryToken.SecurityTokenBitLength, securityTokenBytes);
            deserializedToken.IsCookieToken = reader.ReadBoolean();

            if (!deserializedToken.IsCookieToken)
            {
                var isClaimsBased = reader.ReadBoolean();
                if (isClaimsBased)
                {
                    var claimUidBytes = reader.ReadBytes(AntiforgeryToken.ClaimUidBitLength / 8);
                    deserializedToken.ClaimUid = new BinaryBlob(AntiforgeryToken.ClaimUidBitLength, claimUidBytes);
                }
                else
                {
                    deserializedToken.Username = reader.ReadString();
                }

                deserializedToken.AdditionalData = reader.ReadString();
            }

            // if there's still unconsumed data in the stream, fail
            if (reader.BaseStream.ReadByte() != -1)
            {
                return null;
            }

            // success
            return deserializedToken;
        }
    }
    

    internal sealed class AntiforgeryToken
    {
        internal const int SecurityTokenBitLength = 128;
        internal const int ClaimUidBitLength = 256;

        private string _additionalData = string.Empty;
        private string _username = string.Empty;
        private BinaryBlob? _securityToken;

        public string AdditionalData
        {
            get { return _additionalData; }
            set
            {
                _additionalData = value ?? string.Empty;
            }
        }

        public BinaryBlob? ClaimUid { get; set; }

        public bool IsCookieToken { get; set; }

        public BinaryBlob? SecurityToken
        {
            get
            {
                if (_securityToken == null)
                {
                    _securityToken = new BinaryBlob(SecurityTokenBitLength);
                }
                return _securityToken;
            }
            set
            {
                _securityToken = value;
            }
        }

        public string? Username
        {
            get { return _username; }
            set
            {
                _username = value ?? string.Empty;
            }
        }
    }

    // Represents a binary blob (token) that contains random data.
    // Useful for binary data inside a serialized stream.
    [DebuggerDisplay("{DebuggerString}")]
    internal sealed class BinaryBlob : IEquatable<BinaryBlob>
    {
        private readonly byte[] _data;

        // Generates a new token using a specified bit length.
        public BinaryBlob(int bitLength)
            : this(bitLength, GenerateNewToken(bitLength))
        {
        }

        // Generates a token using an existing binary value.
        public BinaryBlob(int bitLength, byte[] data)
        {
            if (bitLength < 32 || bitLength % 8 != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(bitLength));
            }
            if (data == null || data.Length != bitLength / 8)
            {
                throw new ArgumentOutOfRangeException(nameof(data));
            }

            _data = data;
        }

        public int BitLength
        {
            get
            {
                return checked(_data.Length * 8);
            }
        }

        public string DebuggerString
        {
            get
            {
                var sb = new StringBuilder("0x", 2 + (_data.Length * 2));
                for (var i = 0; i < _data.Length; i++)
                {
                    sb.AppendFormat(CultureInfo.InvariantCulture, "{0:x2}", _data[i]);
                }
                return sb.ToString();
            }
        }

        public override bool Equals(object? obj)
        {
            return Equals(obj as BinaryBlob);
        }

        public bool Equals(BinaryBlob? other)
        {
            if (other == null)
            {
                return false;
            }

            Debug.Assert(_data.Length == other._data.Length);
            return AreByteArraysEqual(_data, other._data);
        }

        public byte[] GetData()
        {
            return _data;
        }

        public override int GetHashCode()
        {
            // Since data should contain uniformly-distributed entropy, the
            // first 32 bits can serve as the hash code.
            Debug.Assert(_data != null && _data.Length >= (32 / 8));
            return BitConverter.ToInt32(_data, 0);
        }

        private static byte[] GenerateNewToken(int bitLength)
        {
            var data = new byte[bitLength / 8];
            RandomNumberGenerator.Fill(data);
            return data;
        }

        // Need to mark it with NoInlining and NoOptimization attributes to ensure that the
        // operation runs in constant time.
        [MethodImplAttribute(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static bool AreByteArraysEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }

            var areEqual = true;
            for (var i = 0; i < a.Length; i++)
            {
                areEqual &= (a[i] == b[i]);
            }
            return areEqual;
        }
    }

}
