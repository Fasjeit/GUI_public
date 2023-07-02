using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using Microsoft.Diagnostics.Tracing.Parsers.ClrPrivate;

namespace MyBenchmarks
{
    public class Gui96
    {
        private const int N = 10000;
        private readonly byte[] pk = new byte[Externc.PUBLICKEY_BYTES];
        private readonly byte[] sk = new byte[Externc.SECRETKEY_BYTES];

        private readonly byte[] sm = new byte[1024];

        private readonly byte[] m = new byte[32];

        private long pkLen;
        private long skLen;
        private long smlen;
        private long mlen = 32;

        RSA rsaKey = RSA.Create();
        byte[] rsaSigned;
        byte[] rsaData = new byte[32];

        public Gui96()
        {
            Externc.keypair(
                sk,
                ref skLen,
                pk,
                ref pkLen);

            var signatureResult = Externc.signatureofshorthash(
                sm,
                ref smlen,
                m,
                mlen,
                sk,
                skLen);

            var validationResult = Externc.verification(
                m,
                mlen,
                sm,
                smlen,
                pk,
                pkLen);

            rsaSigned = rsaKey.SignHash(rsaData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        }

        [Benchmark]
        public void KeyGenRsa()
        {
            var key = RSA.Create();
            var size = key.KeySize;
        }

        [Benchmark]
        public void RsaSign()
        {
            var sgn = rsaKey.SignHash(rsaData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        [Benchmark]
        public void RsaValidate()
        {
            var validated = rsaKey.VerifyHash(rsaData, rsaSigned, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        [Benchmark]
        public void KeyGen()
        {
            Externc.keypair(
                sk,
                ref skLen,
                pk,
                ref pkLen);
        }

        [Benchmark]
        public void Sign()
        {
            var signatureResult = Externc.signatureofshorthash(
                           sm,
                           ref smlen,
                           m,
                           mlen,
                           sk,
                           skLen);
        }

        [Benchmark]
        public void Validate()
        {
            var validationResult = Externc.verification(
                m,
                mlen,
                sm,
                smlen,
                pk,
                pkLen);
        }
    }

    public class Program
    {
        public static void Main(string[] args)
        {
            var summary = BenchmarkRunner.Run<Gui96>();
        }
    }

    public static class Externc
    {
        // private const string LibPath_c = "/mnt/c/git/GUI_public/w_agg/t.so";
        // private const string LibPath_cpp = "/mnt/c/git/GUI_public/w_agg/tpp.so";

        private const string LibPath_cpp2 = "/mnt/c/git/GUI_public/gui96566/ref/liblibrary.so";

        private const string LibPath_cpp2_core = "/mnt/c/git/GUI_public/gui96566/ref/liblibrary_core.so";

        private const string Libqa = "/mnt/c/git/GUI_public/gui96566/ref/libquartz.so";

        // [DllImport(Externc.LibPath_c, EntryPoint = "test_function")]
        // internal static extern int test_function_c(
        //     int sm);

        // [DllImport(Externc.LibPath_cpp, EntryPoint = "test_function")]
        // internal static extern int test_function_cpp(
        //     int sm);

        [DllImport(Externc.LibPath_cpp2, EntryPoint = "inc_value")]
        internal static extern int inc_value(
            int sm);

        [DllImport(Externc.LibPath_cpp2_core, EntryPoint = "inc_value_core", ExactSpelling = false, CallingConvention = CallingConvention.Cdec‌​l)]
        internal static extern int inc_value_core(
            int sm);

        public const int SECRETKEY_BYTES = 3175;
        public const int PUBLICKEY_BYTES = 63036;

        [DllImport(Externc.LibPath_cpp2, EntryPoint = "keypairW")]
        internal static extern int keypairW(
            char[] sk,
            ref IntPtr sklen,
            char[] pk,
            ref IntPtr pklen);

        [DllImport(Externc.Libqa, EntryPoint = "keypair", CallingConvention = CallingConvention.StdCall)]
        internal static extern int keypair(
            byte[] sk,
            ref long sklen,
            byte[] pk,
            ref long pklen);

        [DllImport(Externc.Libqa, EntryPoint = "signatureofshorthash", CallingConvention = CallingConvention.StdCall)]
        internal static extern int signatureofshorthash(
            byte[] sm,
            ref long smlen,
            byte[] m,
            long mlen,
            byte[] sk,
            long sklen);


        // (unsigned char sm[SIGNATURE_BYTES], unsigned long long *smlen,
        // 						const unsigned char m[SHORTHASH_BYTES], const unsigned long long mlen,
        // 						const unsigned char sk[SECRETKEY_BYTES], const unsigned long long sklen)


        [DllImport(Externc.Libqa, EntryPoint = "verification", CallingConvention = CallingConvention.StdCall)]
        internal static extern int verification(
                    byte[] m,
                    long mlen,
                    byte[] sm,
                    long smlen,
                    byte[] pk,
                    long pklen);

        // (const unsigned char m[SHORTHASH_BYTES], const unsigned long long mlen,
        // 					const unsigned char sm[SIGNATURE_BYTES], const unsigned long long smlen,
        // 					const unsigned char pk[PUBLICKEY_BYTES], const unsigned long long pklen)
    }
}