using System.Diagnostics;
using System.Reflection.Metadata;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace wrapper;

class Program
{
    unsafe static void Main(string[] args)
    {
        Console.WriteLine("Hello, World!");
        //var t = Program.Externc.test_function_c(7);
        //Console.WriteLine(t);


        // this working
        //var r = Program.Externc.inc_value(7);

        //var r2 = Program.Externc.inc_value_core(7);

        var sk = new byte[Externc.SECRETKEY_BYTES];
        var pk = new byte[Externc.PUBLICKEY_BYTES];

        long skLen = 0;
        long pkLen = 0;

        //return;

        var keyResult = Program.Externc.keypair(
            sk,
            ref skLen,
            pk,
            ref pkLen);

        var sm = new byte[1024];
        long smlen = 0;

        var m = new byte[32];
        var mlen = (long)(m.Length);

        var signatureResult = Program.Externc.signatureofshorthash(
                sm,
                ref smlen,
                m,
                mlen,
                sk,
                skLen
            );

        var validationResult = Program.Externc.verification(
                m,
                mlen,
                sm,
                smlen,
                pk,
                pkLen);

        Console.WriteLine(validationResult);

        const int CNT = 10000;
        Stopwatch sw = new Stopwatch();

        Console.WriteLine("Start");
        sw.Start();
        for (int i = 0; i < CNT; i++)
        {
            var signatureResultC = Program.Externc.signatureofshorthash(
                sm,
                ref smlen,
                m,
                mlen,
                sk,
                skLen
            );
        }
        sw.Stop();
        Console.WriteLine($"signature {(sw.Elapsed / CNT).TotalMilliseconds} ms");


        Console.WriteLine("Start");
        sw.Reset();
        sw.Start();
        for (int i = 0; i < CNT; i++)
        {
            var validationResultC = Program.Externc.verification(
                m,
                mlen,
                sm,
                smlen,
                pk,
                pkLen);
        }
        sw.Stop();
        Console.WriteLine($"validation {(sw.Elapsed / CNT).TotalMilliseconds} ms");

        Console.WriteLine("Done!");
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

