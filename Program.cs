using System;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace TestOpenSsl
{
    class Program
    {

        #region OpenSsl native functions

        const string SslDllName = "libssl-1_1.dll";

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr TLSv1_2_method();

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_CTX_new(IntPtr method);

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_CTX_free(IntPtr ctx);

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_new(IntPtr ctx);

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_free(IntPtr ssl);

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_set_fd(IntPtr ssl, int fd);

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static long SSL_ctrl(IntPtr ssl, int cmd, long larg, IntPtr parg);

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_connect(IntPtr ssl);

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_read(IntPtr ssl, IntPtr buf, int num);

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_write(IntPtr ssl, IntPtr buf, int num);

        #endregion

        #region OpenSsl constants

        const int SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;

        #endregion


        static void Main(string[] args)
        {
            string proxyHost = "127.0.0.1";
            int proxyPort = 8888;
            string host = "example.com";
            int port = 443;
            Socket socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            byte[] bytes;

            socket.Connect(proxyHost, proxyPort);

            if (!socket.Connected)
            {
                Console.WriteLine("Socket connection error");
                return;
            }

            Console.WriteLine("Socket connected\r\n");

            /* CONNECT request through proxy */

            bytes = Encoding.UTF8.GetBytes($"CONNECT {host}:{port} HTTP/1.1\r\n\r\n");

            socket.Send(bytes, bytes.Length, 0);
            socket.Receive(new byte[0]);

            Console.WriteLine("Connect request:\r\n" + Encoding.UTF8.GetString(bytes));

            bytes = new byte[socket.Available];

            socket.Receive(bytes);

            Console.WriteLine("Connect response:\r\n" + Encoding.UTF8.GetString(bytes));

            /* OpenSsl usage */

            IntPtr tlsMethod = TLSv1_2_method();
            IntPtr sslCtx = SSL_CTX_new(tlsMethod);
            IntPtr ssl = SSL_new(sslCtx);
            int setFdResult = SSL_set_fd(ssl, socket.Handle.ToInt32());

            if (setFdResult == 0)
            {
                Console.WriteLine("Set socket handle error");
                return;
            }

            SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, 0, Marshal.StringToBSTR(host));

            int connectResult = SSL_connect(ssl);

            switch (connectResult)
            {
                case 0:
                    Console.WriteLine("SSL connection error\r\n");
                    return;
                case 1:
                    Console.WriteLine("SSL connection success\r\n");
                    break;
                default:
                    Console.WriteLine("SSL connection fatal error\r\n");
                    return;
            }

            bytes = Encoding.UTF8.GetBytes($"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
            IntPtr bytesPointer = Marshal.AllocHGlobal(bytes.Length);

            Console.WriteLine("Ssl request:\r\n" + Encoding.UTF8.GetString(bytes));
            Marshal.Copy(bytes, 0, bytesPointer, bytes.Length);

            SSL_write(ssl, bytesPointer, bytes.Length);

            socket.Receive(new byte[0]);

            bytes = new byte[socket.Available];
            bytesPointer = Marshal.AllocHGlobal(bytes.Length);

            SSL_read(ssl, bytesPointer, bytes.Length);
            Marshal.Copy(bytesPointer, bytes, 0, bytes.Length);

            Console.WriteLine("Ssl response:\r\n" + Encoding.UTF8.GetString(bytes));

            SSL_free(ssl);
            SSL_CTX_free(sslCtx);

            Console.ReadKey();
        }
    
    }
}
