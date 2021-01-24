using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using STUN;

namespace udp
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            NatTraversal nat = new NatTraversal();
            nat.Run();
        }
    }
}