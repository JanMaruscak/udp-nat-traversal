using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using STUN;

namespace udp
{
    internal class NatTraversal
    {
        public static ConcurrentDictionary<IPEndPoint, int> Remotes = new ConcurrentDictionary<IPEndPoint, int>();
        public static UdpClient udpClient;
        public static byte[] MyToken;

        public void Run()
        {
            var address = Dns.GetHostAddresses("stun.l.google.com");
            var stunep = new IPEndPoint(address[1], 19302);

            var stunResult = STUNClient.Query(stunep, STUNQueryType.ExactNAT, true);
            udpClient = new UdpClient(stunResult.LocalEndPoint);

            var ipBytes = stunResult.PublicEndPoint.Address.GetAddressBytes();
            var portBytes = BitConverter.GetBytes(((UInt16)(stunResult.PublicEndPoint.Port)));
            var magicToken = new byte[ipBytes.Length + portBytes.Length];

            MyToken = magicToken;

            ipBytes.CopyTo(magicToken, 0);
            portBytes.CopyTo(magicToken, ipBytes.Length);

            Console.WriteLine($"Muj magicToken: {Convert.ToBase64String(magicToken)}");

            var th = new Thread(Receive);
            th.Start(udpClient);
            var keepAlive = new Thread(SendKeepAlive);
            keepAlive.Start();

            while (true)
            {
                var cmd = Console.ReadLine();
                if (cmd.StartsWith("/a"))
                {
                    Console.WriteLine("Remote magicToken:");
                    magicToken = Convert.FromBase64String(Console.ReadLine());

                    var remoteEp = new IPEndPoint(new IPAddress(magicToken[0..^2]),
                        BitConverter.ToUInt16(magicToken[^2..]));
                    Remotes.TryAdd(remoteEp, 0);

                    var ms = Encoding.ASCII.GetBytes("holepunch");
                    udpClient.Send(ms, ms.Length, remoteEp);

                    SendMagic();
                }
                else if (cmd.StartsWith("/l"))
                {
                    foreach (var ep in Remotes)
                        Console.WriteLine(ep.ToString());
                }
                else if (cmd.StartsWith("/m"))
                {
                    SendMagic();
                }
                else if (cmd.StartsWith("/scam"))
                {
                    var scamMagic = new MagicToken("wmorozova");
                    var sendByte = Encoding.ASCII.GetBytes(scamMagic.ToString());
                    foreach (var ep in Remotes)
                        udpClient.Send(sendByte, sendByte.Length, ep.Key);
                }
                else
                {
                    var msByte = Encoding.ASCII.GetBytes(cmd);
                    var ms = Encoding.ASCII.GetString(msByte);
                    var packet = new Plain(ms);

                    var sendByte = Encoding.ASCII.GetBytes(packet.ToString());
                    var lol = Encoding.ASCII.GetString(sendByte);

                    foreach (var ep in Remotes)
                        udpClient.Send(sendByte, sendByte.Length, ep.Key);
                }
            }
        }

        private static void Receive(Object args)
        {
            var client = args as UdpClient;
            var remoteEp = new IPEndPoint(IPAddress.Any, 0);

            while (true)
            {
                var msByte = client.Receive(ref remoteEp);
                var ms = Encoding.ASCII.GetString(msByte);

                Packet packet = MessageToPacket(ms);

                if (packet is Plain)
                {
                    Console.WriteLine($"> [{packet.Index}][{packet.Message}]");
                }
                else if (packet is KeepAlive)
                {
                    var msg = Encoding.ASCII.GetBytes(packet.AutoResponse().ToString());
                    udpClient.Send(msg, msg.Length, remoteEp);
                    Console.WriteLine($">>> keep alive {remoteEp.Address}");
                    lock (Remotes)
                    {
                        Remotes[remoteEp] = 0;
                    }
                    Console.WriteLine($"--- sending keep alive reply");
                }
                else if (packet is KeepAliveReply)
                {
                    Console.WriteLine($">>> keep alive reply {remoteEp.Address}");
                }
                else if (packet is MagicToken)
                {
                    Console.WriteLine($">>> magic prd {remoteEp.Address}");
                    bool addedAny = false;
                    var tokens = (packet as MagicToken).GetMagicTokens();
                    foreach (var token in tokens)
                    {
                        if (string.IsNullOrWhiteSpace(token)) continue;
                        byte[] magicToken;
                        try
                        {
                            magicToken = Convert.FromBase64String(token);

                            if (Convert.ToBase64String(magicToken) == Convert.ToBase64String(MyToken))
                            {
                                continue;
                            }
                            var ep = new IPEndPoint(new IPAddress(magicToken[0..^2]), BitConverter.ToUInt16(magicToken[^2..]));
                            lock (Remotes)
                            {
                                if (!Remotes.Keys.Contains(ep))
                                {
                                    Remotes.TryAdd(ep, 0);
                                    addedAny = true;
                                }
                            }
                        }
                        catch (Exception)
                        {
                            continue;
                        }
                    }
                    if (addedAny)
                    {
                        SendMagic();
                    }
                }
            }
        }

        public static void SendKeepAlive()
        {
            var keepAlive = new KeepAlive();
            while (true)
            {
                lock (Remotes)
                {
                    var tokensToRemove = new List<IPEndPoint>();
                    foreach (var ep in Remotes)
                    {
                        var msg = Encoding.ASCII.GetBytes(keepAlive.ToString());
                        Console.WriteLine("--- sending keep alive");
                        udpClient.Send(msg, msg.Length, ep.Key);
                        Remotes[ep.Key] += 1;

                        if (Remotes[ep.Key] == 3)
                        {
                            Console.WriteLine($"--- {ep.Key.Address} is not responding to keep alive");
                        }
                        if (Remotes[ep.Key] == 4)
                        {
                            tokensToRemove.Add(ep.Key);
                        }
                    }
                    foreach (var token in tokensToRemove)
                    {
                        Remotes.TryRemove(token, out int value);
                    }
                }
                Thread.Sleep(30000);
            }
        }

        public static void SendMagic()
        {
            var magic = new MagicToken("");
            foreach (var ep in Remotes)
            {
                var magicToken = EndToString(ep.Key);
                magic.Message += $"{magicToken};";
            }
            foreach (var ep in Remotes)
            {
                var msg = Encoding.ASCII.GetBytes(magic.ToString());
                Console.WriteLine("--- sending magic");
                udpClient.Send(msg, msg.Length, ep.Key);
            }
        }

        public static IPEndPoint StringToEndpoint(string token)
        {
            var magicToken = Convert.FromBase64String(token);
            var remoteEp = new IPEndPoint(
                new IPAddress(magicToken[0..^2]),
                BitConverter.ToUInt16(magicToken[^2..]));

            return remoteEp;
        }

        public static string EndToString(IPEndPoint endpoint)
        {
            var ipBytes = endpoint.Address.GetAddressBytes();
            var portBytes = BitConverter.GetBytes((UInt16)(endpoint.Port));
            var magicToken = new byte[ipBytes.Length + portBytes.Length];
            ipBytes.CopyTo(magicToken, 0);
            portBytes.CopyTo(magicToken, ipBytes.Length);

            return Convert.ToBase64String(magicToken);
        }

        public static Packet MessageToPacket(string message)
        {
            Regex regex = new Regex(@"\[(?<cmd>[0-9])\]\[(?<value>.*)\]");

            MatchCollection matches = regex.Matches(message);

            int index = -1;
            string mess = "";
            foreach (Match item in matches)
            {
                GroupCollection groups = item.Groups;
                index = int.Parse(groups["cmd"].Value);
                mess = groups["value"].Value;
            }

            switch (index)
            {
                case 0:
                    return new Plain(mess);

                case 1:
                    return new KeepAlive();

                case 2:
                    return new KeepAliveReply();

                case 3:
                    return new MagicToken(mess);

                default:
                    return null;
            }
        }
    }
}