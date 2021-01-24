using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace udp
{
    public class Packet
    {
        public IPEndPoint SourceIP { get; set; }
        public int Index { get; set; }
        public string Message { get; set; }

        public override string ToString()
        {
            return $"[{Index}][{Message}]";
        }

        public virtual Packet AutoResponse()
        {
            return null;
        }
    }

    public class Plain : Packet
    {
        public Plain(string message)
        {
            Index = 0;
            Message = message;
        }
    }

    public class KeepAlive : Packet
    {
        public KeepAlive()
        {
            Index = 1;
            Message = "";
        }

        public override Packet AutoResponse()
        {
            return new KeepAliveReply();
        }
    }

    public class KeepAliveReply : Packet
    {
        public KeepAliveReply()
        {
            Index = 2;
            Message = "";
        }
    }

    public class MagicToken : Packet
    {
        public MagicToken(string message)
        {
            Index = 3;
            Message = message;
        }

        public List<string> GetMagicTokens()
        {
            if (string.IsNullOrWhiteSpace(Message)) return new List<string>();

            var tokens = new List<string>(Message.Split(";"));
            return tokens;
        }
    }
}