using System;
using System.Collections.Generic;
using System.Text;

namespace DNS1
{
    class DNSEntry
    {
        public readonly string Name;
        public readonly QType Type;
        public readonly QClass Class;
        public readonly int TTL;
        public readonly byte[] Data;
        public readonly DateTime TimeToDie;

        public DNSEntry(string name, QType type, QClass cls, int ttl, byte[] data)
        {
            Name = name;
            Type = type;
            Class = cls;
            TTL = ttl;
            Data = data;
            TimeToDie = DateTime.Now + TimeSpan.FromSeconds(TTL);
        }

        public virtual List<byte> ConvertToBytes(Dictionary<int, byte[]> cache, ref int offset)
        {
            var response = new List<byte>();
            foreach (var key in cache.Keys)
            {
                if (Encoding.Default.GetString(cache[key]) != Name) continue;
                var bytes = SimpleDNSPacketCreator.GetBytes(key, 2);
                bytes[0] |= 192;
                response.AddRange(bytes);
                break;
            }

            response.AddRange(new byte[] { 0, (byte)Type, 0, 1 });

            response.AddRange(SimpleDNSPacketCreator.GetBytes((int)(TimeToDie - DateTime.Now).TotalSeconds, 4));
            offset += 10;

            if (Type == QType.CNAME)
            {
                var index = offset;
                var str = Encoding.Default.GetString(Data);
                var tmp = new List<byte>();
                var fields = str.Split('.');
                foreach (var field in fields)
                {
                    tmp.Add((byte)field.Length);
                    tmp.AddRange(Encoding.Default.GetBytes(field));
                    offset += field.Length + 1;
                }
                offset += 1;
                response.Add((byte)tmp.Count);
                response.AddRange(tmp);
                cache[index] = tmp.ToArray();
            }
            else
            {
                response.AddRange(SimpleDNSPacketCreator.GetBytes(Data.Length, 2));
                response.AddRange(Data);
                offset += Data.Length + 1;
            }

            response.Add(0);
            response.Add((byte)Type);
            response.Add(0);
            response.Add((byte)Class);
            offset += 4;
            return response;
        }
    }
}
