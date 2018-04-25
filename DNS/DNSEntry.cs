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

        public string GetName(byte[] data)
        {
            var buffer = new Buffer(data);
            var lengthOfEntry = buffer.Pop();
            var builder = new StringBuilder();
            while (lengthOfEntry != 0)
            {
                builder.Append(DNSPacketParser.ReadBytes(buffer, lengthOfEntry));
                builder.Append('.');
                if (buffer.Offset == data.Length) break;
                lengthOfEntry = buffer.Pop();
            }
            builder.Remove(builder.Length - 1, 1);
            return builder.ToString();
        }

        public virtual List<byte> ConvertToBytes(Dictionary<byte[], int> cache, ref int offset)
        {
            var response = new List<byte>();
            foreach (var key in cache.Keys)
            {
                var name = GetName(key);
                if (name != Name) continue;
                var index = cache[key];
                var bytes = SimpleDNSPacketCreator.GetBytes(index, 2);
                bytes[0] |= 192;
                response.AddRange(bytes);
                break;
            }

            response.AddRange(new byte[] { 0, (byte)Type, 0, 1 });

            response.AddRange(SimpleDNSPacketCreator.GetBytes((int)(TimeToDie - DateTime.Now).TotalSeconds, 4));
            offset += 10;

            if (Type == QType.CNAME || Type == QType.NS)
            {
                var index = offset;
                var str = Encoding.Default.GetString(Data);
                var tmp = new List<byte>();
                var fields = str.Split('.');
                foreach (var field in fields)
                {
                    if(field.Length <= 0) continue;
                    tmp.Add((byte)field.Length);
                    tmp.AddRange(Encoding.Default.GetBytes(field));
                    offset += field.Length + 1;
                }
                offset += 1;
                tmp.Add(0);
                response.AddRange(SimpleDNSPacketCreator.GetBytes(tmp.Count, 2));
                response.AddRange(tmp);
                cache[tmp.ToArray()] = index;
            }
            else
            {
                response.AddRange(SimpleDNSPacketCreator.GetBytes(Data.Length, 2));
                response.AddRange(Data);
                offset += Data.Length + 1;
            }
            return response;
        }
    }
}
