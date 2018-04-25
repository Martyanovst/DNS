using System;
using System.Collections.Generic;
using System.Text;


namespace DNS1
{
    class DNSPacketParser
    {
        public static DNSInfo Parse(byte[] rawData)
        {
            var cache = new Dictionary<int, string>();
            var data = new Buffer(rawData);
            var id = int.Parse(data.Pop().ToString() + data.Pop());
            var flags = data.Pop();
            var opcode = flags & 120;
            var aa = (flags & 2) == 2;
            var tc = (flags & 1) == 1;
            var rd = (flags & 0) == 0;
            flags = data.Pop();
            var ra = (flags & 128) == 128;
            var z = flags & 112;
            var rcode = flags & 15;
            var qdcount = ReadRawBytes(data, 2);
            var ancount = ReadRawBytes(data, 2);
            var nscount = ReadRawBytes(data, 2);
            var arcount = ReadRawBytes(data, 2);
            var questions = ReadQuestions(data, qdcount, cache);

            var answers = ReadEntries(data, ancount, cache);
            var authority = ReadEntries(data, nscount, cache);
            var additional = ReadEntries(data, arcount, cache);
            return new DNSResponse(id, opcode, aa, tc, rd, ra, z, rcode, questions, answers, authority, additional);
        }

        public static string ReadBytes(Buffer data, int count)
        {
            var builder = new StringBuilder();
            for (var i = 0; i < count; i++)
                builder.Append(Convert.ToChar(data.Pop()));
            return builder.ToString();
        }

        public static int ReadRawBytes(Buffer data, int count)
        {
            var builder = new StringBuilder();
            for (var i = 0; i < count; i++)
                builder.Append(Convert.ToInt32(data.Pop()));
            return int.Parse(builder.ToString());
        }
        public static long ReadSerialNumberBytes(Buffer data, int count)
        {
            var builder = new StringBuilder();
            for (var i = 0; i < count; i++)
                builder.Append(Convert.ToInt64(data.Pop()));
            return long.Parse(builder.ToString());
        }

        public static DNSQuestion[] ReadQuestions(Buffer data, int count, Dictionary<int, string> cache)
        {
            var result = new DNSQuestion[count];
            for (var i = 0; i < count; i++)
            {
                var name = ReadNameData(data, cache);
                var type = (QType)ReadRawBytes(data, 2);
                var cls = (QClass)ReadRawBytes(data, 2);
                result[i] = new DNSQuestion(name, type, cls);
            }
            return result;
        }

        private static DNSEntry[] ReadEntries(Buffer data, int count, Dictionary<int, string> cache)
        {
            var result = new DNSEntry[count];
            for (var i = 0; i < count; i++)
            {
                var name = ReadName(data, cache);
                var type = (QType)ReadRawBytes(data, 2);
                var cls = (QClass)ReadRawBytes(data, 2);
                var ttl = ReadRawBytes(data, 4);
                var rdlength = ReadRawBytes(data, 2);
                if (type == QType.SOA) result[i] = ReadSoa(data, cache, name, ttl, rdlength);
                else
                {
                    var rdata = ReadNameDataWithFixedLength(data, cache, rdlength, type);
                    result[i] = new DNSEntry(name, type, cls, ttl, rdata);
                }
            }
            return result;
        }

        private static DNSEntry ReadSoa(Buffer data, Dictionary<int, string> cache, string name, int ttl, int rdLength)
        {
            var primaryNameServer = ReadNameData(data, cache);
            var responsibleAuthorityMailbox = ReadNameData(data, cache);
            var serialNumber = ReadSerialNumberBytes(data, 4);
            var refreshInterval = ReadRawBytes(data, 4);
            var retryInterval = ReadRawBytes(data, 4);
            var expirelimit = ReadRawBytes(data, 4);
            var minimumTtl = ReadRawBytes(data, 4);
            return new SOA(name, QType.SOA, QClass.IN, ttl, primaryNameServer, responsibleAuthorityMailbox, serialNumber, refreshInterval, retryInterval, expirelimit, minimumTtl, rdLength);
        }

        private static byte[] ReadNameDataWithFixedLength(Buffer data, Dictionary<int, string> cache, int length, QType type)
        {
            if (type != QType.CNAME && type != QType.NS)
                return ReadBytesWithoutCasting(data, length);
            var bldr = new StringBuilder();
            var finish = data.Offset + length;
            var index = data.Offset;
            var builders = new Dictionary<int, StringBuilder>() { [index] = new StringBuilder() };
            while (data.Offset != finish)
            {
                var lengthOfEntry = data.Pop();
                //bldr.Append(lengthOfEntry);
                if (lengthOfEntry >= 192)
                {
                    var addr = lengthOfEntry & 63;
                    var secondByte = data.Pop();
                    var address = int.Parse(Convert.ToInt32(addr).ToString() + Convert.ToInt32(secondByte));
                    builders[index].Append(cache[address + 1]);
                    bldr.Append(cache[address + 1] + '.');
                }
                else
                {
                    builders[data.Offset] = new StringBuilder();
                    var entry = ReadBytes(data, lengthOfEntry);
                    bldr.Append(entry + '.');
                    foreach (var builder in builders.Values)
                        builder.Append(entry + '.');
                }
            }

            bldr.Remove(bldr.Length - 1, 1);
            foreach (var idx in builders.Keys)
            {
                var builder = builders[idx];
                if (builder[builder.Length - 1] == '.')
                    builder.Remove(builder.Length - 1, 1);
                cache[idx] = builder.ToString();
            }
            return Encoding.Default.GetBytes(bldr.ToString());
        }

        private static byte[] ReadBytesWithoutCasting(Buffer data, int length)
        {
            var result = new byte[length];
            for (var i = 0; i < length; i++)
                result[i] = data.Pop();
            return result;
        }

        private static string ReadNameData(Buffer data, Dictionary<int, string> cache)
        {
            var index = data.Offset;
            var lengthOfEntry = data.Pop();
            var builders = new Dictionary<int, StringBuilder>() { [index] = new StringBuilder() };
            while (lengthOfEntry != 0)
            {
                if (lengthOfEntry >= 192)
                {
                    var addr = lengthOfEntry & 63;
                    var address = int.Parse(Convert.ToInt32(addr).ToString() + Convert.ToInt32(data.Pop()));
                    builders[index].Append(cache[address + 1]);
                    break;
                }
                builders[data.Offset] = new StringBuilder();
                var entry = ReadBytes(data, lengthOfEntry);
                foreach (var builder in builders.Values)
                    builder.Append(entry + '.');
                lengthOfEntry = data.Pop();
            }
            foreach (var idx in builders.Keys)
            {
                var builder = builders[idx];
                if (builder[builder.Length - 1] == '.')
                    builder.Remove(builder.Length - 1, 1);
                cache[idx] = builder.ToString();
            }
            return cache[index];
        }
        private static string ReadName(Buffer data, Dictionary<int, string> cache)
        {
            var firstByte = data.Pop();
            if (firstByte == 0) return "<ROOT>";
            var addr = firstByte & 63;
            var address = int.Parse(Convert.ToInt32(addr).ToString() + Convert.ToInt32(data.Pop()));
            return cache[address + 1];
        }
    }
}