using System;
using System.Collections.Generic;
using System.Linq;

namespace DNS1
{
    class SimpleDNSPacketCreator
    {
        public static byte[] CreateResponse(DNSQuestion[] questions, int transmissionId, List<DNSEntry> data)
        {
            var cache = new Dictionary<byte[], int>();
            var answers = data.Where(x => x.Type != QType.SOA).ToArray();
            var authority = data.Where(x => x.Type == QType.SOA).ToArray();
            var response = new List<byte>();
            response.AddRange(GetBytes(transmissionId, 2));
            response.Add(0x81);
            response.Add(0x80);

            response.Add(0x00);
            response.Add((byte)questions.Length);
            response.Add(0x00);
            response.Add((byte)answers.Length);
            response.Add(0x00);
            response.Add((byte)authority.Length);
            response.Add(0x00);
            response.Add(0x00);
            var offset = 12;
            foreach (var question in questions)
                response.AddRange(question.ConvertToBytes(cache, ref offset));

            foreach (var entry in answers)
                response.AddRange(entry.ConvertToBytes(cache, ref offset));

            foreach (var entry in authority)
                response.AddRange(entry.ConvertToBytes(cache, ref offset));
            return response.ToArray();
        }

        public static byte[] GetBytes(int number, int count)
        {
            var array = BitConverter.GetBytes(number);
            var resultIdBytes = new byte[count];
            for (var i = count - 1; i >= 0; i--)
                resultIdBytes[i] = array[count - i - 1];
            return resultIdBytes;
        }

        public static byte[] GetBytes(long number, int count)
        {
            var array = BitConverter.GetBytes(number);
            var resultIdBytes = new byte[count];
            for (var i = count - 1; i >= 0; i--)
                resultIdBytes[i] = array[count - i - 1];
            return resultIdBytes;
        }
    }
}
