using System;
using System.Collections.Generic;
using System.Text;

namespace DNS1
{
    class SOA : DNSEntry
    {
        private readonly string _pns;
        private readonly string _ram;
        private readonly long _sn;
        private readonly int _refI;
        private readonly int _retI;
        private readonly int _el;
        private readonly int _minimumTtl;
        private readonly int dataLength;

        public SOA(string name, QType type, QClass cls, int ttl, string PNS, string RAM, long SN, int RefI, int RetI,
            int El, int minimumTTL, int dataLen) : base(name, type, cls, ttl, null)
        {
            _pns = PNS;
            _ram = RAM;
            _sn = SN;
            _refI = RefI;
            _retI = RetI;
            _el = El;
            _minimumTtl = minimumTTL;
            dataLength = dataLen;
        }

        public override List<byte> ConvertToBytes(Dictionary<byte[],int> cache, ref int offset)
        {
            var response = new List<byte> { 0 };
            //
            response.AddRange(new byte[] { 0, (byte)Type, 0, 1 });
            response.AddRange(SimpleDNSPacketCreator.GetBytes((int)(TimeToDie - DateTime.Now).TotalSeconds, 4));
            response.AddRange(SimpleDNSPacketCreator.GetBytes(dataLength, 2));
            offset += 11;
            ConvertData(response, cache, _pns, ref offset);

            ConvertData(response, cache, _ram, ref offset);
            response.AddRange(SimpleDNSPacketCreator.GetBytes(_sn, 4));
            response.AddRange(SimpleDNSPacketCreator.GetBytes(_refI, 4));
            response.AddRange(SimpleDNSPacketCreator.GetBytes(_retI, 4));
            response.AddRange(SimpleDNSPacketCreator.GetBytes(_el, 4));
            response.AddRange(SimpleDNSPacketCreator.GetBytes(_minimumTtl, 4));

            offset += 16;
            return response;
        }

        private void ConvertData(List<byte> response, Dictionary<byte[],int> cache, string data, ref int offset)
        {
            var index = offset;
            var tmp = new List<byte>();
            var fields = data.Split('.');
            foreach (var field in fields)
            {
                tmp.Add((byte)field.Length);
                tmp.AddRange(Encoding.Default.GetBytes(field));
                offset += field.Length + 1;
            }

            offset += 1;
            response.Add((byte)tmp.Count);
            response.AddRange(tmp);
            cache[tmp.ToArray()] = index;
        }
    }
}
