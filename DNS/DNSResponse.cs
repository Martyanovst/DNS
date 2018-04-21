using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DNS1
{
    class DNSResponse: DNSInfo
    {
        public DNSResponse(int id, int opcode, bool aa, bool tc, bool rd, bool ra, int z, int rcode, DNSQuestion[] questions, DNSEntry[] answers, DNSEntry[] authority, DNSEntry[] additional) : base(id, opcode, aa, tc, rd, ra, z, rcode, questions, answers, authority, additional)
        {
        }
    }
}
