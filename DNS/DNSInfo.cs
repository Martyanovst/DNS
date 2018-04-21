using System.Text;

namespace DNS1
{
    abstract class DNSInfo
    {
        public int Id;
        public int Opcode;
        public bool Aa;
        public bool Tc;
        public bool Rd;
        public bool Ra;
        public int Z;
        public int Rcode;
        public DNSQuestion[] Questions;
        public DNSEntry[] Answers;
        public DNSEntry[] Authority;
        public DNSEntry[] Additional;

        protected DNSInfo(int id,int opcode, bool aa, bool tc, bool rd, bool ra, int z, int rcode,
            DNSQuestion[] questions, DNSEntry[] answers, DNSEntry[] authority, DNSEntry[] additional)
        {
            Id = id;
            Opcode = opcode;
            Aa = aa;
            Tc = tc;
            Rd = rd;
            Ra = ra;
            Z = z;
            Rcode = rcode;
            Questions = questions;
            Answers = answers;
            Authority = authority;
            Additional = additional;
        }
    }
}
