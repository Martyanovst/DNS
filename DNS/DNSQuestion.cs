using System.Collections.Generic;
using System.Text;

namespace DNS1
{
    struct DNSQuestion
    {
        public readonly string Name;
        public readonly QType Type;
        public readonly QClass Cls;

        public DNSQuestion(string name, QType type, QClass cls)
        {
            Name = name;
            Type = type;
            Cls = cls;
        }

        public List<byte> ConvertToBytes(Dictionary<int,byte[]> cache,ref int offset)
        {
            var response = new List<byte>();
            var fields = Name.Split('.');
            var index = offset;
            foreach (var field in fields)
            {
                if(string.IsNullOrEmpty(field)) continue;
                response.Add((byte)field.Length);
                response.AddRange(Encoding.Default.GetBytes(field));
                offset += field.Length + 1;
            }

            cache[index] = response.ToArray();

            response.Add(0);

            response.Add(0);
            response.Add((byte)Type);
            response.Add(0);
            response.Add((byte)Cls);
            offset += 5;
            return response;
        }
    }
}
