using System.Collections.Generic;

namespace DNS1
{
    class Buffer : Queue<byte>
    {
        public int Offset { get; private set; }

        public Buffer(byte[] data) : base(data)
        {
        }

        public byte Pop()
        {
            Offset++;
            return Dequeue();
        }
    }
}
