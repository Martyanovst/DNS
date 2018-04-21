using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace DNS1
{
    class Program
    {
        static void Main(string[] args)
        {
            var cache = new Dictionary<QType, Dictionary<string, DNSEntry>>()
            {
                [QType.A] = new Dictionary<string, DNSEntry>(),
                [QType.NS] = new Dictionary<string, DNSEntry>(),
                [QType.SOA] = new Dictionary<string, DNSEntry>(),
                [QType.AAAA] = new Dictionary<string, DNSEntry>(),
                [QType.CNAME] = new Dictionary<string, DNSEntry>()
            };

            var ROOT = IPAddress.Parse("8.8.8.8");

            IPEndPoint client = null;
            var server = new IPEndPoint(ROOT, 53);

            using (var rootClient = new UdpClient(11000))
            {
                using (var udpClient = new UdpClient(53))
                {
                    while (true)
                    {
                        var requestData = WaitForConnection(udpClient, ref client);
                        var query = DNSPacketParser.Parse(requestData);

                        var answersToSend = new List<DNSEntry>();
                        foreach (var question in query.Questions)
                            if (cache.ContainsKey(question.Type) &&
                                cache[question.Type].TryGetValue(question.Name, out var data))
                            {
                                if (DateTime.Now > data.TimeToDie)
                                    cache[question.Type].Remove(question.Name);
                                else
                                    answersToSend.Add(data);
                            }

                        if (answersToSend.Count != 0)
                        {
                            var dataToSend = SimpleDNSPacketCreator.CreateResponse(query.Questions, query.Id, answersToSend);
                            udpClient.Send(dataToSend, dataToSend.Length, client);
                        }
                        else
                        {
                            rootClient.Send(requestData, requestData.Length, server);
                            var responseData = rootClient.Receive(ref server);
                            var response = DNSPacketParser.Parse(responseData);
                            foreach (var question in response.Answers.Concat(response.Authority)
                                .Concat(response.Additional))
                            {
                                if (cache.ContainsKey(question.Type))
                                    cache[question.Type][question.Name] = question;
                            }

                            udpClient.Send(responseData, responseData.Length, client);
                        }
                    }
                }
            }
        }

        public static byte[] TryReceive(UdpClient udpClient, int depth, ref IPEndPoint client)
        {
            if (depth >= 10)
                return new byte[0];
            try
            {
                var requestData = udpClient.Receive(ref client);
                return requestData;
            }
            catch
            {
                return TryReceive(udpClient, depth + 1, ref client);
            }
        }

        public static byte[] WaitForConnection(UdpClient udpClient, ref IPEndPoint client)
        {
            var request = TryReceive(udpClient, 0, ref client);
            while (request.Length == 0)
                request = TryReceive(udpClient, 0, ref client);
            return request;
        }
    }
}
