using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace DNS1
{
    class Program
    {
        public static async void ClearCache(Dictionary<QType, ConcurrentDictionary<string, DNSEntry>> cache)
        {
            while (true)
            {
                await Task.Delay(30000);
                foreach (var typeCache in cache.Values)
                {
                    foreach (var key in typeCache.Keys)
                    {
                        if (!typeCache.TryGetValue(key, out var entry)) continue;
                        if (DateTime.Now > entry.TimeToDie)
                            typeCache.TryRemove(key, out var _);
                    }
                }
            }
        }

        static void Main(string[] args)
        {
            var cache = new Dictionary<QType, ConcurrentDictionary<string, DNSEntry>>()
            {
                [QType.A] = new ConcurrentDictionary<string, DNSEntry>(),
                [QType.NS] = new ConcurrentDictionary<string, DNSEntry>(),
                [QType.SOA] = new ConcurrentDictionary<string, DNSEntry>(),
                [QType.AAAA] = new ConcurrentDictionary<string, DNSEntry>(),
                [QType.CNAME] = new ConcurrentDictionary<string, DNSEntry>()
            };

            var ROOT = IPAddress.Parse("8.8.8.8");

            IPEndPoint client = null;
            var server = new IPEndPoint(ROOT, 53);
            Task.Run(() => ClearCache(cache));
            using (var rootClient = new UdpClient(11000))
            {
                using (var udpClient = new UdpClient(53))
                {
                    while (true)
                    {
                        var requestData = WaitForConnection(udpClient, ref client);
                        var query = DNSPacketParser.Parse(requestData);
                        Console.WriteLine($"Query from {client}: query: {query.Questions[0].Name} type: {query.Questions[0].Type}\n");
                        var answersToSend = new List<DNSEntry>();
                        foreach (var question in query.Questions)
                            if (cache.ContainsKey(question.Type) &&
                                cache[question.Type].TryGetValue(question.Name, out var data))
                            {
                                if (DateTime.Now > data.TimeToDie)
                                    cache[question.Type].TryRemove(question.Name, out var _);
                                else
                                    answersToSend.Add(data);
                            }
                        if (answersToSend.Count != 0)
                        {
                            var dataToSend = SimpleDNSPacketCreator.CreateResponse(query.Questions, query.Id, answersToSend);
                            udpClient.Send(dataToSend, dataToSend.Length, client);
                            var builder = new StringBuilder();

                            foreach (var answer in answersToSend.Select(x => x.Name))
                            {
                                builder.Append(answer);
                                builder.Append(Environment.NewLine);
                            }
                            Console.WriteLine($"Send to client from cache: {builder} type: {query.Questions[0].Type}");
                        }
                        else
                        {
                            rootClient.Send(requestData, requestData.Length, server);
                            Console.WriteLine($"Can't find entry in cache. Send to server: {query.Questions[0].Name} type: {query.Questions[0].Type}\n");
                            var responseData = rootClient.Receive(ref server);
                            var response = DNSPacketParser.Parse(responseData);
                            Console.WriteLine($"Response from server: query: {response.Questions[0].Name} type: {response.Questions[0].Type}\n");

                            foreach (var question in response.Answers.Concat(response.Authority)
                                .Concat(response.Additional))
                                if (cache.ContainsKey(question.Type))
                                    cache[question.Type][question.Name] = question;

                            udpClient.Send(responseData, responseData.Length, client);
                            Console.WriteLine($"Send response to client: server-address: {ROOT} query:  {response.Questions[0].Name} type: {response.Questions[0].Type}\n");
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
