using RestSharp; // Used in the Main method
using Newtonsoft.Json; // Used in the DeserializeJson method
using Ganss.XSS; // Vulnerable package, used in an unused method
using AutoMapper; // Unused but imported, vulnerable package

namespace VulnerableApp
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Starting Vulnerable Application...");

            // Vulnerability in RestSharp package (CVE-2021-27293)
            // HIGH https://github.com/advisories/GHSA-9pq7-rcxv-47vq
            var client = new RestClient("http://worldtimeapi.org/");
            var request = new RestRequest("api/timezone/Europe/Madrid", Method.GET);
            var response = client.Execute(request);
            Console.WriteLine($"Response from API: {response.Content}");

            // Use the vulnerable Newtonsoft.Json package (CVE-2024-21907)
            DeserializeJson();
        }

        // Vulnerability in Newtonsoft.Json package (CVE-2024-21907)
        // HIGH https://nvd.nist.gov/vuln/detail/CVE-2024-21907
        static void DeserializeJson()
        {
            // Simulated untrusted JSON input
            string json = "{\"Name\":\"John Doe\",\"Age\":30}";

            // Deserialize into a Person, which can be a security risk when deserializing untrusted data
            var person = JsonConvert.DeserializeObject<Person>(json);
            Console.WriteLine($"Deserialized Person: Name = {person.Name}, Age = {person.Age}");

        }

        // Vulnerability in HtmlSanitizer package (CVE-2021-26701)
        // LOW https://github.com/advisories/GHSA-8j9v-h2vp-2hhv
        // MEDIUM https://github.com/advisories/GHSA-43cp-6p3q-2pc4
        static void UnusedMethod()
        {
            var sanitizer = new HtmlSanitizer();
            var sanitizedHtml = sanitizer.Sanitize("<script>alert('xss');</script>");
            Console.WriteLine($"This method uses HtmlSanitizer, but is never called. Output = {sanitizedHtml}");
        }

        // AutoMapper is added to the project but never used

    }

    public class Person
    {
        public string Name { get; set; }
        public int Age { get; set; }

    }
}
