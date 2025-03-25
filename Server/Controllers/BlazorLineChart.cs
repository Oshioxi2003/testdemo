using Flic.Shared.Models;
using Microsoft.AspNetCore.Mvc;
using System.Globalization;
using System.Xml.Linq;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class BlazorLineChart : ControllerBase
    {
        readonly CultureInfo culture = new CultureInfo("en-US");

        [HttpGet]
        public List<DateWiseCount> GetLatestArticls()
        {
            try
            {
                XDocument doc = XDocument.Load("https://www.c-sharpcorner.com/rss/latestarticles.aspx");
                var feeds = from item in doc.Root.Descendants().First(i => i.Name.LocalName == "channel").Elements().Where(i => i.Name.LocalName == "item")
                            select new Feed
                            {
                                PubDate = Convert.ToDateTime(item.Elements().First(i => i.Name.LocalName == "pubDate").Value, culture).ToString("dd-MMM-yy")
                            };

                var feedGroups =
                from p in feeds
                orderby p.PubDate descending
                group p by p.PubDate into g
                select new { PubDate = g.Key, Count = g.Count() };

                List<DateWiseCount> dateWiseCounts = new List<DateWiseCount>();
                foreach (var feed in feedGroups)
                {

                    dateWiseCounts.Add(new DateWiseCount { PubDate = feed.PubDate, Count = feed.Count });
                }
                return dateWiseCounts;

            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}
