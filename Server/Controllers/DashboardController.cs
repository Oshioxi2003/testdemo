using Flic.Server.Data;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DashboardController : ControllerBase
    {
        readonly ApplicationDbContext _dbContext;
        public DashboardController(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }
        // GET: api/<DashboardController>
        [HttpGet]        
        public async Task<DashboardResult> Get()
        {
            DashboardResult s = new DashboardResult();
            s.student_stats = new List<StudentStatistic>();
            var students = _dbContext.Students.Where(m => m.Trangthai == "DH").ToList();
            var rs = from e in students
                     group e by (e.KhoahocID, e.KhoaID, e.NganhID) into g
                select new { Group = g.Key, Total = g.Count() };
            foreach(var item in rs)
            {
                var p = item.Group;
                var n = new StudentStatistic();
                n.KhoahocID = p.KhoahocID;
                n.KhoaID = p.KhoaID;
                n.NganhID = p.NganhID;
                n.NumStudent = item.Total;
                s.student_stats.Add(n);
            }
            return await Task.FromResult(s);
        }
        // GET api/<DashboardController>/5
        [HttpGet("{id}")]
        public string Get(int id)
        {
            return "value";
        }

        // POST api/<DashboardController>
        [HttpPost]
        public void Post([FromBody] string value)
        {
        }

        // PUT api/<DashboardController>/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE api/<DashboardController>/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
