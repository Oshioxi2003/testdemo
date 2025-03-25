using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoaiLophocController : ControllerBase
    {
        private readonly ILoaiLophoc _ILoaiLophoc;
        public LoaiLophocController(ILoaiLophoc iLoaiLophoc)
        {
            _ILoaiLophoc = iLoaiLophoc;
        }

        // GET: api/<LophocController>
        [HttpGet("LoaiLophocGetList")]
        public async Task<List<LoaiLophoc>> LoaiLophocGetList()
        {
            return await Task.FromResult(_ILoaiLophoc.Get());
        }

        [HttpGet("LoaiLophocGetListActive")]
        public async Task<List<LoaiLophoc>> LoaiLophocGetListActive()
        {
            return await Task.FromResult(_ILoaiLophoc.GetActive());
        }
        [HttpGet("LoaiLophococGetListInActive")]
        public async Task<List<LoaiLophoc>> LoaiLophococGetListInActive()
        {
            return await Task.FromResult(_ILoaiLophoc.GetInActive());
        }
        // GET api/<LophocController>/5
        [HttpGet("LoaiLophocGetByID/{id}")]
        public IActionResult LoaiLophocGetByID(string id)
        {
            LoaiLophoc item = _ILoaiLophoc.Get(id);
            if (item != null)
            {
                return Ok(item);
            }
            return NotFound();
        }

        // POST api/<LophocController>

        [HttpPost("LoaiLophocAdd")]
        public async Task<IActionResult> LoaiLophocAdd(LoaiLophoc item)
        {
            try
            {
                _ILoaiLophoc.Add(item);
                return Ok(item);
            }
            catch (Exception e)
            {
                return BadRequest(e.Message);
            }
        }

        // PUT api/<LophocController>/5
        [HttpPut("LoaiLophocUpdate")]
        public async Task<IActionResult> LoaiLophocUpdate(LoaiLophoc item)
        {
            return Ok(_ILoaiLophoc.Update(item));
        }

        // DELETE api/<LophocController>/5
        [HttpDelete("LoaiLophocDelete/{id}")]
        public async Task<IActionResult> LoaiLophocDelete(string id)
        {
            try
            {
                return Ok(_ILoaiLophoc.Delete(id));  
            }
            catch (Exception e)
            {
                Console.WriteLine("ERROR: Delete Lop ID " + id + " " + e.Message);
                return  BadRequest("ERROR: Delete Lop ID " + id + " Error:" +e.Message);
            }

        }
    }
}
