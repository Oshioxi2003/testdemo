using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DotthiController : ControllerBase
    {
        // GET: api/<DotthiController>
    
            private readonly IDotthi _Interface;
            public DotthiController(IDotthi _Int)
            {
                _Interface = _Int;
            }
            [HttpGet("DotthiGetList")]
            public async Task<List<Dotthi>> DotthiGetList()
            {
                return await Task.FromResult(_Interface.Get());
            }
            [HttpGet("DotthiGetListActive")]
            public async Task<List<Dotthi>> DotthiGetListActive()
            {
                return await Task.FromResult(_Interface.Get().Where(m=>m.Status!=null && m.Status ==1).ToList());
            }

        [HttpGet("DotthiGetByID/{id}")]
            public IActionResult DotthiGetByID(string id)
            {
                Dotthi item = _Interface.Get(id);
                if (item != null)
                {
                    return Ok(item);
                }
                return NotFound();
            }
            [HttpPost("DotthiAdd")]
            public async Task<IActionResult> DotthiAdd(Dotthi item)
            {
                try
                {
                    _Interface.Add(item);
                    return Ok(item);
                }
                catch (Exception e)
                {
                    return BadRequest();
                }


            }
            [HttpPut("DotthiUpdate")]
            public void DotthiUpdate(Dotthi item)
            {
                _Interface.Update(item);
            }

            [HttpDelete("DotthiDelete/{id}")]
            public bool DotthiDelete(string id)
            {
                try
                {
                    _Interface.Delete(id);
                    return true;
                }
                catch (Exception e)
                {
                    Console.WriteLine("ERROR: Delete Lop ID " + id + " " + e.Message);
                    return false;
                }

            }
        }
}
