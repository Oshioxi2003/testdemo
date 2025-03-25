using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DMDantocController : ControllerBase
    {
        // GET: api/<DMDantocController>
        private readonly IDMDantoc _Interface;
        public DMDantocController(IDMDantoc _Int)
        {
            _Interface = _Int;
        }
        [HttpGet("DMDantocGetList")]
        public async Task<List<DMDantoc>> DMDantocGetList()
        {
            return await Task.FromResult(_Interface.Get());
        }

        [HttpGet("DMDantocGetByID/{id}")]
        public IActionResult DMDantocGetByID(int id)
        {
            DMDantoc item = _Interface.Get(id);
            if (item != null)
            {
                return Ok(item);
            }
            return NotFound();
        }
        [HttpPost("DMDantocAdd")]
        public async Task<IActionResult> DMDantocAdd(DMDantoc item)
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
        [HttpPut("DMDantocUpdate")]
        public void DMDantocUpdate(DMDantoc item)
        {
            _Interface.Update(item);
        }

        [HttpDelete("DMDantocDelete/{id}")]
        public bool DMDantocDelete(int id)
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
