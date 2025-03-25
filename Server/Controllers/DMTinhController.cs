using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DMTinhController : ControllerBase
    {
        private readonly IDMTinh _Interface;
        public DMTinhController(IDMTinh _Int)
        {
            _Interface = _Int;
        }
        [HttpGet("DMTinhGetList")]
        public async Task<List<DMTinh>> DMTinhGetList()
        {
            return await Task.FromResult(_Interface.Get());
        }
        
        [HttpGet("DMTinhGetByID/{id}")]
        public IActionResult DMTinhGetByID(int id)
        {
            DMTinh item = _Interface.Get(id);
            if (item != null)
            {
                return Ok(item);
            }
            return NotFound();
        }
        [HttpPost("DMTinhAdd")]
        public async Task<IActionResult> DMTinhAdd(DMTinh item)
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
        [HttpPut("DMTinhUpdate")]
        public void DMTinhUpdate(DMTinh item)
        {
            _Interface.Update(item);
        }

        [HttpDelete("DMTinhDelete/{id}")]
        public bool DMTinhDelete(int id)
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
