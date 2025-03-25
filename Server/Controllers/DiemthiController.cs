using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DiemthiController : ControllerBase
    {        
        private readonly IDiemthi _Interface;
        public DiemthiController(IDiemthi _Int)
        {
            _Interface = _Int;
        }
        [HttpGet("DiemthiGetList")]
        public async Task<List<Diemthi>> DiemthiGetList()
        {
            return await Task.FromResult(_Interface.Get());
        }

        [HttpGet("DiemthiGetByID/{id}")]
        public IActionResult DiemthiGetByID(string id)
        {
            Diemthi item = _Interface.Get(id);
            if (item != null)
            {
                return Ok(item);
            }
            return NotFound();
        }
        [HttpPost("DiemthiAdd")]
        public async Task<IActionResult> DiemthiAdd(Diemthi item)
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
        [HttpPut("DiemthiUpdate")]
        public bool DiemthiUpdate(Diemthi item)
        {
            try
            {
                _Interface.Update(item);
                return true;
            }
            catch(Exception e)
            {
                return false;
            }
            
        }

        [HttpDelete("DiemthiDelete/{id}")]
        public bool DiemthiDelete(string id)
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
