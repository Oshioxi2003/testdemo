using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PhongKTXController : ControllerBase
    {
        private readonly IPhongKTX _Interface;
        public PhongKTXController(IPhongKTX Iterface)
        {
            _Interface = Iterface;
        }
        [HttpGet("PhongKTXGetList")]
        public async Task<List<PhongKTX>> PhongKTXGetList()
        {
            return await Task.FromResult(_Interface.Get());
        }
        [HttpGet("PhongKTXGetByID/{id}")]
        public IActionResult PhongKTXGetByID(string id)
        {
            PhongKTX item = _Interface.Get(id);
            if (item != null)
            {
                return Ok(item);
            }
            return NoContent();
        }
        [HttpPost("PhongKTXAdd")]
        public async Task<IActionResult> PhongKTXAdd(PhongKTX item)
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
        [HttpPut("PhongKTXUpdate")]
        public bool PhongKTXUpdate(PhongKTX item)
        {
            try
            {
                _Interface.Update(item);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("Error update Khoa " + e.Message);
                return false;
            }

        }
        [HttpDelete("PhongKTXDelete/{id}")]
        public bool PhongKTXDelete(string id)
        {
            try
            {
                _Interface.Delete(id);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("Delete Phòng KTX ID" + id.ToString() + " Error: " + e.Message);
                return false;
            }

        }
    }
}
