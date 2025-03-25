using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class Tin03TrangthaiController : ControllerBase
    {
        private readonly ITin03Trangthai _Interface;
        public Tin03TrangthaiController(ITin03Trangthai _Int)
        {
            _Interface = _Int;
        }
        [HttpGet("Tin03TrangthaiGetList")]
        public async Task<List<Tin03_Trangthai>> DiemthiGetList()
        {
            return await Task.FromResult(_Interface.Get());
        }

        [HttpGet("Tin03TrangthaiGetByID/{id}")]
        public IActionResult Tin03TrangthaiGetByID(int id)
        {
            Tin03_Trangthai item = _Interface.Get(id);
            if (item != null)
            {
                return Ok(item);
            }
            return Ok(null);
        }
        [HttpPost("Tin03TrangthaiAdd")]
        public async Task<IActionResult> Tin03TrangthaiAdd(Tin03_Trangthai item)
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
        [HttpPut("Tin03TrangthaiUpdate")]
        public bool Tin03TrangthaiUpdate(Tin03_Trangthai item)
        {
            try
            {
                _Interface.Update(item);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }

        }

        [HttpDelete("Tin03TrangthaiDelete/{id}")]
        public bool Tin03TrangthaiDelete(int id)
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
