using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SinhvienPhongKTXController : ControllerBase
    {
        private readonly ISinhvienPhong _Interface;
        public SinhvienPhongKTXController(ISinhvienPhong Interface)
        {
            _Interface = Interface;
        }
        [HttpGet("SinhvienPhongKTXGetList")]
        public async Task<List<SinhvienPhongView>> SinhvienPhongKTXGetList()
        {
            return await Task.FromResult(_Interface.Get());
        }
        [HttpGet("SinhvienPhongKTXGetByID/{id}")]
        public IActionResult SinhvienPhongKTXGetByID(int id)
        {
            SinhvienPhongView item = _Interface.Get(id);
            if (item != null)
            {
                return Ok(item);
            }
            return NotFound();
        }
        [HttpPost("SinhvienPhongKTXAdd")]
        public async Task<IActionResult> SinhvienPhongKTXAdd(SinhvienPhong item)
        {
            try
            {
               if (_Interface.Add(item))
               {
                    return Ok(item);
               }
                return Ok(null); 
            }
            catch (Exception e)
            {
                return BadRequest(e.Message);
            }

        }
        [HttpPut("SinhvienPhongKTXUpdate")]
        public bool PhongKTXUpdate(SinhvienPhong item)
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
        [HttpDelete("SinhvienPhongKTXDelete/{id}")]
        public bool SinhvienPhongKTXDelete(int id)
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
