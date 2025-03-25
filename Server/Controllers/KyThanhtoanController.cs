using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class KyThanhtoanController : ControllerBase
    {
        private readonly IKyThanhtoan _IKyThanhtoan;
        public KyThanhtoanController(IKyThanhtoan IKyThanhtoan)
        {
            _IKyThanhtoan = IKyThanhtoan;
        }
        [HttpGet("KyThanhtoanGetList")]
        public async Task<List<KyThanhtoan>> KyThanhtoanGetList()
        {
            var rs = await Task.FromResult(_IKyThanhtoan.Get());
            return rs;
        }
        [HttpGet("KyThanhtoanGetByID/{id}")]
        public IActionResult KyThanhtoanGetByID(string id)
        {
            KyThanhtoan item = _IKyThanhtoan.Get(id);
            if (item != null)
            {
                return Ok(item);
            }
            return NotFound();
        }
        [HttpGet("KyThanhtoanGetByKhoanthu/{id}")]
        public async Task<List<KyThanhtoan>> KyThanhtoanGetByKhoanthu(string id)
        {
            var rs = await Task.FromResult(_IKyThanhtoan.GetByKhoanthu(id));
            return rs;            
        }
        [HttpPost("KyThanhtoanAdd")]
        public async Task<IActionResult> KyThanhtoanAdd(KyThanhtoan item)
        {
            try
            {
                _IKyThanhtoan.Add(item);
                return Ok(item);
            }
            catch (Exception e)
            {
                return BadRequest();
            }


        }
        [HttpPut("KyThanhtoanUpdate")]
        public bool KyThanhtoanUpdate(KyThanhtoan item)
        {
            try
            {
                _IKyThanhtoan.Update(item);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("Error update Khoa " + e.Message);
                return false;
            }

        }
        [HttpDelete("KyThanhtoanDelete/{id}")]
        public bool KyThanhtoanDelete(string id)
        {
            try
            {
                _IKyThanhtoan.Delete(id);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("Delete Khoa ID" + id.ToString() + " Error: " + e.Message);
                return false;
            }

        }
    }
}
