using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Controllers
{    
    //[Authorize]

    [Route("api/[controller]")]
    [ApiController]

    public class LoaiKhoanthuController : Controller
    {
        private readonly ILoaiKhoanthu _ILoaiKhoanthu;
        public LoaiKhoanthuController(ILoaiKhoanthu ILoaiKhoanthu)
        {
            _ILoaiKhoanthu = ILoaiKhoanthu;
        }
        [HttpGet("LoaiKhoanthuGetList")]
        public async Task<IActionResult> Get()
        {            
            string msg = "";
            try
            {
                var ls = _ILoaiKhoanthu.Get();
                return Ok(ls); 
            }
            catch (Exception e)
            {
                msg = e.Message;
            }

            return BadRequest("Invalide token" + msg);
        }

      

        [HttpGet("LoaiKhoanthuGetByID/{id}")]
        public async Task<IActionResult> LoaiKhoanthuGetByID(string id)
        {            
            var item = _ILoaiKhoanthu.Get(id);
            return Ok(item);
        }
        [Authorize]
        [HttpPost("LoaiKhoanthuAdd")]
        public async Task<IActionResult> LoaiKhoanthuAdd(LoaiKhoanthu item)
        {
            var rs = _ILoaiKhoanthu.Add(item);
            return Ok(rs);
        }
        [Authorize]
        [HttpPut("LoaiKhoanthuUpdate")]
        public async Task<IActionResult> LoaiKhoanthuUpdate(LoaiKhoanthu item)
        {
            var rs = _ILoaiKhoanthu.Update(item);
            return Ok(rs);
        }
        [Authorize]
        [HttpDelete("LoaiKhoanthuDelete/{id}")]
        public async Task<IActionResult> LoaiKhoanthuDelete(string id)
        {
            var rs = _ILoaiKhoanthu.Delete(id);
            return Ok(rs);
        }
    }
}
