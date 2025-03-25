using Flic.Shared.Models;
using Flic.Server.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Reflection.PortableExecutable;
using Flic.Server.Interfaces;

namespace eBHYT.Server.Controllers
{
    //[Authorize]
    
    [Route("api/[controller]")]
    [ApiController]
    
    public class KhoanthuController : ControllerBase
    {
        //private readonly ApplicationDbContext _context;
        private readonly IKhoanthu _IKhoanthu;
        public KhoanthuController(IKhoanthu context)
        {
            _IKhoanthu = context;
        }
        [HttpGet ("KhoanthuGetList")]
        public async Task<IActionResult> KhoanthuGetList()
        {            
            string msg = "";
            try
            {
                var kts = _IKhoanthu.Get(); ;
                return Ok(kts);
            }
            catch (Exception e)
            {
                msg = e.Message;
            }


            return BadRequest("Invalide token" + msg);
        }
        [HttpGet("KhoanthuGetByID/{id}")]
        public async Task<IActionResult> KhoanthuGetByID(int id)
        {
            var dev = _IKhoanthu.Get(id);
            return Ok(dev);
        }
        [HttpGet("GetMa/{ma}")]
        public async Task<IActionResult> GetMa(string ma)
        {
            var dev = _IKhoanthu.Get();
            return Ok(dev);
        }
        [HttpPost("PostFindKhoanthu")]
        public async Task<IActionResult> PostFindKhoanthu(Khoanthu kt)
        {
            var rs = await Task.FromResult(_IKhoanthu.GetByItem(kt));
            if (rs!=null)
            {
                return Ok(rs);
            }else
            {
                return NoContent();
            }
        }

        [HttpPost("KhoanthuAdd")]
        public async Task<IActionResult> KhoanthuAdd(Khoanthu kt)
        {
            var rs = _IKhoanthu.Add(kt);            
            return Ok(rs);
        }
        [HttpPut("KhoanthuUpdate")]
        public async Task<IActionResult> KhoanthuUpdate(Khoanthu kt)
        {
            var rs = _IKhoanthu.Update(kt);
            return Ok(rs);
        }
        [HttpDelete("KhoanthuDelete/{id}")]
        public async Task<IActionResult> KhoanthuDelete(int id)
        {
            var rs = _IKhoanthu.Delete(id);
            return Ok(rs);
        }
    }
}
