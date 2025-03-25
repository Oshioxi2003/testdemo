using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;


namespace Flic.Server.Controllers
{
    
    //[CustomAuthorization]
    [Route("api/[controller]")]
    [ApiController]
    public class LopController : Controller
    {
        private readonly ILop _ILop;
        public LopController(ILop _Ilop)
        {
            _ILop = _Ilop;
        }
        [HttpGet("LopGetList")]
        public async Task<List<Lop>> LopGetList()
        {
            return await Task.FromResult(_ILop.Get());
        }

        [HttpGet("LopGetListByKhoahoc/{khoahocId}")]
        public async Task<List<Lop>> LopGetListByKhoa(string khoahocId)
        {
            return await Task.FromResult(_ILop.Get().ToList().Where(m=>m.KhoahocID== khoahocId).ToList());
        }

        [HttpGet("LopGetListByKhoahocNganh/{khoahoc}/{nganh}")]
        public async Task<List<Lop>> LopGetListByKhoahocNganh(string khoahoc, string nganh)
        {
            return await Task.FromResult(_ILop.Get().ToList().Where(m => m.KhoahocID == khoahoc && m.NganhID == nganh).ToList());
        }

        [HttpGet("LopGetByID/{id}")]
        public IActionResult GetByID(string id)
        {
            Lop item = _ILop.Get(id);
            if (item != null)
            {
                return Ok(item);
            }
            return NotFound();
        }
        [Authorize]
        [HttpPost("LopAdd")]
        public async Task<IActionResult> LopAdd(Lop item)
        {
            try
            {
                _ILop.Add(item);
                return Ok(item);
            }
            catch (Exception e)
            {
                return BadRequest();
            }
        }
        [Authorize]
        [HttpPut("LopUpdate")]
        public void LopUpdate(Lop item)
        {
            _ILop.Update(item);
        }
        [Authorize]
        [HttpDelete("LopDelete/{id}")]
        public bool LopDelete(string id)
        {
            try
            {
                _ILop.Delete(id);
                return true;
            }
            catch(Exception e)
            {
                Console.WriteLine("ERROR: Delete Lop ID " + id + " " + e.Message);
                return false;
            }           
            
        }
    }
}
