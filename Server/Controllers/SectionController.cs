using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SectionController : Controller
    {
        
        private readonly ISection _Interface;
        public SectionController(ISection _Int)
        {
            _Interface = _Int;
        }
        [HttpGet("SectionGetList")]
        public async Task<List<Section>> SectionGetList()
        {
            return await Task.FromResult(_Interface.Get());
        }

        //[HttpGet("SectionGetListByKhoahoc/{khoahocId}")]
        //public async Task<List<Lop>> LopGetListByKhoa(string khoahocId)
        //{
        //    return await Task.FromResult(_ILop.Get().ToList().Where(m => m.KhoahocID == khoahocId).ToList());
        //}

        //[HttpGet("LopGetListByKhoahocNganh/{khoahoc}/{nganh}")]
        //public async Task<List<Lop>> LopGetListByKhoahocNganh(string khoahoc, string nganh)
        //{
        //    return await Task.FromResult(_ILop.Get().ToList().Where(m => m.KhoahocID == khoahoc && m.NganhID == nganh).ToList());
        //}

        [HttpGet("SectionGetByID/{id}")]
        public IActionResult SectionGetByID(int id)
        {
            Section item = _Interface.Get(id);
            if (item != null)
            {
                return Ok(item);
            }
            return NotFound();
        }
        //[Authorize]
        [HttpPost("SectionAdd")]
        public async Task<IActionResult> SectionAdd(Section item)
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
        [Authorize]
        [HttpPut("SectionUpdate")]
        public void SectionUpdate(Section item)
        {
            _Interface.Update(item);
        }
        [Authorize]
        [HttpDelete("SectionDelete/{id}")]
        public bool SectionDelete(int id)
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
