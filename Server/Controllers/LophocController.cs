using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LophocController : ControllerBase
    {
        private readonly ILophoc _ILophoc;
        public LophocController(ILophoc lophoc)
        {
            _ILophoc = lophoc;
        }

        // GET: api/<LophocController>
        [HttpGet("LophocGetList")]
        public async Task<List<Lophoc>> LophocGetList()
        {
            return await Task.FromResult(_ILophoc.Get());
        }

        [HttpGet("LophocGetListActive")]
        public async Task<List<Lophoc>> LophocGetListActive()
        {
            return await Task.FromResult(_ILophoc.GetActive());
        }
        [HttpGet("LophocGetListInActive")]
        public async Task<List<Lophoc>> LophocGetListInActive()
        {
            return await Task.FromResult(_ILophoc.GetInActive());
        }

        [HttpGet("LopHocGetListByLoaiLop/{loailop}")]
        public async Task<List<Lophoc>> LopHocGetListByLoaiLop(string loailop)
        {
            List < Lophoc > ls = _ILophoc.GetListByLoaiLop(loailop).Where(m=>m.Trangthai==1).ToList();
            return await Task.FromResult(ls);
        }

        // GET api/<LophocController>/5
        [HttpGet("LophocGetByID/{id}")]
        public IActionResult GetByID(int id)
        {
            Lophoc item = _ILophoc.Get(id);
            if (item != null)
            {
                return Ok(item);
            }
            return NotFound();
        }

        // POST api/<LophocController>

        [HttpPost("LophocAdd")]
        public async Task<IActionResult> LophocAdd(Lophoc item)
        {
            try
            {
                _ILophoc.Add(item);
                return Ok(item);
            }
            catch (Exception e)
            {
                return BadRequest();
            }
        }

        // PUT api/<LophocController>/5
        [HttpPut("LophocUpdate")]
        public void LophocUpdate(Lophoc item)
        {
            _ILophoc.Update(item);
        }

        // DELETE api/<LophocController>/5
        [HttpDelete("LophocDelete/{id}")]
        public bool LopDelete(int id)
        {
            try
            {
                _ILophoc.Delete(id);
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
