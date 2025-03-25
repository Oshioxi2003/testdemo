using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;


namespace Flic.Server.Controllers
{
    //[Authorize]
    //[CustomAuthorization]
    [Route("api/[controller]")]
    [ApiController]
    public class KhoahocController : Controller
    {
        private readonly IKhoahoc _IKhoahoc;
        public KhoahocController(IKhoahoc _Ikhoa)
        {
            _IKhoahoc = _Ikhoa;
        }
        [HttpGet("KhoahocGetList")]
        public async Task<List<Khoahoc>> KhoahocGetList()
        {

            return await Task.FromResult(_IKhoahoc.Get());
        }
        [HttpGet("KhoahocGetByID/{id}")]
        public IActionResult KhoahocGetByID(string id)
        {
            Khoahoc item = _IKhoahoc.Get(id);
            if (item != null)
            {
                return Ok(item);
            }
            return NotFound();
        }
        [Authorize]
        [HttpPost("KhoahocAdd")]
        public async Task<IActionResult> KhoahocAdd(Khoahoc item)
        {
            try
            {
                _IKhoahoc.Add(item);
                return Ok(item);
            }
            catch (Exception e)
            {
                return BadRequest();
            }

        }
        [Authorize]
        [HttpPut("KhoahocUpdate")]
        public bool KhoahocUpdate(Khoahoc item)
        {
            try
            {
                _IKhoahoc.Update(item);
                return true;
            }catch(Exception e)
            {
                Console.WriteLine(e.Message);
                return false;
            }
            
        }
        [Authorize]
        [HttpDelete("KhoahocDelete/{id}")]
        public bool KhoahocDelete(string id)
        {
            try
            {
                _IKhoahoc.Delete(id);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return false;
            }
            
        }
    }
}
