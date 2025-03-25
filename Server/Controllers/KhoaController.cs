using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Flic.Server.Controllers
{
    
    //[CustomAuthorization]
    [Route("api/[controller]")]
    [ApiController]
    public class KhoaController : Controller
    {
        private readonly IKhoa _IKhoa;
        public KhoaController(IKhoa _Ikhoa)
        {
            _IKhoa = _Ikhoa;
        }
        [HttpGet("KhoaGetList")]
        public async Task<List<Khoa>> KhoaGetList()        
        {

            return await Task.FromResult(_IKhoa.Get());
        }
        [HttpGet("KhoaGetByID/{id}")]
        public IActionResult GetByID(string id)
        {
            Khoa item = _IKhoa.Get(id);
            if (item != null)
            {
                return Ok(item);
            }
            return NotFound();
        }
        [Authorize]
        [HttpPost("KhoaAdd")]
        public async Task<IActionResult> KhoaAdd(Khoa item)
        {
            try
            {
                _IKhoa.Add(item);
                return Ok(item);
            }catch(Exception e)
            {
                return BadRequest();
            }
            

        }
        [Authorize]
        [HttpPut("KhoaUpdate")]
        public bool KhoaUpdate(Khoa item)
        {
            try
            {
                _IKhoa.Update(item);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("Error update Khoa " + e.Message);
                return false;
            }
            
        }
        [Authorize]
        [HttpDelete("KhoaDelete/{id}")]
        public bool KhoaDelete(string id)
        {
            try
            {
                _IKhoa.Delete(id);
                return true;
            }catch (Exception e)
            {
                Console.WriteLine("Delete Khoa ID" + id.ToString() + " Error: " + e.Message);
                return false;
            }
            
        }
    }
}
