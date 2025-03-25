using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;


namespace Flic.Server.Controllers
{
    
    //[CustomAuthorization]
    [Route("api/[controller]")]
    [ApiController]
    public class NganhController : Controller
    {
        private readonly INganh _INganh;
        private readonly IKhoa _IKhoa;
        public NganhController(INganh _Inganh, IKhoa _Ikhoa)
        {
            _INganh = _Inganh;
            _IKhoa = _Ikhoa;
        }
        public string GetKeyFromDict(Dictionary<string, string> d, string key)
        {
            try
            {
                string v = d[key];
                return v;
            }
            catch
            {
                return "";
            }
            
        }
        [HttpGet("NganhGetList")]
        public async Task<List<NganhListView>> NganhGetList()
        {
            List<Nganh> rs = _INganh.Get();
            List<Khoa> khoaList = _IKhoa.Get();
            Dictionary<string, string> khoaDict = khoaList.ToDictionary(k=>k.Id, v=>v.Name);

            IEnumerable< NganhListView> q = from p in rs                                            
                    select new NganhListView
                    {
                        Id = p.Id,
                        Name = p.Name,
                        KhoaId = p.KhoaId,
                        KhoaName = GetKeyFromDict( khoaDict, p.KhoaId)
                    };

            return await Task.FromResult(q.ToList());
        }        
        [HttpGet("NganhGetListByKhoa/{khoaID}")]
        public async Task<List<NganhListView>> NganhGetListByKhoa(string khoaId)
        {
            List<Nganh> rs = _INganh.Get().ToList().Where(m=>m.KhoaId == khoaId).ToList();
            List<Khoa> khoaList = _IKhoa.Get();
            Dictionary<string, string> khoaDict = khoaList.ToDictionary(k => k.Id, v => v.Name);

            IEnumerable<NganhListView> q = from p in rs
            select new NganhListView
            {
                Id = p.Id,
                Name = p.Name,
                KhoaId = p.KhoaId,
                KhoaName = GetKeyFromDict(khoaDict, p.KhoaId)
            };

            return await Task.FromResult(q.ToList());
        }

        [HttpGet("NganhGetByID/{id}")]
        public IActionResult GetByID(string id)
        {
            Nganh item = _INganh.Get(id);
            if (item != null)
            {
                return Ok(item);
            }
            return NotFound();
        }
        [Authorize]
        [HttpPost("NganhAdd")]
        public async Task<IActionResult> NganhAdd(Nganh item)
        {
            try
            {
                _INganh.Add(item);
                return Ok(item);
            }
            catch (Exception e)
            {
                return BadRequest();
            }
        }
        [Authorize]
        [HttpPut("NganhUpdate")]
        public bool NganhUpdate(Nganh item)
        {
            try
            {
                _INganh.Update(item);
                return true;
            }catch (Exception e)
            {
                Console.WriteLine("Update Nganh error: " + e.Message);
                return false;
            }
            
        }
        [Authorize]
        [HttpDelete("NganhDelete/{id}")]
        public bool NganhDelete(string id)
        {
            try
            {
                _INganh.Delete(id);
                return true;
            }catch (Exception e)
            {
                Console.WriteLine("Delete Nganh error: " + e.Message);
                return false;
            }
            
        }
    }
}
