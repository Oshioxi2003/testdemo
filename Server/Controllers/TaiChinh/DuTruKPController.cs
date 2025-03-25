using Flic.Server.Data;
using Flic.Shared.Models.TaiChinh;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers.TaiChinh
{
    [Route("api/[controller]")]
    [ApiController]
    public class DuTruKPController : ControllerBase
    {
        // GET: api/<MucChiController>        
        private readonly ApplicationDbContext _context;
        private static IWebHostEnvironment _env;
        private ILoggerFactory _Factory;
        private ILogger _Logger;
        public DuTruKPController(ApplicationDbContext dbContext, IWebHostEnvironment env, ILoggerFactory factory, ILogger logger)
        {
            _env = env;
            _context = dbContext;

            _Factory = factory;
            _Logger = logger;

        }

        [HttpGet("DuTruKPGetList")]
        public IEnumerable<TAICHINH_DuTruKP> Get()
        {
            return _context.TAICHINH_DuTruKP.ToList();
        }
        [HttpGet("DuTruKPGetListByDonvi/{ma}")]
        public IEnumerable<TAICHINH_DuTruKP> DuTruKPGetListByDonvi(string ma)
        {
            return _context.TAICHINH_DuTruKP.Where(m=>m.MaDonVi.Equals(ma)).ToList();
        }
        // GET api/<MucChiController>/5
        [HttpGet("DuTruKPGetByID/{id}")]
        public TAICHINH_DuTruKP Get(int id)
        {
            return _context.TAICHINH_DuTruKP.Find(id);
        }

        // POST api/<MucChiController>
        [HttpPost("DuTruKPAdd")]
        public void Post(TAICHINH_DuTruKP item)
        {
            try
            {
                item.NgayTao = DateTime.Now;                
                _context.TAICHINH_DuTruKP.Add(item);
                _context.SaveChanges();
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        // PUT api/<MucChiController>/5
        [HttpPut("DuTruKPUpdate")]
        public void Put(TAICHINH_DuTruKP item)
        {
            try
            {
                item.NgaySua = DateTime.Now;
                _context.Entry(item).State = EntityState.Modified;
                _context.SaveChanges();
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        // DELETE api/<MucChiController>/5
        [HttpDelete("DuTruKPDelete/{id}")]
        public void Delete(int id)
        {
            try
            {
                TAICHINH_DuTruKP item = _context.TAICHINH_DuTruKP.Find(id);
                if (item != null)
                {
                    _context.TAICHINH_DuTruKP.Remove(item);
                    _context.SaveChanges();
                }
                else
                {
                    throw new Exception("Không tìm thấy bản ghi: " + id.ToString());
                }

            }
            catch (Exception ex)
            {
                throw new Exception("Lỗi xảy ra khi xóa: " + ex.Message);
            }
        }
    }
}
