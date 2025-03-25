using Flic.Server.Data;
using Flic.Shared.Models.TaiChinh;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers.TaiChinh
{
    [Route("api/[controller]")]
    [ApiController]
    public class NhomMucController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private static IWebHostEnvironment _env;
        private ILoggerFactory _Factory;
        private ILogger _Logger;
        public NhomMucController(ApplicationDbContext dbContext, IWebHostEnvironment env, ILoggerFactory factory, ILogger logger)
        {
            _env = env;
            _context = dbContext;

            _Factory = factory;
            _Logger = logger;

        }

        [HttpGet("NhomMucGetList")]
        public IEnumerable<TAICHINH_NhomMuc> Get()
        {
            return _context.TAICHINH_NhomMuc.ToList();
        }

        // GET api/<MucChiController>/5
        [HttpGet("NhomMucGetByID/{id}")]
        public TAICHINH_NhomMuc Get(string id)
        {
            return _context.TAICHINH_NhomMuc.Find(id);
        }

        // POST api/<MucChiController>
        [HttpPost("NhomMucAdd")]
        public void Post(TAICHINH_NhomMuc item)
        {
            try
            {
                _context.TAICHINH_NhomMuc.Add(item);
                _context.SaveChanges();
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        // PUT api/<MucChiController>/5
        [HttpPut("NhomMucUpdate")]
        public void Put(TAICHINH_NhomMuc item)
        {
            try
            {
                _context.Entry(item).State = EntityState.Modified;
                _context.SaveChanges();
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        // DELETE api/<MucChiController>/5
        [HttpDelete("NhomMucDelete/{id}")]
        public void Delete(string id)
        {
            try
            {
                TAICHINH_NhomMuc item = _context.TAICHINH_NhomMuc.Find(id);
                if (item != null)
                {
                    _context.TAICHINH_NhomMuc.Remove(item);
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
