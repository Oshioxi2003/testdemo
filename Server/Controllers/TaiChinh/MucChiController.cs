using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models.TaiChinh;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers.TaiChinh
{
    [Route("api/[controller]")]
    [ApiController]
    public class MucChiController : ControllerBase
    {
        // GET: api/<MucChiController>        
        private readonly ApplicationDbContext _context;
        private static IWebHostEnvironment _env;
        private ILoggerFactory _Factory;
        private ILogger _Logger;
        public MucChiController(ApplicationDbContext dbContext, IWebHostEnvironment env, ILoggerFactory factory, ILogger logger)
        {
            _env = env;
            _context = dbContext;

            _Factory = factory;
            _Logger = logger;

        }

        [HttpGet("MucChiGetList")]
        public IEnumerable<TAICHINH_MucChi> Get()
        {
            return _context.TAICHINH_MucChi.ToList();
        }
        [HttpGet("MucChiGetListByNhom/{nhom}")]
        public IEnumerable<TAICHINH_MucChi> MucChiGetListByNhom(string nhom)
        {
            return _context.TAICHINH_MucChi.Where(m=>m.NhomMuc.Equals(nhom)).ToList();
        }
        // GET api/<MucChiController>/5
        [HttpGet("MucChiGetByID/{id}")]
        public TAICHINH_MucChi Get(int id)
        {
            return _context.TAICHINH_MucChi.Find(id);
        }

        // POST api/<MucChiController>
        [HttpPost("MucChiAdd")]
        public void Post(TAICHINH_MucChi item)
        {
            try
            {
                _context.TAICHINH_MucChi.Add(item);
                _context.SaveChanges();
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        // PUT api/<MucChiController>/5
        [HttpPut("MucChiUpdate")]
        public void Put(TAICHINH_MucChi item)
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
        [HttpDelete("MucChiDelete/{id}")]
        public void Delete(int id)
        {
            try
            {
                TAICHINH_MucChi item = _context.TAICHINH_MucChi.Find(id);
                if (item != null)
                {
                    _context.TAICHINH_MucChi.Remove(item);
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
