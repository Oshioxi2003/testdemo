using Flic.Server.Data;
using Flic.Shared;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Org.BouncyCastle.Asn1.Pkcs;
using Newtonsoft.Json;
using System.Security.Authentication.ExtendedProtection;
using MathNet.Numerics.Distributions;
using Flic.Server.Interfaces;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class VantinController : ControllerBase
    {
        // GET: api/<VantinController>
        readonly ApplicationDbContext _dbContext;
        private static IWebHostEnvironment _env;
        private readonly IThutien _IThutien;

        private RSA privateKey;
        private RSA publicKey;

        public VantinController(ApplicationDbContext dbContext, IThutien context, IWebHostEnvironment env)
        {
            _dbContext = dbContext;
            this._IThutien = context;
            _env = env;
        }

        [HttpGet]
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }

        // GET api/<VantinController>/5
        [HttpGet("{id}")]
        public string Get(int id)
        {
            return "value";
        }

        // POST api/<VantinController>
        [HttpPost]
        public async Task<ResponseVanTin> Post(RequestVanTin req)
        {
            string pub_path = Path.Combine(_env.ContentRootPath, CommonInfo.PublicKeyPath);
            string pri_path = Path.Combine(_env.ContentRootPath, CommonInfo.PrivateKeyPath);
            string pass_path = Path.Combine(_env.ContentRootPath, CommonInfo.PasswordPath);

            string Password = System.IO.File.ReadAllText(pass_path).Trim();
            ResponseVanTin rs = new ResponseVanTin();

            try
            {
                req.timeRequest= DateTime.Now;
                
                _dbContext.RequestVanTins.Add(req);
                _dbContext.SaveChanges();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                //throw ex;
                rs.responseDesc = "Lỗi không cập nhật được Request - " + ex.Message;
                return rs;
            }
            

            try
            {
                var collection = new X509Certificate2Collection();
                //collection.Import(pub_path);
                //var certificate = collection[0];                
                //publicKey = (RSA)certificate.PublicKey.Key;               

                collection = new X509Certificate2Collection();
                //collection.Import(System.IO.File.ReadAllBytes(pri_path), Password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
                collection.Import(System.IO.File.ReadAllBytes(pri_path), Password, X509KeyStorageFlags.DefaultKeySet);
                var certificate = collection[0];
                privateKey = (RSA)certificate.PrivateKey;

                var std = _dbContext.Students.Where(m => m.MaSV.Equals(req.custCode)).FirstOrDefault();
                if (std != null)
                {
                    var list = await Task.FromResult(_IThutien.GetByMSV(req.custCode));
                    string json = JsonConvert.SerializeObject(list);
                    var signature = Sign(json, privateKey);
                    rs.signature = signature;
                    rs.items = json;
                }                
                rs.requestId = req.requestId;
                rs.responseCode = "1";
                rs.custName = std.HoDem + " " + std.Ten;
                rs.address = std.LopID;
                rs.addInfor1 = std.NganhID;
                rs.birthday = std.Ngaysinh;
                rs.transTime = DateTime.Now;
                rs.responseDesc = "Mô tả";
               
                _dbContext.ResponseVanTins.Add(rs);
                _dbContext.SaveChanges();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                //throw ex;
                rs.responseDesc = "Lỗi " + ex.Message ;
                return rs;
            }

            rs.responseDesc = "Thành công";
            return rs;
        }

        // PUT api/<VantinController>/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE api/<VantinController>/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
        // Sign with RSA using private key
        public string Sign(string text, RSA rsa)
        {
            byte[] data = Encoding.UTF8.GetBytes(text);
            byte[] signature = rsa.SignData(data,
               HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signature);
        }
        // Verify with RSA using public key
        public bool Verify(string text, string signatureBase64, RSA rsa)
        {
            byte[] data = Encoding.UTF8.GetBytes(text);
            byte[] signature = Convert.FromBase64String(signatureBase64);
            bool isValid = rsa.VerifyData(data,
                signature,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            return isValid;
        }
    }
}
