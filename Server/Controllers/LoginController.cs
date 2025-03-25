using Flic.Shared;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.NetworkInformation;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Session;
using Flic.Server.Data;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly SignInManager<IdentityUser> _signInManager;
        readonly ApplicationDbContext _dbContext;

        public LoginController(IConfiguration configuration,
                               SignInManager<IdentityUser> signInManager, ApplicationDbContext dbContext)
        {
            _configuration = configuration;
            _signInManager = signInManager;
            _dbContext = dbContext;
        }

        [HttpPost]
        public async Task<IActionResult> Login([FromBody] LoginModel login)
        {
            var result = await _signInManager.PasswordSignInAsync(login.Username, login.Password, false, false);
            var claims = new List<Claim>();
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSecurityKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expiry = DateTime.Now.AddDays(Convert.ToInt32(_configuration["JwtExpiryInDays"]));

            var token = new JwtSecurityToken(
                            _configuration["JwtIssuer"],
                            _configuration["JwtAudience"],
                            claims,
                            expires: expiry,
                            signingCredentials: creds
                        );

            if (!result.Succeeded)
            {
                //check login with student
                var std = _dbContext.Students.Where(m => (m.MaSV!=null && m.MaSV == login.Username)).FirstOrDefault();
                if (std == null)
                {
                    return BadRequest(new LoginResult { Successful = false, Error = "Không tìm thấy tài khoản" });
                }else
                {
                    if (std.Ngaysinh != login.Password)
                    {
                        return BadRequest(new LoginResult { Successful = false, Error = "Sai mật khẩu" });
                    }else
                    {                        
                        claims.Add(new Claim(ClaimTypes.Name, login.Username));
                        claims.Add(new Claim(ClaimTypes.Role, "SINHVIEN"));                        

                        token = new JwtSecurityToken(
                            _configuration["JwtIssuer"],
                            _configuration["JwtAudience"],
                            claims,
                            expires: expiry,
                            signingCredentials: creds
                        );
                        //await storage.SetAsync("greeting", "Hello, World!");
                        return Ok(new LoginResult { Successful = true, Token = new JwtSecurityTokenHandler().WriteToken(token) });
                    }
                }
                //return BadRequest(new LoginResult { Successful = false, Error = "Username and password are invalid." });
            }
            
            var user = await _signInManager.UserManager.FindByNameAsync(login.Username);
            var roles = await _signInManager.UserManager.GetRolesAsync(user);            

            claims.Add(new Claim(ClaimTypes.Name, login.Username));

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }            

            token = new JwtSecurityToken(
                _configuration["JwtIssuer"],
                _configuration["JwtAudience"],
                claims,
                expires: expiry,
                signingCredentials: creds
            );
            //await storage.SetAsync("greeting", "Hello, World!");
            return Ok(new LoginResult { Successful = true, Token = new JwtSecurityTokenHandler().WriteToken(token) });
        }
    }
}
