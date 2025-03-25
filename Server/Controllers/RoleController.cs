using Flic.Shared.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Controllers
{
    
    [Route("api/[controller]")]
    [ApiController]
    public class RoleController : Controller
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        public RoleController(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }
       
        [HttpGet("GetList")]
        public async Task<IActionResult> GetAll()
        {
            var roles = await _roleManager.Roles.ToListAsync();
            return Ok(roles);
        }
        [HttpGet("Get{id}")]
        public async Task<IActionResult> Get(string id)
        {
            var roles = await _roleManager.Roles.Where(m => m.Id == id).FirstOrDefaultAsync();
            return Ok(roles);
        }
        [HttpPost("Add")]
        public async Task<IActionResult> AddRole([FromBody]  string roleName)
        {
            if (roleName != null)
            {
                await _roleManager.CreateAsync(new IdentityRole(roleName.Trim()));
            }
            return Ok();
        }
    }
}
