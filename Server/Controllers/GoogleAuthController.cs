using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class GoogleAuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;

        public GoogleAuthController(IConfiguration configuration,
                                 SignInManager<IdentityUser> signInManager,
                                 UserManager<IdentityUser> userManager)
        {
            _configuration = configuration;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        [HttpGet("login")]
        public IActionResult Login(string returnUrl = null)
        {
            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Google",
                Url.Action(nameof(GoogleCallback), "GoogleAuth", new { returnUrl }));
            return Challenge(properties, "Google");
        }

        [HttpGet("callback")]
        public async Task<IActionResult> GoogleCallback(string returnUrl = null)
        {
            // Get the login info from the external provider
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return Redirect("/login?error=ExternalLoginFailure");
            }

            // Sign in the user with the external login provider
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);

            if (result.Succeeded)
            {
                // User is authenticated - generate JWT token
                var identityUser = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
                var token = await GenerateJwtToken(identityUser);
                return Redirect($"/google-callback?token={token}");
            }

            // The external login is not linked to a local user - create a new user
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            var newUser = new IdentityUser
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true
            };

            var createResult = await _userManager.CreateAsync(newUser);
            if (createResult.Succeeded)
            {
                // Add the external login to the new user
                var addLoginResult = await _userManager.AddLoginAsync(newUser, info);
                if (addLoginResult.Succeeded)
                {
                    // Optionally assign a default role
                    // await _userManager.AddToRoleAsync(newUser, "USER");

                    // Generate JWT token
                    var token = await GenerateJwtToken(newUser);
                    return Redirect($"/google-callback?token={token}");
                }
            }

            // If we got this far, something failed
            return Redirect("/login?error=UserCreationFailed");
        }

        private async Task<string> GenerateJwtToken(IdentityUser user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName)
            };

            // Add roles to claims
            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

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

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
