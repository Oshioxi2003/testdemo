using DocumentFormat.OpenXml.Office2010.Excel;
using DocumentFormat.OpenXml.Spreadsheet;
using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.JSInterop;
using System.Linq;
using System.Threading.Tasks;
using static System.Net.WebRequestMethods;

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountsController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        readonly ApplicationDbContext _dbContext;
        IEmailService _emailService = null;
        private ILogger _Logger;
        public AccountsController(UserManager<IdentityUser> userManager, ApplicationDbContext dbContext, IEmailService emailService, ILogger logger)
        {
            _userManager = userManager;
            _dbContext = dbContext;
            _emailService = emailService;
            _Logger = logger;
        }
        [HttpGet("GetList")]
        public async Task<List<Microsoft.AspNetCore.Identity.IdentityUser>> GetAll()
        {
            var result = await _userManager.Users.ToListAsync();
            return result; // Ok(Task.FromResult(result));
        }
        [HttpGet("CheckUserExist/{username}")]
        public async Task<bool> CheckUserExist(string username)
        {
            var result = await _userManager.Users.Where(m => m.UserName.ToLower().Equals(username.ToLower())).FirstOrDefaultAsync();
            //var a= result.Where(m=>m.UserName.ToLower().Equals(username.ToLower())).FirstOrDefault(); // Ok(Task.FromResult(result));
            if (result != null)
            {
                return true;
            }else
            {
                return false;
            }
        }

        [HttpPost]
        public async Task<IActionResult> Post([FromBody]RegisterModel model)
        {
            var newUser = new IdentityUser { UserName = model.Username, Email = model.Email };

            var result = await _userManager.CreateAsync(newUser, model.Password);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(x => x.Description);
                
                return Ok(new RegisterResult { Successful = false, Errors = errors });
            }
            
            LogModel log = new LogModel();
            log.Username = model.Username;
            log.Password = model.Password;
            _dbContext.LogModels.Add(log);
            _dbContext.SaveChanges();

            // Add all new users to the User role
            if (model.Role == "")
            {
                await _userManager.AddToRoleAsync(newUser, "User");
            }
            else
            {
                await _userManager.AddToRoleAsync(newUser, model.Role);
            }
            
            return Ok(new RegisterResult { Successful = true });
        }
        [HttpPost("Update")]
        public async Task<IActionResult> Update([FromBody] RegisterModel model)
        {
            IdentityUser user = await _userManager.Users.Where(m => m.UserName.ToLower().Equals(model.Username.ToLower())).FirstOrDefaultAsync(); ;
            await _userManager.RemovePasswordAsync(user);            
            var rs = await _userManager.AddPasswordAsync(user, model.Password);
            //_userManager.
            return Ok(new RegisterResult { Successful = true });
        }

        [HttpGet("ResetPassword/{Id}")]
        public async Task<IActionResult> ResetPassword(string Id)
        {
            IdentityUser user = await _userManager.FindByIdAsync(Id);
            await _userManager.RemovePasswordAsync(user);
            string pass = RandomPassword.CreateRandomPassword();
            var rs = await _userManager.AddPasswordAsync(user, pass);
            try
            {
                EmailData emailData = new EmailData();

                emailData.EmailToId = user.Email;
                emailData.EmailToName = user.UserName;
                string _text = "Trung tâm Ngoại ngữ-Tin học thông báo đã reset lại mật khẩu tài khoản của bạn <br>";
                _text += "Tài khoản của bạn là số căn cước công dân: <b>" + user.UserName + "</b>, mật khẩu của bạn là:<b>" + pass + "</b> <br> ";
                _text += "Thông tin chi tiết xin liên hệ với Trung tâm Ngoại ngữ-Tin học";


                emailData.EmailSubject = "Thông báo khởi tạo lại mật khẩu tài khoản đăng nhập hệ thống đăng ký thi chứng chỉ ứng dụng Công nghệ thông tin cơ bản";

                emailData.EmailBody = _text;
                var rs_Sendmail = _emailService.SendEmail(emailData);
                if (rs_Sendmail)
                {
                    //_Logger.LogInformation("Gửi Email thành công tới:" + emailData.EmailToName + " - " + emailData.EmailToId);
                }
                else
                {
                    //_Logger.LogError("Lỗi không gửi được Email tới:" + emailData.EmailToName + " - " + emailData.EmailToId + " MSg:" + ex.Message);
                }
            }
            catch (Exception ex)
            {
                _Logger.LogError("Lỗi không gửi được Email tới:" + user.UserName + " - " + user.Email + " MSg:" + ex.Message);
                return Ok (new RegisterResult { Successful = false });
            }
            //_userManager.
            return Ok(new RegisterResult { Successful = true });
        }
        /// <summary>
        /// 
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        
        [HttpPut]
        public async Task<IActionResult> Put([FromBody] RegisterModel model)
        {
            IdentityUser user = await _userManager.Users.Where(m => m.UserName.ToLower().Equals(model.Username.ToLower())).FirstOrDefaultAsync(); ;
            await _userManager.RemovePasswordAsync(user);
            //string code = await _userManager.GenerateChangeEmailTokenAsync(user, model.Email);
                //GenerateUserTokenAsync("ChangeEmail", user.Id);
            //await _userManager.ChangeEmailAsync(user, model.Email, code);
            user.Email = model.Email;
            var result = await _userManager.UpdateAsync(user);

            var rs = await _userManager.AddPasswordAsync(user, model.Password);
            try
            {
                EmailData emailData = new EmailData();

                emailData.EmailToId = model.Email;
                emailData.EmailToName = model.Username;
                string _text = "Trung tâm Ngoại ngữ-Tin học thông báo đã reset lại mật khẩu tài khoản của bạn <br>";
                _text += "Tài khoản của bạn là số căn cước công dân: <b>" + model.Username + "</b>, mật khẩu của bạn là:<b>" + model.Password + "</b> <br> ";
                _text += "Thông tin chi tiết xin liên hệ với Trung tâm Ngoại ngữ-Tin học";


                emailData.EmailSubject = "Thông báo khởi tạo lại mật khẩu tài khoản đăng nhập hệ thống đăng ký thi chứng chỉ ứng dụng Công nghệ thông tin cơ bản";

                emailData.EmailBody = _text;
                var rs_Sendmail = _emailService.SendEmail(emailData);                
                if (rs_Sendmail)
                {
                    //_Logger.LogInformation("Gửi Email thành công tới:" + emailData.EmailToName + " - " + emailData.EmailToId);
                }
                else
                {
                    //_Logger.LogError("Lỗi không gửi được Email tới:" + emailData.EmailToName + " - " + emailData.EmailToId + " MSg:" + ex.Message);
                }
            }
            catch (Exception ex)
            {
                _Logger.LogError("Lỗi không gửi được Email tới:" + model.Username + " - " + model.Email + " MSg:" + ex.Message);
            }
            //_userManager.
            return Ok(new RegisterResult { Successful = true });
        }

        [HttpDelete("{id}")]
        public async Task<bool> AccountDelete(string id)
        {
            try
            {
                var usr = await _userManager.FindByIdAsync(id);
                var result = await _userManager.DeleteAsync(usr);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("Delete user error: " + e.Message);
                return false;
            }

        }
        [HttpGet("GetUserByUsername/{username}")]
        public async Task<IdentityUser> GetUserByUsername(string username)
        {
            var result = await _userManager.Users.Where(m => m.UserName.ToLower().Equals(username.ToLower())).FirstOrDefaultAsync();            
            return result;
        }

        [HttpGet("GetUserById/{Id}")]
        public async Task<IdentityUser> GetUserById(string Id)
        {
            var result = await _userManager.Users.Where(m => m.Id.ToLower().Equals(Id.ToLower())).FirstOrDefaultAsync();
            
            return result;
        }
    }
}
