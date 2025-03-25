using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EmailController : ControllerBase
    {
        IEmailService _emailService = null;
        public EmailController(IEmailService emailService)
        {
            _emailService = emailService;
        }
        [Route("SendEmail")]
        [HttpPost]
        public bool SendEmail(EmailData emailData)
        {
            return _emailService.SendEmail(emailData);
        }

        [Route("SendEmailWithAttachment")]
        [HttpPost]
        public bool SendEmailWithAttachment([FromForm] EmailDataWithAttachment emailData)
        {
            return _emailService.SendEmailWithAttachment(emailData);
        }

        [Route("SendUserWelcomeEmail")]
        [HttpPost]
        public bool SendUserWelcomeEmail([FromForm] UserData userData)
        {
            return _emailService.SendUserWelcomeEmail(userData);
        }
    }
}
