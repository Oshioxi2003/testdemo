using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{
    public interface IEmailService
    {
        bool SendEmail(EmailData emailData);
        bool SendEmailWithAttachment(EmailDataWithAttachment emailData);
        bool SendUserWelcomeEmail(UserData userData);
    }
}
