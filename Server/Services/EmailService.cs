using Flic.Server.Configuration;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.Extensions.Options;
using MimeKit;
using MailKit.Net.Smtp;

namespace Flic.Server.Services
{
    public class EmailService : IEmailService
    {
        EmailSettings _emailSettings = null;
        private ILogger _Logger;
        public EmailService(IOptions<EmailSettings> options, ILogger logger)
        {
            _emailSettings = options.Value;
            _Logger = logger;
        }

        public bool SendEmail(EmailData emailData)
        {
            try
            {
                MimeMessage emailMessage = new MimeMessage();

                MailboxAddress emailFrom = new MailboxAddress(_emailSettings.Name, _emailSettings.EmailId);
                emailMessage.From.Add(emailFrom);

                MailboxAddress emailTo = new MailboxAddress(emailData.EmailToName, emailData.EmailToId);
                emailMessage.To.Add(emailTo);

                emailMessage.Subject = emailData.EmailSubject;

                BodyBuilder emailBodyBuilder = new BodyBuilder();
                //emailBodyBuilder.TextBody = emailData.EmailBody;
                //emailMessage.Body = emailBodyBuilder.ToMessageBody();
                emailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Html) { Text = emailData.EmailBody };

                MailKit.Net.Smtp.SmtpClient emailClient = new MailKit.Net.Smtp.SmtpClient();
                emailClient.Connect(_emailSettings.Host, _emailSettings.Port, _emailSettings.UseSSL);
                emailClient.Authenticate(_emailSettings.EmailId, _emailSettings.Password);
                emailClient.Send(emailMessage);
                emailClient.Disconnect(true);
                emailClient.Dispose();
                _Logger.LogInformation("Gửi Email thành công tới:" + emailData.EmailToName + " - " + emailData.EmailToId);
                return true;
            }
            catch (Exception ex)
            {
                //Log Exception Details
                Console.WriteLine(ex.Message);
                _Logger.LogError("Lỗi không gửi được Email tới:" + emailData.EmailToName + " - " + emailData.EmailToId +" MSg:" + ex.Message);
                return false;
            }
        }


        public bool SendEmailWithAttachment(EmailDataWithAttachment emailData)
        {
            try
            {
                MimeMessage emailMessage = new MimeMessage();

                MailboxAddress emailFrom = new MailboxAddress(_emailSettings.Name, _emailSettings.EmailId);
                emailMessage.From.Add(emailFrom);

                MailboxAddress emailTo = new MailboxAddress(emailData.EmailToName, emailData.EmailToId);
                emailMessage.To.Add(emailTo);

                emailMessage.Subject = emailData.EmailSubject;

                BodyBuilder emailBodyBuilder = new BodyBuilder();

                if (emailData.EmailAttachments != null)
                {
                    byte[] attachmentFileByteArray;
                    foreach (IFormFile attachmentFile in emailData.EmailAttachments)
                    {
                        if (attachmentFile.Length > 0)
                        {
                            using (MemoryStream memoryStream = new MemoryStream())
                            {
                                attachmentFile.CopyTo(memoryStream);
                                attachmentFileByteArray = memoryStream.ToArray();
                            }
                            emailBodyBuilder.Attachments.Add(attachmentFile.FileName, attachmentFileByteArray, ContentType.Parse(attachmentFile.ContentType));
                        }
                    }
                }

                emailBodyBuilder.TextBody = emailData.EmailBody;
                emailMessage.Body = emailBodyBuilder.ToMessageBody();

                SmtpClient emailClient = new SmtpClient();
                emailClient.Connect(_emailSettings.Host, _emailSettings.Port, _emailSettings.UseSSL);
                emailClient.Authenticate(_emailSettings.EmailId, _emailSettings.Password);
                emailClient.Send(emailMessage);
                emailClient.Disconnect(true);
                emailClient.Dispose();

                return true;
            }
            catch (Exception ex)
            {
                //Log Exception Details
                return false;
            }
        }


        public bool SendUserWelcomeEmail(UserData userData)
        {
            try
            {
                MimeMessage emailMessage = new MimeMessage();

                MailboxAddress emailFrom = new MailboxAddress(_emailSettings.Name, _emailSettings.EmailId);
                emailMessage.From.Add(emailFrom);

                MailboxAddress emailTo = new MailboxAddress(userData.UserName, userData.UserEmailId);
                emailMessage.To.Add(emailTo);

                emailMessage.Subject = "Welcome To HNUE";

                string FilePath = Directory.GetCurrentDirectory() + "\\Templates\\WelcomeEmail.html";
                string EmailTemplateText = File.ReadAllText(FilePath);

                EmailTemplateText = string.Format(EmailTemplateText, userData.UserName, DateTime.Now.Date.ToShortDateString());

                BodyBuilder emailBodyBuilder = new BodyBuilder();
                emailBodyBuilder.HtmlBody = EmailTemplateText;
                emailMessage.Body = emailBodyBuilder.ToMessageBody();

                SmtpClient emailClient = new SmtpClient();
                emailClient.Connect(_emailSettings.Host, _emailSettings.Port, _emailSettings.UseSSL);
                emailClient.Authenticate(_emailSettings.EmailId, _emailSettings.Password);
                emailClient.Send(emailMessage);
                emailClient.Disconnect(true);
                emailClient.Dispose();

                return true;
            }
            catch (Exception ex)
            {
                //Log Exception Details
                return false;
            }
        }

    }
}
