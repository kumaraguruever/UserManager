using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using System.Threading.Tasks;
using Twilio;
using Twilio.Rest.Api.V2010.Account;
using Twilio.Types;

namespace CoreUserManagementDemo.Services
{
    public class AuthMessageSender : IEmailSender, ISmsSender
    {
        public AuthMessageSender(IConfiguration configuration)
        {
            Configuration = configuration;
        }


        public Task SendEmailAsync(string email, string subject, string message)
        {
            // Plug in your email service here to send an email.
            return Task.FromResult(0);
        }
        public Task SendSmsAsync(string number, string message)
        {
            // Plug in your SMS service here to send a text message.
            // Your Account SID from twilio.com/console
            var accountSid = Configuration["2FA:Twilio:AccountSID"];
            // Your Auth Token from twilio.com/console
            var authToken = Configuration["2FA:Twilio:AuthToken"];

            TwilioClient.Init(accountSid, authToken);

            return MessageResource.CreateAsync(
              to: new PhoneNumber(number),
              from: new PhoneNumber(Configuration["2FA:Twilio:SMSAccountFrom"]),
              body: message);
        }


        public IConfiguration Configuration { get; }
    }
}
