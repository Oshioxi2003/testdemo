using Flic.Shared;

namespace Flic.Client.Services
{
    public interface IAuthService
    {
        Task<LoginResult> Login(LoginModel loginModel);
        Task Logout();
        Task<HttpResponseMessage> Register(RegisterModel registerModel);
        Task<HttpResponseMessage> Update(RegisterModel registerModel);
        //Task<RegisterModel> GetUser(string username);
        Task<RegisterModel> GetUserByUsername(string username);
        Task<RegisterModel> GetUserById(string Id);
        void GoogleLogin();
    }
}
