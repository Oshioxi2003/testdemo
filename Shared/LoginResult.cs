using System.Security.Claims;
using System.Text.Json.Serialization;

namespace Flic.Shared
{
    public class LoginResult
    {
        [JsonConstructor]
        public LoginResult()
        {
            Successful = false;
            //Claims = new List<Claim>();
            Token = "";
            Error = "";
        }
        public bool Successful { get; set; }
        public string Error { get; set; }
        public string Token { get; set; }
        //public List<Claim> Claims {get; set;}
    }
}
