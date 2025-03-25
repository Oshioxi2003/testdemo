using Flic.Shared;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Data.SqlClient;
using System.Data.Common;
using System.Net;
using Blazored.LocalStorage;


namespace Flic.Server
{
    public class CustomAuthorization :  Attribute, IAuthorizationFilter
    {
        private readonly ILocalStorageService _localStorage;

        //public CustomAuthorization(ILocalStorageService localStorage)
        //{            
        //    _localStorage = localStorage;
        //}
        public void OnAuthorization(AuthorizationFilterContext filterContext)
        {
            if (filterContext != null)
            {
                Microsoft.Extensions.Primitives.StringValues authTokens;
                filterContext.HttpContext.Request.Headers.TryGetValue("Authorization", out authTokens);

                //var storeToken = filterContext.HttpContext.Session.Get("authToken");
                var _token = authTokens.FirstOrDefault();

                if (_token != null)
                {
                    //string authToken = _token;
                    if (_token != null)
                    {
                        if (IsValidToken(_token))
                        {                            

                            return;
                        }
                        else
                        {    
                            filterContext.HttpContext.Response.Headers.Add("AuthStatus", "NotAuthorized");

                            filterContext.HttpContext.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                            filterContext.HttpContext.Response.HttpContext.Features.Get<IHttpResponseFeature>().ReasonPhrase = "Not Authorized";
                            filterContext.Result = new JsonResult("NotAuthorized")
                            {
                                Value = new
                                {
                                    Status = "Error",
                                    Message = "Invalid Token"
                                },
                            };
                        }

                    }

                }
                else
                {
                    filterContext.HttpContext.Response.StatusCode = (int)HttpStatusCode.ExpectationFailed;
                    filterContext.HttpContext.Response.HttpContext.Features.Get<IHttpResponseFeature>().ReasonPhrase = "Please Provide authToken";
                    filterContext.Result = new JsonResult("Please Provide authToken")
                    {
                        Value = new
                        {
                            Status = "Error",
                            Message = "Please Provide authToken"
                        },
                    };
                }
            }
        }
        public bool IsValidToken(string authToken)
        {               
            var KeyString = authToken.Split(' ');

            if (KeyString[0].Trim().ToUpper() == "BEARER" && KeyString[1].Trim() == CommonInfo.BankApiKey)
                return true;
            return false;
        }
    }

}
