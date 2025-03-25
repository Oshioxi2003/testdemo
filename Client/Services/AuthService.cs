using Blazored.LocalStorage;
using Flic.Shared;
using Microsoft.AspNetCore.Components.Authorization;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Components;

namespace Flic.Client.Services
{
    public class AuthService : IAuthService
    {
        private readonly HttpClient _httpClient;
        private readonly AuthenticationStateProvider _authenticationStateProvider;
        private readonly ILocalStorageService _localStorage;
        private readonly NavigationManager _navigationManager;

        public AuthService(HttpClient httpClient,
                           AuthenticationStateProvider authenticationStateProvider,
                           ILocalStorageService localStorage,
                           NavigationManager navigationManager)
        {
            _httpClient = httpClient;
            _authenticationStateProvider = authenticationStateProvider;
            _localStorage = localStorage;
            _navigationManager = navigationManager;
        }
        public void GoogleLogin()
        {
            _navigationManager.NavigateTo("api/GoogleAuth/login", true);
        }

        public async Task<HttpResponseMessage> Register(RegisterModel registerModel)
        {
            var result = await _httpClient.PostAsJsonAsync<RegisterModel>("api/accounts", registerModel);

            return result;
        }

        public async Task<HttpResponseMessage> Update(RegisterModel registerModel)
        {
            //var result = await _httpClient.PostAsJsonAsync<RegisterModel>("api/accounts/Update/", registerModel);
            var result = await _httpClient.PutAsJsonAsync<RegisterModel>("api/accounts/", registerModel);
            return result;
        }

        public async Task<LoginResult> Login(LoginModel loginModel)
        {
            var loginAsJson = JsonSerializer.Serialize(loginModel);
            var response = await _httpClient.PostAsync("api/Login", new StringContent(loginAsJson, Encoding.UTF8, "application/json"));
            try
            {
                var loginResult = JsonSerializer.Deserialize<LoginResult>(await response.Content.ReadAsStringAsync(), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                if (!response.IsSuccessStatusCode)
                {
                    return loginResult;
                }

                await _localStorage.SetItemAsync("authToken", loginResult.Token);
                ((ApiAuthenticationStateProvider)_authenticationStateProvider).MarkUserAsAuthenticated();
                
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("bearer", loginResult.Token);

                return loginResult;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }


        public async Task Logout()
        {
            await _localStorage.RemoveItemAsync("authToken");
            ((ApiAuthenticationStateProvider)_authenticationStateProvider).MarkUserAsLoggedOut();
            _httpClient.DefaultRequestHeaders.Authorization = null;
        }

        public async Task<RegisterModel> GetUserByUsername(string username)
        {
            var result = await _httpClient.GetFromJsonAsync<RegisterModel>("api/accounts/GetUserByUsername/" + username);

            return result;
        }
        public async Task<RegisterModel> GetUserById(string Id)
        {
            var result = await _httpClient.GetFromJsonAsync<RegisterModel>("api/accounts/GetUserById/" + Id);

            return result;
        }
    }
}
