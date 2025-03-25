using Blazored.LocalStorage;
using Flic.Shared;
using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;
using System.Net.Http.Json;
using System.Threading.Tasks;

namespace Flic.Client.Services
{
    public static class GoogleAuthService
    {
        private static ILocalStorageService _localStorage;
        private static AuthenticationStateProvider _authStateProvider;
        private static HttpClient _httpClient;
        private static NavigationManager _navigationManager;

        public static void Initialize(
            ILocalStorageService localStorage,
            AuthenticationStateProvider authStateProvider,
            HttpClient httpClient,
            NavigationManager navigationManager)
        {
            _localStorage = localStorage;
            _authStateProvider = authStateProvider;
            _httpClient = httpClient;
            _navigationManager = navigationManager;
        }

        [JSInvokable]
        public static async Task ProcessGoogleToken(string token)
        {
            try
            {
                // Call your server API
                var response = await _httpClient.PostAsJsonAsync("api/GoogleAuth/login", new { IdToken = token });

                if (response.IsSuccessStatusCode)
                {
                    var result = await response.Content.ReadFromJsonAsync<LoginResult>();

                    if (result.Successful)
                    {
                        await _localStorage.SetItemAsync("authToken", result.Token);
                        ((ApiAuthenticationStateProvider)_authStateProvider).MarkUserAsAuthenticated();
                        _httpClient.DefaultRequestHeaders.Authorization =
                            new System.Net.Http.Headers.AuthenticationHeaderValue("bearer", result.Token);

                        _navigationManager.NavigateTo("/flic");
                    }
                }
            }
            catch (Exception)
            {
                // Handle errors
            }
        }
    }
}
