global using Microsoft.AspNetCore.Components.Authorization;
using Blazored.LocalStorage;
using Flic;
using Flic.Client;
using Flic.Client.Services;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using MudBlazor.Services;
using Radzen;



var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });
//New code here
builder.Services.AddBlazoredLocalStorage();

builder.Services.AddAuthorizationCore();
builder.Services.AddScoped<AuthenticationStateProvider, ApiAuthenticationStateProvider>();
builder.Services.AddScoped<IAuthService, AuthService>(provider =>
    new AuthService(
        provider.GetRequiredService<HttpClient>(),
        provider.GetRequiredService<AuthenticationStateProvider>(),
        provider.GetRequiredService<ILocalStorageService>(),
        provider.GetRequiredService<NavigationManager>()
    )
);

builder.Services.AddMudServices();


builder.Services.AddScoped<DialogService>();
builder.Services.AddScoped<NotificationService>();
builder.Services.AddScoped<TooltipService>();
builder.Services.AddScoped<ContextMenuService>();

builder.Services.AddScoped<NorthwindService>();
await builder.Build().RunAsync();
