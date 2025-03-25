using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Server.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Radzen;
using Flic.Shared;
using Flic;
using Flic.Server.Configuration;
using DinkToPdf.Contracts;
using DinkToPdf;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Http.Json;

var builder = WebApplication.CreateBuilder(args);
ConfigurationManager configuration = builder.Configuration;
// Add services to the container.
builder.Services.AddDbContext<ApplicationDbContext>(options => 
{ 
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
    options.UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking);
}) ;
builder.Services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>();



builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
// Adding Jwt Bearer
.AddJwtBearer(options =>
{
    options.SaveToken = true;
    options.RequireHttpsMetadata = false;
    options.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidAudience = configuration["JwtAudience"],
        ValidIssuer = configuration["JwtIssuer"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JwtSecurityKey"]))
    };
})
// Add Google authentication (chained to the same AddAuthentication call)
.AddGoogle(options =>
{
    options.ClientId = configuration["Authentication:Google:ClientId"];
    options.ClientSecret = configuration["Authentication:Google:ClientSecret"];
    options.CallbackPath = "/signin-google";
});

builder.Services.Configure<JsonOptions>(options =>
{
    options.SerializerOptions.PropertyNameCaseInsensitive = true;
});

//Add add 20/12/2022
CommonInfo.ConnectionString =  builder.Configuration.GetConnectionString("DefaultConnection");
CommonInfo.BankApiKey = configuration["BankApiKey"];

CommonInfo.PrivateKeyPath = configuration["PrivateKeyPath"];
CommonInfo.PublicKeyPath = configuration["PublicKeyPath"];
CommonInfo.PasswordPath = configuration["PasswordPath"];
CommonInfo.BankPublicKeyPath = configuration["BankPublicKeyPath"];
CommonInfo.PROVIDERID = configuration["PROVIDERID"];
CommonInfo.VTBPublicKeyPath = configuration["VTBPublicKeyPath"];

CommonInfo.config = configuration;

//Add add 20/12/2022

builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();


builder.Services.AddTransient<IStudent, StudentManager>();
builder.Services.AddTransient<IKhoa, KhoaService>();
builder.Services.AddTransient<ILoaiKhoanthu, LoaiKhoanthuService>();
builder.Services.AddTransient<IKhoanthu, KhoanthuService>();
builder.Services.AddTransient<IThutien, ThutienService>();
builder.Services.AddTransient<IKhoahoc, KhoahocService>();
builder.Services.AddTransient<INganh, NganhService>();
builder.Services.AddTransient<ILop, LopService>();
builder.Services.AddTransient<IKyThanhtoan, KyThanhtoanService>();
builder.Services.AddTransient<IStudentStatus, StudentStatusManager>();
builder.Services.AddTransient<IPhongKTX, PhongKTXService>();
builder.Services.AddTransient<ISinhvienPhong, SinhvienPhongService>();

builder.Services.AddTransient< IDangkyTH03, DangkyTH03Service> ();
builder.Services.AddTransient<IDMTinh, DMTinhService>();
builder.Services.AddTransient<IDMDantoc, DMDantocService>();

builder.Services.AddTransient<IDotthi, DotthiService>();
builder.Services.AddTransient<IDiemthi, DiemthiService>();
builder.Services.AddTransient<ITin03Trangthai, Tin03TrangthaiService>();

builder.Services.AddTransient<ISection, SectionService>();
builder.Services.AddTransient<IArticle, ArticleService>();

builder.Services.AddTransient<ILoaiLophoc, LoaiLophocService>();
builder.Services.AddTransient<ILophoc, LophocService>();
builder.Services.AddTransient<IDKHoc, DKHocService>();
builder.Services.AddScoped<IVnPayService, VnPayService>();

builder.Services.AddTransient<IEmailService, EmailService>();

builder.Services.AddScoped<NorthwindService>();

builder.Services.Configure<EmailSettings>(builder.Configuration.GetSection("EmailConfiguration"));
//PDF
builder.Services.AddSingleton(typeof(IConverter), new SynchronizedConverter(new PdfTools()));

var serviceProvider = builder.Services.BuildServiceProvider();
var logger = serviceProvider.GetService<ILogger<Program>>();

//ServiceProvider serviceProvider = new ServiceCollection()
//    .AddLogging((loggingBuilder) => loggingBuilder
//        .SetMinimumLevel(LogLevel.Trace)
//        .AddConsole()
//        )
//    .BuildServiceProvider();

//var logger = serviceProvider.GetService<ILoggerFactory>().CreateLogger<Program>();

builder.Services.AddSingleton(typeof(ILogger), logger);

builder.Logging.ClearProviders();
builder.Logging.AddConsole();
//
builder.Services.Configure<IdentityOptions>(options =>
{
    // Default Password settings.
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequiredLength = 6;
    options.Password.RequiredUniqueChars = 0;
});
//

builder.Services.AddScoped<Radzen.DialogService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseWebAssemblyDebugging();
}
else
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseBlazorFrameworkFiles();
app.UseStaticFiles();

app.UseStaticFiles(new StaticFileOptions()
{
    FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), @"StaticFiles")),
    RequestPath = new PathString("/StaticFiles")
});

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();
app.MapFallbackToFile("index.html");


app.Run();
