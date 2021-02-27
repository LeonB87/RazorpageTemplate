using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Graph;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using WebappAuthN.Data;
using WebappAuthN.Graph;
using WebappAuthN.Helpers;

namespace WebappAuthN
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            string ConnectionString = Configuration["SqlConnectionString"];
            string AzureAdInstance = Configuration["AzureAdInstance"];
            string AzureAdDomain = Configuration["AzureAdDomain"];
            string AzureAdTenantId = Configuration["AzureAdTenantId"];
            string AzureAdCallbackPath = Configuration["AzureAdCallbackPath"];
            string AzureAdClientId = Configuration["AzureAdClientId"];
            string AzureAdClientSecret = Configuration["AzureAdClientSecret"];


            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    Configuration.GetConnectionString("DefaultConnection")));
            services.AddDatabaseDeveloperPageExceptionFilter();

            services.AddIdentity<IdentityUser, IdentityRole>()
                // services.AddDefaultIdentity<IdentityUser>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();
            services.AddRazorPages();

            services.AddMvc().SetCompatibilityVersion(Microsoft.AspNetCore.Mvc.CompatibilityVersion.Version_3_0)
       .AddRazorPagesOptions(options =>
       {
           options.Conventions.AuthorizeAreaFolder("Identity", "/Account/Manage");
           options.Conventions.AuthorizeAreaPage("Identity", "/Account/Logout");
       });

            services.ConfigureApplicationCookie(options =>
            {
                options.LoginPath = $"/Identity/Account/Login";
                options.LogoutPath = $"/Identity/Account/Logout";
                options.AccessDeniedPath = $"/Identity/Account/AccessDenied";
            });

            // using Microsoft.AspNetCore.Identity.UI.Services;
            services.AddSingleton<IEmailSender, EmailSender>();

            services.AddAuthentication()
            .AddMicrosoftAccount(microsoftOptions =>
            {
                microsoftOptions.ClientId = Configuration["clientid"];
                microsoftOptions.ClientSecret = Configuration["clientsecret"];
            });

            //.AddMicrosoftIdentityWebApp(options =>
            //{
            //    Configuration.Bind("AzureAd", options);
            //    options.SignInScheme = "OpenIdConnect";
            //    options.Instance = AzureAdInstance;
            //    options.Domain = AzureAdDomain;
            //    options.ClientId = AzureAdClientId;
            //    options.ClientSecret = AzureAdClientSecret;
            //    options.TenantId = AzureAdTenantId;
            //    options.CallbackPath = AzureAdCallbackPath;
            //    options.Events ??= new OpenIdConnectEvents();
            //    options.Prompt = "select_account";


            //    options.Events.OnTokenValidated = async context =>
            //    {
            //        var tokenAcquisition = context.HttpContext.RequestServices
            //            .GetRequiredService<ITokenAcquisition>();
            //        var graphClient = new GraphServiceClient(
            //            new DelegateAuthenticationProvider(async (request) =>
            //            {
            //                var token = await tokenAcquisition
            //                    .GetAccessTokenForUserAsync(GraphConstants.Scopes, user: context.Principal);
            //                request.Headers.Authorization =
            //                    new AuthenticationHeaderValue("Bearer", token);
            //            })
            //        );

            //        // Get user information from Graph
            //        var user = await graphClient.Me.Request()
            //        .Select(u => new
            //        {
            //            u.DisplayName,
            //            u.Mail,
            //            u.UserPrincipalName,
            //            u.MailboxSettings
            //        })
            //        .GetAsync();

            //        context.Principal.AddUserGraphInfo(user);

            //        // Get the user's photo
            //        // If the user doesn't have a photo, this throws
            //        try
            //        {
            //            var photo = await graphClient.Me
            //                .Photos["48x48"]
            //                .Content
            //                .Request()
            //                .GetAsync();

            //            context.Principal.AddUserGraphPhoto(photo);
            //        }
            //        catch (ServiceException ex)
            //        {
            //            if (ex.IsMatch("ErrorItemNotFound") ||
            //                ex.IsMatch("ConsumerPhotoIsNotSupported"))
            //            {
            //                context.Principal.AddUserGraphPhoto(null);
            //            }
            //            else
            //            {
            //                throw;
            //            }
            //        }
            //    };

            //    options.Events.OnAuthenticationFailed = context =>
            //    {
            //        var error = WebUtility.UrlEncode(context.Exception.Message);
            //        context.Response
            //            .Redirect($"/Home/ErrorWithMessage?message=Authentication+error&debug={error}");
            //        context.HandleResponse();

            //        return Task.FromResult(0);
            //    };

            //    options.Events.OnRemoteFailure = context =>
            //    {
            //        if (context.Failure is OpenIdConnectProtocolException)
            //        {
            //            var error = WebUtility.UrlEncode(context.Failure.Message);
            //            context.Response
            //                .Redirect($"/Home/ErrorWithMessage?message=Sign+in+error&debug={error}");
            //            context.HandleResponse();
            //        }

            //        return Task.FromResult(0);
            //    };
            //},"AzureAd").EnableTokenAcquisitionToCallDownstreamApi(options =>
            //{
            //    Configuration.Bind("AzureAd", options);
            //}, GraphConstants.Scopes)

            //// Add a GraphServiceClient via dependency injection
            //.AddMicrosoftGraph(options =>
            //{
            //    options.Scopes = string.Join(' ', GraphConstants.Scopes);
            //})

            //// Use in-memory token cache
            //// See https://github.com/AzureAD/microsoft-identity-web/wiki/token-cache-serialization
            //.AddInMemoryTokenCaches()
            //; 

            services.Configure<IdentityOptions>(options =>
            {
                // Password settings.
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequireUppercase = true;
                options.Password.RequiredLength = 6;
                options.Password.RequiredUniqueChars = 1;

                // Lockout settings.
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;

                // User settings.
                options.User.AllowedUserNameCharacters =
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
                options.User.RequireUniqueEmail = true;

                // Sign-in settings.
                options.SignIn.RequireConfirmedEmail = true;
                options.SignIn.RequireConfirmedAccount = true;
            });

            services.ConfigureApplicationCookie(options =>
            {
                // Cookie settings
                options.Cookie.HttpOnly = true;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(5);

                options.LoginPath = "/Identity/Account/Login";
                options.AccessDeniedPath = "/Identity/Account/AccessDenied";
                options.SlidingExpiration = true;
            });

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseMigrationsEndPoint();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
            });
        }
    }
}
