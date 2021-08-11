using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.OAuth;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System;

namespace AspNetCoreGitHubAuth
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
            services.AddMvc(options => options.EnableEndpointRouting = false);

            //support older browser. only if client on https
            services.Configure<CookiePolicyOptions>(options =>
            {
                options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
                options.OnAppendCookie = cookieContext =>
                    CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
                options.OnDeleteCookie = cookieContext =>
                    CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
            });


            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = "Keycloak";
            })
                .AddCookie(options => {
                    //set cookie to expire in 1 minute
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(1);
                })
                .AddOAuth("Keycloak", options =>
                    {

                        //this application as  Keycloak's client apps
                        options.ClientId = Configuration["Keycloak:ClientId"];
                        options.ClientSecret = Configuration["Keycloak:ClientSecret"];
                        options.CallbackPath = new PathString("/signin-keycloak");
                        options.Scope.Add(Configuration["Keycloak:ClientScope"]);

                        //your keycloak endpoint
                        options.AuthorizationEndpoint = Configuration["Keycloak:AuthorizationEndpoint"];
                        options.TokenEndpoint = Configuration["Keycloak:TokenEndpoint"];
                        options.UserInformationEndpoint = Configuration["Keycloak:UserInformationEndpoint"];

                        //Claim after hit user info endpoint
                        options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
                        options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
                        options.ClaimActions.MapJsonKey("urn:keycloak:email", "email");
                        options.ClaimActions.MapJsonKey("urn:keycloak:preferred_username", "preferred_username");
                        options.ClaimActions.MapJsonKey("urn:keycloak:family_name", "family_name");
                        options.ClaimActions.MapJsonKey("urn:keycloak:given_name", "given_name");

                        options.SaveTokens = true;

                        //accept  self sign cert
                        options.BackchannelHttpHandler = new HttpClientHandler()
                        {
                            ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => {return true;}
                        };

                        //on oauth event
                        options.Events = new OAuthEvents
                        {
                            OnCreatingTicket = async context =>
                            {
                                var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);

                                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);

                                var response = await context.Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.HttpContext.RequestAborted);
                                response.EnsureSuccessStatusCode();

                                var user = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

                                context.RunClaimActions(user.RootElement);
                            }
                        };
                    }
                );
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            
            app.UseStaticFiles();

            app.UseAuthentication();
            app.UseCookiePolicy();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller}/{action=Index}/{id?}");
            });
        }

        private void CheckSameSite(HttpContext httpContext, CookieOptions options)
        {
            if (options.SameSite == SameSiteMode.None)
            {
                var userAgent = httpContext.Request.Headers["User-Agent"].ToString();
                options.SameSite = SameSiteMode.Unspecified;
            }
        }

    }
}
