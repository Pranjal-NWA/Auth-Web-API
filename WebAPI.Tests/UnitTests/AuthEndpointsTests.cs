using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using WebAPI.Data;
using WebAPI.DTOs;
using Xunit;

namespace WebAPI.Tests;

/// <summary>
/// End-to-end HTTP tests through the real ASP.NET Core pipeline -
/// middleware, exception handler, rate limiting, and all - not just the
/// service layer in isolation. Each test gets a fresh in-memory database
/// via a custom WebApplicationFactory so tests never interfere with each
/// other or need a real Postgres instance.
///
/// Requires a `public partial class Program { }` marker at the bottom of
/// Program.cs for WebApplicationFactory<Program> to work with top-level
/// statements - add that one line if it's not already there.
/// </summary>
public class AuthEndpointsTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;

    public AuthEndpointsTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    private HttpClient NewClient() => _factory.CreateClient(
        new WebApplicationFactoryClientOptions
        {
            HandleCookies = true,
        });

    [Fact]
    public async Task Signup_ThenLogin_SetsHttpOnlyCookies_NoTokenInBody()
    {
        var client = NewClient();
        var email = $"{Guid.NewGuid()}@example.com";

        var signupResponse = await client.PostAsJsonAsync(
            "/api/v1/auth/signup",
            new
            {
                email,
                password = "Testpass1!",
                fullName = "Integration Test",
            });

        Assert.Equal(HttpStatusCode.Created, signupResponse.StatusCode);

        var signupBody = await signupResponse.Content.ReadAsStringAsync();
        Assert.DoesNotContain(
            "token",
            signupBody,
            StringComparison.OrdinalIgnoreCase);

        var loginResponse = await client.PostAsJsonAsync(
            "/api/v1/auth/login",
            new
            {
                email,
                password = "Testpass1!"
            });

        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);

        var loginBody = await loginResponse.Content.ReadAsStringAsync();
        Assert.DoesNotContain(
            "token",
            loginBody,
            StringComparison.OrdinalIgnoreCase);

        Assert.True(
            loginResponse.Headers.TryGetValues("Set-Cookie", out var cookies));

        var cookieList = cookies!.ToList();

        foreach (var cookie in cookieList)
        {
            Console.WriteLine($"COOKIE: {cookie}");
        }

        Assert.Contains(cookieList, c =>
            c.StartsWith("access_token=") &&
            c.Contains("HttpOnly", StringComparison.OrdinalIgnoreCase));

        Assert.Contains(cookieList, c =>
            c.StartsWith("refresh_token=") &&
            c.Contains("HttpOnly", StringComparison.OrdinalIgnoreCase));

        Assert.Contains(
            cookieList,
            c => c.Contains(
                "SameSite=Lax",
                StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Me_WithoutCookie_Returns401()
    {
        var client = NewClient();

        var response = await client.GetAsync("/api/v1/users/me");

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            response.StatusCode);
    }

    [Fact]
    public async Task Me_AfterLogin_ReturnsProfile()
    {
        var client = NewClient();
        var email = $"{Guid.NewGuid()}@example.com";

        var signupResponse = await client.PostAsJsonAsync(
            "/api/v1/auth/signup",
            new
            {
                email,
                password = "Testpass1!"
            });

        Assert.Equal(
            HttpStatusCode.Created,
            signupResponse.StatusCode);

        var loginResponse = await client.PostAsJsonAsync(
            "/api/v1/auth/login",
            new
            {
                email,
                password = "Testpass1!"
            });

        Assert.Equal(
            HttpStatusCode.OK,
            loginResponse.StatusCode);

        var meResponse = await client.GetAsync(
            "/api/v1/users/me");

        Assert.Equal(
            HttpStatusCode.OK,
            meResponse.StatusCode);

        var body =
            await meResponse.Content.ReadFromJsonAsync<UserResponse>();

        Assert.Equal(email, body!.Email);
    }

    [Fact]
    public async Task Signup_DuplicateEmail_Returns409()
    {
        var client = NewClient();
        var email = $"{Guid.NewGuid()}@example.com";

        var payload = new
        {
            email,
            password = "Testpass1!"
        };

        await client.PostAsJsonAsync(
            "/api/v1/auth/signup",
            payload);

        var second = await client.PostAsJsonAsync(
            "/api/v1/auth/signup",
            payload);

        Assert.Equal(
            HttpStatusCode.Conflict,
            second.StatusCode);
    }

    [Fact]
    public async Task Signup_WeakPassword_Returns400WithProblemDetails()
    {
        var client = NewClient();

        var response = await client.PostAsJsonAsync(
            "/api/v1/auth/signup",
            new
            {
                email = $"{Guid.NewGuid()}@example.com",
                password = "weak",
            });

        Assert.Equal(
            HttpStatusCode.BadRequest,
            response.StatusCode);

        Assert.Equal(
            "application/json",
            response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Refresh_RotatesTokenAndOldCookieNoLongerWorks()
    {
        var client = NewClient();
        var email = $"{Guid.NewGuid()}@example.com";

        await client.PostAsJsonAsync(
            "/api/v1/auth/signup",
            new
            {
                email,
                password = "Testpass1!"
            });

        var loginResponse = await client.PostAsJsonAsync(
            "/api/v1/auth/login",
            new
            {
                email,
                password = "Testpass1!"
            });

        Assert.Equal(
            HttpStatusCode.OK,
            loginResponse.StatusCode);

        var originalCookies =
            loginResponse.Headers
                .GetValues("Set-Cookie")
                .ToList();

        var refreshResponse = await client.PostAsync(
            "/api/v1/auth/refresh",
            null);

        Assert.Equal(
            HttpStatusCode.OK,
            refreshResponse.StatusCode);

        var newCookies =
            refreshResponse.Headers
                .GetValues("Set-Cookie")
                .ToList();

        Assert.NotEqual(
            originalCookies.First(
                c => c.StartsWith("refresh_token=")),
            newCookies.First(
                c => c.StartsWith("refresh_token=")));
    }

    [Fact]
    public async Task Logout_ThenMe_Returns401()
    {
        var client = NewClient();
        var email = $"{Guid.NewGuid()}@example.com";

        await client.PostAsJsonAsync(
            "/api/v1/auth/signup",
            new
            {
                email,
                password = "Testpass1!"
            });

        await client.PostAsJsonAsync(
            "/api/v1/auth/login",
            new
            {
                email,
                password = "Testpass1!"
            });

        var logoutResponse = await client.PostAsync(
            "/api/v1/auth/logout",
            null);

        Assert.Equal(
            HttpStatusCode.NoContent,
            logoutResponse.StatusCode);

        var meResponse = await client.GetAsync(
            "/api/v1/users/me");

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            meResponse.StatusCode);
    }

    [Fact]
    public async Task Logout_CalledTwice_StaysIdempotent()
    {
        var client = NewClient();
        var email = $"{Guid.NewGuid()}@example.com";

        await client.PostAsJsonAsync(
            "/api/v1/auth/signup",
            new
            {
                email,
                password = "Testpass1!"
            });

        await client.PostAsJsonAsync(
            "/api/v1/auth/login",
            new
            {
                email,
                password = "Testpass1!"
            });

        var first = await client.PostAsync(
            "/api/v1/auth/logout",
            null);

        var second = await client.PostAsync(
            "/api/v1/auth/logout",
            null);

        Assert.Equal(
            HttpStatusCode.NoContent,
            first.StatusCode);

        Assert.Equal(
            HttpStatusCode.NoContent,
            second.StatusCode);
    }
    [Fact]
    public async Task Refresh_WithoutRefreshCookie_Returns401()
    {
        var client = NewClient();

        var response = await client.PostAsync(
            "/api/v1/auth/refresh",
            null);

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            response.StatusCode);
    }

    [Fact]
    public async Task Healthz_ReturnsOkAndChecksDatabase()
    {
        var client = NewClient();

        var response = await client.GetAsync("/healthz");

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);
    }
}

/// <summary>
/// Swaps the real Postgres registration for EF Core InMemory, per test
/// class instance, so integration tests need no real database running.
/// </summary>
public class TestWebApplicationFactory : WebApplicationFactory<Program>
{
    private const string TestJwtSecret =
        "test-secret-key-at-least-32-characters-long-for-hmac";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureServices(services =>
        {
            var descriptor = services.SingleOrDefault(
                d => d.ServiceType ==
                     typeof(DbContextOptions<AppDbContext>));

            if (descriptor is not null)
            {
                services.Remove(descriptor);
            }

            services.AddDbContext<AppDbContext>(options =>
                options.UseInMemoryDatabase("integration-tests"));
        });

        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    ["Jwt:SecretKey"] = TestJwtSecret,
                    ["Jwt:AccessTokenExpirySeconds"] = "900",
                    ["Jwt:RefreshTokenExpiryDays"] = "30",
                    ["CookieSecure"] = "false",
                });
        });

        // Test-only override of JWT validation.
        // Production Program.cs remains unchanged.
        builder.ConfigureServices(services =>
        {
            services.PostConfigure<JwtBearerOptions>(
                JwtBearerDefaults.AuthenticationScheme,
                options =>
                {
                    options.TokenValidationParameters.IssuerSigningKey =
                        new SymmetricSecurityKey(
                            Encoding.UTF8.GetBytes(TestJwtSecret));
                });
        });
    }
}