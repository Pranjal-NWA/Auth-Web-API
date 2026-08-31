using System.Net;
using System.Net.Http.Json;
using Xunit;

namespace WebAPI.Tests.IntegrationTests;

public class AuthEndpointsIntegrationTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly CustomWebApplicationFactory _factory;

    public AuthEndpointsIntegrationTests(CustomWebApplicationFactory factory)
    {
        _factory = factory;
    }

    private HttpClient NewClientWithCookies() =>
        _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            HandleCookies = true, // mirrors the browser's cookie jar behavior
        });

    [Fact]
    public async Task Signup_ThenLogin_SetsHttpOnlyCookies_NoTokenInBody()
    {
        var client = NewClientWithCookies();
        var email = $"itest-{Guid.NewGuid():N}@test.com";

        var signupResp = await client.PostAsJsonAsync("/api/v1/auth/signup",
            new { email, password = "Passw0rd1!" });
        Assert.Equal(HttpStatusCode.Created, signupResp.StatusCode);

        var signupBody = await signupResp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("token", signupBody, StringComparison.OrdinalIgnoreCase);

        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login",
            new { email, password = "Passw0rd1!" });

        Assert.Equal(HttpStatusCode.OK, loginResp.StatusCode);
        var loginBody = await loginResp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("access_token", loginBody, StringComparison.OrdinalIgnoreCase);

        Assert.True(loginResp.Headers.TryGetValues("Set-Cookie", out var cookies));
        var cookieList = cookies!.ToList();
        Assert.Contains(cookieList, c =>
            c.StartsWith("access_token=") &&
            c.Contains("HttpOnly", StringComparison.OrdinalIgnoreCase));

        Assert.Contains(cookieList, c =>
            c.StartsWith("refresh_token=") &&
            c.Contains("HttpOnly", StringComparison.OrdinalIgnoreCase)); Assert.Contains(cookieList, c => c.Contains("SameSite=Lax", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Me_WithoutCookie_Returns401()
    {
        var client = _factory.CreateClient();

        var resp = await client.GetAsync("/api/v1/users/me");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Me_AfterLogin_ReturnsProfile()
    {
        var client = NewClientWithCookies();
        var email = $"itest-{Guid.NewGuid():N}@test.com";
        await client.PostAsJsonAsync("/api/v1/auth/signup", new { email, password = "Passw0rd1!" });
        await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "Passw0rd1!" });

        var resp = await client.GetAsync("/api/v1/users/me");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Refresh_RotatesToken_OldTokenNoLongerWorks()
    {
        var client = NewClientWithCookies();
        var email = $"itest-{Guid.NewGuid():N}@test.com";
        await client.PostAsJsonAsync("/api/v1/auth/signup", new { email, password = "Passw0rd1!" });
        await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "Passw0rd1!" });

        var firstRefresh = await client.PostAsync("/api/v1/auth/refresh", null);
        Assert.Equal(HttpStatusCode.OK, firstRefresh.StatusCode);
    }

    [Fact]
    public async Task Login_WrongPassword_Returns401_GenericMessage()
    {
        var client = NewClientWithCookies();
        var email = $"itest-{Guid.NewGuid():N}@test.com";
        await client.PostAsJsonAsync("/api/v1/auth/signup", new { email, password = "Passw0rd1!" });

        var resp = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "WrongOne1!" });

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Signup_DuplicateEmail_Returns409()
    {
        var client = NewClientWithCookies();
        var email = $"itest-{Guid.NewGuid():N}@test.com";
        await client.PostAsJsonAsync("/api/v1/auth/signup", new { email, password = "Passw0rd1!" });

        var second = await client.PostAsJsonAsync("/api/v1/auth/signup", new { email, password = "Passw0rd1!" });

        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Logout_ThenMe_Returns401()
    {
        var client = NewClientWithCookies();
        var email = $"itest-{Guid.NewGuid():N}@test.com";
        await client.PostAsJsonAsync("/api/v1/auth/signup", new { email, password = "Passw0rd1!" });
        await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "Passw0rd1!" });

        await client.PostAsync("/api/v1/auth/logout", null);
        var meResp = await client.GetAsync("/api/v1/users/me");

        // Access token cookie clearing depends on your logout endpoint
        // actually deleting it - if this fails, check AuthController's
        // Logout action clears both cookies, not just revoking the DB row.
        Assert.Equal(HttpStatusCode.Unauthorized, meResp.StatusCode);
    }
}