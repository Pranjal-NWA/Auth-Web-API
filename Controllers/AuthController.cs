using WebAPI.DTOs;
using WebAPI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace WebAPI.Controllers;

[ApiController]
[Route("api/v1/auth")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly IConfiguration _config;

    public AuthController(IAuthService authService, IConfiguration config)
    {
        _authService = authService;
        _config = config;
    }

    [HttpPost("signup")]
    [EnableRateLimiting("signup")]
    public async Task<ActionResult<UserResponse>> Signup(SignupRequest request)
    {
        var user = await _authService.SignupAsync(request);

        return StatusCode(StatusCodes.Status201Created, new UserResponse
        {
            Id = user.Id,
            Email = user.Email!,
            FullName = user.FullName,
            IsVerified = user.EmailConfirmed,
            Role = await _authService.GetUserRoleAsync(user),
            CreatedAt = user.CreatedAt,
        });
    }

    [HttpPost("login")]
    [EnableRateLimiting("login")]
    public async Task<ActionResult<UserResponse>> Login(LoginRequest request)
    {
        var (user, accessToken, rawRefresh) = await _authService.LoginAsync(request);
        SetAuthCookies(accessToken, rawRefresh);

        return Ok(new UserResponse
        {
            Id = user.Id,
            Email = user.Email!,
            FullName = user.FullName,
            IsVerified = user.EmailConfirmed,
            Role = await _authService.GetUserRoleAsync(user),
            CreatedAt = user.CreatedAt,
        });
    }

    [HttpPost("refresh")]
    [EnableRateLimiting("refresh")]
    public async Task<ActionResult<UserResponse>> Refresh()
    {
        Request.Cookies.TryGetValue("refresh_token", out var rawToken);
        if (rawToken is null)
            return Unauthorized(new { detail = "No refresh token" });

        var (user, accessToken, newRawRefresh) = await _authService.RefreshAsync(rawToken);
        SetAuthCookies(accessToken, newRawRefresh);

        return Ok(new UserResponse
        {
            Id = user.Id,
            Email = user.Email!,
            FullName = user.FullName,
            IsVerified = user.EmailConfirmed,
            CreatedAt = user.CreatedAt,
        });
    }

    [HttpPost("forgot-password")]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordRequest request)
    {
        var linkTemplate = $"{_config["Frontend:BaseUrl"]}/reset-password?email={{email}}&token={{token}}";
        await _authService.ForgotPasswordAsync(request.Email, linkTemplate);

        // Always 204 regardless of whether the account exists - same
        // enumeration-prevention reasoning as resend-confirmation above.
        return NoContent();
    }

    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword(ResetPasswordRequest request)
    {
        await _authService.ResetPasswordAsync(request);
        return NoContent();
    }
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        Request.Cookies.TryGetValue("refresh_token", out var rawToken);
        await _authService.LogoutAsync(rawToken);

        Response.Cookies.Delete("access_token", new CookieOptions { Path = "/" });
        Response.Cookies.Delete("refresh_token", new CookieOptions { Path = "/" });

        return NoContent();
    }

    private void SetAuthCookies(string accessToken, string refreshToken)
    {
        var cookieSecure = _config.GetValue<bool>("CookieSecure");
        var accessSeconds = double.Parse(_config["Jwt:AccessTokenExpirySeconds"] ?? "900");
        var refreshDays = int.Parse(_config["Jwt:RefreshTokenExpiryDays"] ?? "30");

        var common = new CookieOptions
        {
            HttpOnly = true,
            Secure = cookieSecure,
            SameSite = SameSiteMode.Lax,
            Path = "/",
        };

        Response.Cookies.Append("access_token", accessToken, new CookieOptions
        {
            HttpOnly = common.HttpOnly,
            Secure = common.Secure,
            SameSite = common.SameSite,
            Path = common.Path,
            MaxAge = TimeSpan.FromSeconds(accessSeconds),
        });

        Response.Cookies.Append("refresh_token", refreshToken, new CookieOptions
        {
            HttpOnly = common.HttpOnly,
            Secure = common.Secure,
            SameSite = common.SameSite,
            Path = common.Path,
            MaxAge = TimeSpan.FromDays(refreshDays),
        });
    }
}